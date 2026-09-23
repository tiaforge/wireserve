//! Terminal QR rendering for `export-config --qr` (PLAN.md M24).
//!
//! The point of this is that refreshing a phone becomes a scan instead of a
//! file transfer. It renders to stdout and never to a file: a `.conf` holds a
//! private key, and the existing `--out` path already writes mode-0600 — a
//! second key-bearing artifact with its own permissions story is not worth
//! adding.
//!
//! **The binding constraint is terminal width, not QR capacity.** A QR code
//! is `4 * version + 17` modules square plus a 4-module quiet zone each side,
//! and half-block characters only halve the *vertical* extent — horizontally
//! it is still one column per module. So a code that fits comfortably inside
//! byte capacity (2953 bytes at version 40) would need 185 columns to print
//! and could not be scanned off a normal terminal at all. [`MAX_COLUMNS`] is
//! what actually decides whether `--qr` is offered, and the caller is pointed
//! at `--out` when a conf exceeds it.
//!
//! Colors are written explicitly rather than relying on the terminal's own
//! foreground and background. A scanner needs dark modules on a light field;
//! bare block characters inherit the theme, so the same output would scan on
//! a light terminal and be inverted (hence unscannable) on a dark one.

use qrcodegen::{QrCode, QrCodeEcc};

/// Modules of light margin required on every side for a scanner to find the
/// code. Four is the spec minimum.
const QUIET_ZONE: usize = 4;

/// The widest code worth printing, in terminal columns including the quiet
/// zone. 116 columns admits up to a version-22 code (105 modules), which is
/// roughly 1.1 kB of payload — comfortably more than a gateway-routed conf
/// needs, and about the point past which a phone camera stops resolving
/// modules off a screen anyway.
pub const MAX_COLUMNS: usize = 116;

#[derive(Debug, thiserror::Error)]
pub enum QrError {
    #[error(
        "config is {bytes} bytes — too large for a QR code that fits a terminal \
         (needs {columns} columns, limit {MAX_COLUMNS}). Write it to a file with \
         --out and transfer that instead."
    )]
    TooWide { bytes: usize, columns: usize },
    #[error("config is {0} bytes, which exceeds what any QR code can carry")]
    TooLong(usize),
}

/// Renders `text` as a QR code drawn with half-block characters, one string
/// ready to print. Low error correction is deliberate: the code is on a
/// screen for seconds, not printed on a label that will be scuffed, and
/// lower ECC means a smaller code and so a narrower terminal.
pub fn render(text: &str) -> Result<String, QrError> {
    let code = QrCode::encode_text(text, QrCodeEcc::Low)
        .map_err(|_| QrError::TooLong(text.len()))?;
    let size = code.size() as usize;
    let columns = size + 2 * QUIET_ZONE;
    if columns > MAX_COLUMNS {
        return Err(QrError::TooWide { bytes: text.len(), columns });
    }

    // `dark(x, y)` reads one module, treating everything outside the code as
    // light so the quiet zone falls out of the same lookup.
    let dark = |x: usize, y: usize| -> bool {
        if x < QUIET_ZONE || y < QUIET_ZONE {
            return false;
        }
        let (x, y) = (x - QUIET_ZONE, y - QUIET_ZONE);
        x < size && y < size && code.get_module(x as i32, y as i32)
    };

    // 256-color white and black, set explicitly on every cell.
    const WHITE_FG: &str = "\x1b[38;5;15m";
    const BLACK_FG: &str = "\x1b[30m";
    const WHITE_BG: &str = "\x1b[48;5;15m";
    const BLACK_BG: &str = "\x1b[40m";
    const RESET: &str = "\x1b[0m";

    let mut out = String::new();
    // Two module rows per character row, via the upper-half block: its top
    // half takes the foreground color and its bottom half the background.
    for y in (0..columns).step_by(2) {
        for x in 0..columns {
            let top = dark(x, y);
            let bottom = dark(x, y + 1);
            out.push_str(if top { BLACK_FG } else { WHITE_FG });
            out.push_str(if bottom { BLACK_BG } else { WHITE_BG });
            out.push('\u{2580}');
        }
        out.push_str(RESET);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strips SGR sequences so tests can assert on geometry.
    fn plain(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in s.lines() {
            let mut cleaned = String::new();
            let mut chars = line.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for c in chars.by_ref() {
                        if c == 'm' {
                            break;
                        }
                    }
                } else {
                    cleaned.push(c);
                }
            }
            out.push(cleaned);
        }
        out
    }

    #[test]
    fn renders_a_square_block_with_a_quiet_zone() {
        let rendered = render("wireserve").unwrap();
        let lines = plain(&rendered);
        let width = lines[0].chars().count();
        // Every row is the same width, and there are half as many rows as
        // columns (rounded up), because each row holds two module rows.
        assert!(lines.iter().all(|l| l.chars().count() == width), "ragged: {lines:?}");
        assert_eq!(lines.len(), width.div_ceil(2));
        // The first two module rows are quiet zone, so the top line is blank.
        assert!(
            lines[0].chars().all(|c| c == '\u{2580}'),
            "expected only half-blocks, got {:?}",
            lines[0]
        );
    }

    #[test]
    fn every_cell_sets_both_colors_so_the_terminal_theme_cannot_invert_it() {
        let rendered = render("wireserve").unwrap();
        for line in rendered.lines() {
            let cells = line.matches('\u{2580}').count();
            assert_eq!(line.matches("\x1b[38;5;15m").count() + line.matches("\x1b[30m").count(), cells);
            assert_eq!(line.matches("\x1b[48;5;15m").count() + line.matches("\x1b[40m").count(), cells);
        }
    }

    #[test]
    fn a_realistic_gateway_conf_fits() {
        // [Interface] plus a gateway peer and two direct peers — the shape a
        // gateway-routed export actually produces.
        let conf = format!(
            "[Interface]\nPrivateKey = {k}\nAddress = 10.1.0.7/32, fd12:3456:789a::7/128\n\n{peers}",
            k = "A".repeat(44),
            peers = (0..3)
                .map(|i| format!(
                    "[Peer]\nPublicKey = {k}\nAllowedIPs = 10.1.0.{i}/32, fd12:3456:789a::{i}/128\n\
                     Endpoint = node{i}.example.com:51820\nPersistentKeepalive = 25\n\n",
                    k = "B".repeat(44)
                ))
                .collect::<String>()
        );
        let rendered = render(&conf).expect("a 3-peer conf must fit");
        let width = plain(&rendered)[0].chars().count();
        assert!(width <= MAX_COLUMNS, "{width} columns");
    }

    #[test]
    fn an_oversized_conf_is_refused_rather_than_rendered_unscannable() {
        let huge = "x".repeat(4000);
        match render(&huge) {
            Err(QrError::TooWide { .. } | QrError::TooLong(_)) => {}
            Ok(_) => panic!("a 4000-byte conf must not render"),
        }
    }

    #[test]
    fn the_refusal_names_the_size_and_points_at_the_file_path() {
        let err = render(&"x".repeat(1800)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("1800"), "{msg}");
        assert!(msg.contains("--out"), "{msg}");
    }
}
