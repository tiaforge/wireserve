//! Terminal QR rendering for `device create --qr` (PLAN.md M24).
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
//! it is still one column per module. So the code is checked against the
//! terminal's actual width ([`terminal_columns`]): a config lists every node
//! (PLAN.md M40), so it grows with the mesh, and a phone scans a big code off
//! a wide terminal fine — only a code whose lines would wrap is refused.
//!
//! Colors are written explicitly rather than relying on the terminal's own
//! foreground and background. A scanner needs dark modules on a light field;
//! bare block characters inherit the theme, so the same output would scan on
//! a light terminal and be inverted (hence unscannable) on a dark one.

use qrcodegen::{QrCode, QrCodeEcc};

/// Modules of light margin required on every side for a scanner to find the
/// code. Four is the spec minimum.
const QUIET_ZONE: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum QrError {
    #[error(
        "the QR code needs {columns} columns and this terminal has {available} — widen the \
         window or zoom out, or write the config to a file with --out and transfer that"
    )]
    TooWide { columns: usize, available: usize },
    #[error("config is {0} bytes, which exceeds what any QR code can carry")]
    TooLong(usize),
}

/// How many columns the terminal on stderr has, where the code is drawn;
/// `None` when stderr is no terminal, and nothing then wraps a line.
#[must_use]
pub fn terminal_columns() -> Option<usize> {
    // SAFETY: TIOCGWINSZ writes one `winsize` into the struct passed, and
    // fails harmlessly on a descriptor that is no terminal.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        (libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0).then_some(usize::from(ws.ws_col))
    }
}

/// Renders `text` as a QR code drawn with half-block characters, one string
/// ready to print. Low error correction is deliberate: the code is on a
/// screen for seconds, not printed on a label that will be scuffed, and
/// lower ECC means a smaller code and so a narrower terminal.
///
/// As wide as it has to be: a config lists every node, so it grows with the
/// mesh, and a phone scans a large code off a screen fine. Only a code wider
/// than the terminal is refused, since its lines would wrap into noise.
pub fn render(text: &str) -> Result<String, QrError> {
    render_within(text, terminal_columns())
}

fn render_within(text: &str, available: Option<usize>) -> Result<String, QrError> {
    let code = QrCode::encode_text(text, QrCodeEcc::Low)
        .map_err(|_| QrError::TooLong(text.len()))?;
    let size = code.size() as usize;
    let columns = size + 2 * QUIET_ZONE;
    if let Some(available) = available.filter(|a| columns > *a) {
        return Err(QrError::TooWide { columns, available });
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
    fn a_code_wider_than_the_terminal_is_refused_and_one_that_fits_is_drawn() {
        // A config with a handful of relayed nodes: about 1.3 kB, too wide
        // for the old fixed limit of 116 columns.
        let conf = format!(
            "[Interface]\nPrivateKey = {k}\nAddress = 10.1.0.7/32, fd12:3456:789a::7/128\nMTU = 1340\n\n{peers}",
            k = "A".repeat(44),
            peers = (0..6)
                .map(|i| format!(
                    "[Peer]\nPublicKey = {k}\nAllowedIPs = 10.1.0.{i}/32, fd12:3456:789a::{i}/128\n\
                     Endpoint = 85.215.231.166:4100{i}\nPersistentKeepalive = 25\n\n",
                    k = "B".repeat(44)
                ))
                .collect::<String>()
        );
        let rendered = render_within(&conf, Some(200)).expect("fits a 200-column terminal");
        let width = plain(&rendered)[0].chars().count();
        assert!(width > 116 && width <= 200, "{width} columns");
        match render_within(&conf, Some(116)) {
            Err(QrError::TooWide { columns, available: 116 }) => assert_eq!(columns, width),
            other => panic!("{:?}", other.map(|_| ())),
        }
        assert!(render_within(&conf, None).is_ok(), "no terminal, nothing wraps");
    }

    #[test]
    fn more_than_any_qr_code_holds_is_refused() {
        assert!(matches!(render_within(&"x".repeat(4000), None), Err(QrError::TooLong(4000))));
    }

    #[test]
    fn the_refusal_says_how_wide_and_points_at_the_file_path() {
        let msg = render_within(&"x".repeat(1800), Some(80)).unwrap_err().to_string();
        assert!(msg.contains("80"), "{msg}");
        assert!(msg.contains("--out"), "{msg}");
    }
}
