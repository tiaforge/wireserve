//! Text for a person's terminal, shared by `wireserve status` and
//! `wireserve-admin`'s listings: columns padded to their widest cell, never
//! tabs, which jump to the next multiple of eight and lose their alignment
//! as soon as one cell is longer than that.
//!
//! Nearly every string these print came from the coordinator, so every
//! control character is escaped rather than printed: no field can move the
//! cursor, recolour the screen or forge a line of output.

/// Escapes every control character (`\n`, `\r`, `\t`, ESC, …) in `s`.
#[must_use]
pub fn clean(s: &str) -> String {
    s.chars()
        .flat_map(|c| -> Box<dyn Iterator<Item = char>> {
            if c.is_control() {
                Box::new(c.escape_default())
            } else {
                Box::new(std::iter::once(c))
            }
        })
        .collect()
}

/// Left-aligned columns two spaces apart, sized to their widest cell; the
/// last column is not padded, so a long one (a reason, an error) does not
/// widen the rest. Cells are counted in characters: everything shown is
/// ASCII or escaped, apart from free text, which only goes last.
#[must_use]
pub fn columns(rows: &[Vec<String>]) -> String {
    let count = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..count)
        .map(|i| rows.iter().filter_map(|r| r.get(i)).map(|c| c.chars().count()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for r in rows {
        let mut line = String::new();
        for (i, cell) in r.iter().enumerate() {
            line.push_str(cell);
            if i + 1 < r.len() {
                line.push_str(&" ".repeat(widths[i] - cell.chars().count() + 2));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// [`columns`] under a header row.
#[must_use]
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut all = Vec::with_capacity(rows.len() + 1);
    all.push(header.iter().map(|h| (*h).to_string()).collect());
    all.extend(rows.iter().cloned());
    columns(&all)
}

/// `key: value` lines with the values lined up, for one record shown whole.
#[must_use]
pub fn fields(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter().map(|(k, v)| format!("{k}:{}{v}\n", " ".repeat(width - k.len() + 2))).collect()
}

/// `4s ago`, `3m ago`, `5h ago`, `2d ago`.
#[must_use]
pub fn ago(then: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> String {
    let secs = (now - then).num_seconds().max(0);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cells: &[&str]) -> Vec<String> {
        cells.iter().map(|c| (*c).to_string()).collect()
    }

    #[test]
    fn columns_line_up_whatever_a_cell_is_long() {
        let out = table(
            &["SERVICE", "PORTS", "NOTE"],
            &[row(&["a-rather-long-service-name", "80", "-"]), row(&["db", "53/udp 53/tcp 8080:8000/tcp", "denied: not here"])],
        );
        assert_eq!(
            out,
            "\
SERVICE                     PORTS                        NOTE
a-rather-long-service-name  80                           -
db                          53/udp 53/tcp 8080:8000/tcp  denied: not here
"
        );
    }

    #[test]
    fn the_last_column_is_not_padded_and_lines_end_without_spaces() {
        let out = columns(&[row(&["a", "x"]), row(&["b", ""])]);
        assert_eq!(out, "a  x\nb\n");
    }

    #[test]
    fn control_characters_are_escaped_tabs_included() {
        assert_eq!(clean("a\tb\nc\r\u{1b}[31m"), "a\\tb\\nc\\r\\u{1b}[31m");
        assert_eq!(clean("plain"), "plain");
    }

    #[test]
    fn fields_line_up_their_values() {
        assert_eq!(fields(&[("node", "a".into()), ("public key", "k".into())]), "node:        a\npublic key:  k\n");
    }
}
