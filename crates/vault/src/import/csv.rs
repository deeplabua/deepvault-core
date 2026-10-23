//! CSV exports: 1Password, Bitwarden, Apple Passwords, Chrome, Firefox, or any file with
//! recognisable column names. Cells are copied out once into buffers of their exact size (no
//! growing, no stray copies).
//!
//! RFC 4180 by hand (quotes, doubled quotes, line breaks in quotes, CRLF, a UTF-8 BOM): a
//! dependency for this is not worth an ADR.

use zeroize::Zeroizing;

use super::{host, trimmed, Format, Imported};
use crate::entry::{field, EntryKind, Field, NewEntry};
use crate::error::{Result, VaultError};
use crate::totp;

/// The entries in a CSV export. `InvalidImport` when the file is not CSV text or has none of
/// the columns a password export has.
pub(super) fn parse(bytes: &[u8]) -> Result<Imported> {
    let rows = split(bytes).ok_or(VaultError::InvalidImport)?;
    let (header, rows) = rows.split_first().ok_or(VaultError::InvalidImport)?;
    let names: Vec<String> =
        header.iter().map(|cell| String::from_utf8_lossy(&cell.text(bytes)).trim().to_lowercase()).collect();
    let columns = Columns::find(&names).ok_or(VaultError::InvalidImport)?;

    let mut entries = Vec::new();
    let mut skipped = 0;
    for row in rows {
        let cell = |column: Option<usize>| -> Zeroizing<Vec<u8>> {
            column.and_then(|index| row.get(index)).map(|cell| cell.text(bytes)).unwrap_or_default()
        };
        if row.iter().all(|cell| cell.is_empty()) {
            continue;
        }
        match columns.entry(&cell) {
            Some(entry) => entries.push(entry),
            None => skipped += 1,
        }
    }
    Ok(Imported { format: columns.format, entries, skipped })
}

/// A cell: where its text is in the file, and whether it was quoted (then `""` is `"`).
#[derive(Clone, Copy)]
struct Cell {
    start: usize,
    end: usize,
    quoted: bool,
}

impl Cell {
    fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// The cell's text in a buffer of its exact size, zeroed on drop.
    fn text(&self, bytes: &[u8]) -> Zeroizing<Vec<u8>> {
        let raw = &bytes[self.start..self.end];
        let mut text = Zeroizing::new(Vec::with_capacity(raw.len()));
        if self.quoted {
            let mut i = 0;
            while i < raw.len() {
                text.push(raw[i]);
                i += if raw[i] == b'"' { 2 } else { 1 };
            }
        } else {
            text.extend_from_slice(raw);
        }
        text
    }
}

/// Rows of cells; `None` for an unterminated quote or text after a closing quote.
fn split(bytes: &[u8]) -> Option<Vec<Vec<Cell>>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut i = 0;
    loop {
        // One cell from `i`.
        let cell = if bytes.get(i) == Some(&b'"') {
            let start = i + 1;
            let mut j = start;
            loop {
                match bytes.get(j)? {
                    b'"' if bytes.get(j + 1) == Some(&b'"') => j += 2,
                    b'"' => break,
                    _ => j += 1,
                }
            }
            i = j + 1;
            Cell { start, end: j, quoted: true }
        } else {
            let start = i;
            while i < bytes.len() && !matches!(bytes[i], b',' | b'\n' | b'\r') {
                if bytes[i] == b'"' {
                    return None;
                }
                i += 1;
            }
            Cell { start, end: i, quoted: false }
        };
        row.push(cell);
        match bytes.get(i) {
            Some(b',') => i += 1,
            Some(b'\r') | Some(b'\n') | None => {
                rows.push(std::mem::take(&mut row));
                if bytes.get(i) == Some(&b'\r') {
                    i += 1;
                }
                if bytes.get(i) == Some(&b'\n') {
                    i += 1;
                }
                if i >= bytes.len() {
                    return Some(rows);
                }
            }
            Some(_) => return None,
        }
    }
}

/// Which column holds what, by the header's names (lowercase).
struct Columns {
    format: Format,
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    otp: Option<usize>,
    notes: Option<usize>,
    tags: Option<usize>,
    folder: Option<usize>,
    kind: Option<usize>,
    /// Bitwarden's custom fields: `name: value` lines.
    fields: Option<usize>,
}

impl Columns {
    fn find(names: &[String]) -> Option<Self> {
        // The first candidate present wins (`username` over `email`), wherever it is.
        let column = |candidates: &[&str]| {
            candidates.iter().find_map(|candidate| names.iter().position(|name| name == candidate))
        };
        let has = |name: &str| names.iter().any(|n| n == name);
        let columns = Self {
            format: if has("login_password") {
                Format::Bitwarden
            } else if has("otpauth") && has("favorite") && has("archived") {
                Format::OnePassword
            } else if has("otpauth") && has("title") {
                Format::Apple
            } else if has("httprealm") {
                Format::Firefox
            } else if has("name") && has("url") && has("username") && has("password") {
                Format::Chrome
            } else {
                Format::Other
            },
            title: column(&["title", "name"]),
            url: column(&["url", "login_uri", "website", "web site", "uri"]),
            username: column(&["username", "login_username", "user name", "login", "email"]),
            password: column(&["password", "login_password"]),
            otp: column(&["otpauth", "login_totp", "totp", "otp"]),
            notes: column(&["notes", "note", "extra", "comments"]),
            tags: column(&["tags"]),
            folder: column(&["folder", "grouping"]),
            kind: column(&["type"]),
            fields: column(&["fields"]),
        };
        // A password export has at least a password or a site column.
        (columns.password.is_some() || columns.url.is_some()).then_some(columns)
    }

    /// One row as an entry, in the order the app saves a login; `None` to skip it.
    fn entry(&self, cell: &dyn Fn(Option<usize>) -> Zeroizing<Vec<u8>>) -> Option<NewEntry> {
        let kind = match cell(self.kind).as_slice() {
            b"" | b"login" => EntryKind::Login,
            b"note" => EntryKind::Note,
            // Bitwarden writes cards and identities without their fields: nothing to keep.
            _ => return None,
        };
        let mut fields = Vec::new();
        let mut add = |name: &str, value: Zeroizing<Vec<u8>>, concealed: bool, custom: bool| {
            let mut value = trimmed(&value);
            if !value.is_empty() {
                // Moved, not copied: `Field` zeroes it from here on.
                fields.push(Field {
                    name: name.into(),
                    value: std::mem::take(&mut *value),
                    concealed,
                    custom,
                });
            }
        };

        let urls = cell(self.url);
        let username = cell(self.username);
        add(field::USERNAME, username.clone(), false, false);
        add(field::PASSWORD, cell(self.password), true, false);
        let otp = cell(self.otp);
        let valid_otp = totp::parse(trimmed(&otp).as_slice()).is_ok();
        add(if valid_otp { field::TOTP } else { "OTP" }, otp, true, !valid_otp);
        // Bitwarden puts several sites in one cell, one per line or after commas.
        for url in urls.split(|byte| matches!(byte, b'\n' | b'\r' | b',')) {
            add(field::URL, Zeroizing::new(url.to_vec()), false, false);
        }
        add(field::NOTES, cell(self.notes), true, false);
        for line in cell(self.fields).split(|byte| *byte == b'\n') {
            let line = trimmed(line);
            if let Some(colon) = line.iter().position(|byte| *byte == b':') {
                let name = String::from_utf8_lossy(&trimmed(&line[..colon])).into_owned();
                add(&name, Zeroizing::new(line[colon + 1..].to_vec()), true, true);
            } else {
                add("", line, true, true);
            }
        }
        let folder = cell(self.folder);
        for tag in cell(self.tags).split(|byte| matches!(byte, b',' | b';')).chain([folder.as_slice()]) {
            add(field::TAG, Zeroizing::new(tag.to_vec()), false, false);
        }

        let title = String::from_utf8_lossy(&trimmed(&cell(self.title))).into_owned();
        let first_url = fields.iter().find(|f| f.name == field::URL && !f.custom).map(|f| f.value.as_slice());
        let title = if !title.is_empty() {
            title
        } else if let Some(host) = first_url.and_then(host) {
            host
        } else if !trimmed(&username).is_empty() {
            String::from_utf8_lossy(&trimmed(&username)).into_owned()
        } else {
            String::new()
        };
        let has_content = fields.iter().any(|f| f.name != field::TAG);
        if title.is_empty() || !has_content {
            return None;
        }
        Some(NewEntry { kind, title, fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(text: &str) -> Vec<Vec<String>> {
        split(text.as_bytes())
            .unwrap()
            .iter()
            .map(|row| {
                row.iter().map(|c| String::from_utf8(c.text(text.as_bytes()).to_vec()).unwrap()).collect()
            })
            .collect()
    }

    #[test]
    fn splits_quotes_doubled_quotes_and_line_breaks() {
        assert_eq!(
            rows("a,\"b,c\",\"say \"\"hi\"\"\"\r\n\"two\nlines\",,x"),
            vec![vec!["a", "b,c", "say \"hi\""], vec!["two\nlines", "", "x"]]
        );
        assert_eq!(rows("a,b\n"), vec![vec!["a", "b"]]);
        assert!(split(b"\"open").is_none());
        assert!(split(b"\"a\"b").is_none());
        assert!(split(b"a\"b").is_none());
    }
}
