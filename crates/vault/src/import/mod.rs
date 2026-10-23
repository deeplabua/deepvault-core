//! Another password manager's export as new entries (PRD 02, «Импорт»): CSV from 1Password,
//! Bitwarden, Apple Passwords, Chrome, Firefox (or any file with recognisable column names),
//! and the XML of Secrets.
//!
//! An export is plain text with every password in it. It is read here, in the core, so the
//! secrets go from the file's bytes straight into zeroed-on-drop fields and never become an
//! app string; the caller zeroes the file's bytes. Both formats are parsed by hand: a
//! dependency for either is not worth an ADR.

mod csv;
mod secrets;
mod xml;

use zeroize::Zeroizing;

use crate::entry::NewEntry;
use crate::error::Result;

/// Whose export the file looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    OnePassword,
    Bitwarden,
    Apple,
    Chrome,
    Firefox,
    Secrets,
    /// CSV with known column names, but not one of the above's set.
    Other,
}

/// What an export holds. No `Debug`: the entries hold passwords.
pub struct Imported {
    pub format: Format,
    pub entries: Vec<NewEntry>,
    /// Items that could not be imported: a Bitwarden card or identity, a row with nothing but
    /// a title, an item in Secrets' trash.
    pub skipped: usize,
}

/// The entries in an export: XML (Secrets) when it starts with `<`, CSV otherwise.
/// `InvalidImport` when it is neither, or has nothing a password export has.
pub fn parse(bytes: &[u8]) -> Result<Imported> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    match bytes.iter().find(|byte| !byte.is_ascii_whitespace()) {
        Some(b'<') => secrets::parse(bytes),
        _ => csv::parse(bytes),
    }
}

/// `value` without outer white space, in a buffer of its exact size.
fn trimmed(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let start = value.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(value.len());
    let end = value.iter().rposition(|byte| !byte.is_ascii_whitespace()).map_or(start, |end| end + 1);
    let mut out = Zeroizing::new(Vec::with_capacity(end - start));
    out.extend_from_slice(&value[start..end]);
    out
}

/// `https://www.example.com/login` → `example.com` (a title for an item without one).
fn host(url: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(url).ok()?;
    let rest = text.split_once("://").map_or(text, |(_, rest)| rest);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?.split(':').next()?;
    let host = host.strip_prefix("www.").unwrap_or(host);
    (!host.is_empty()).then(|| host.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_hosts() {
        assert_eq!(host(b"https://www.GitHub.com/login?x=1").as_deref(), Some("github.com"));
        assert_eq!(host(b"user@example.org:8443").as_deref(), Some("example.org"));
        assert_eq!(host(b""), None);
    }

    #[test]
    fn trims() {
        assert_eq!(trimmed(b"  a b \n").as_slice(), b"a b");
        assert_eq!(trimmed(b"   ").as_slice(), b"");
    }
}
