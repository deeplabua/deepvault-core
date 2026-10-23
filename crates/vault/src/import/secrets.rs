//! The XML export of Secrets (macOS), three kinds of item:
//!
//! - `credentials/credential` — logins: a `name`, an `identifier` (user name), `secrets/secret`
//!   (passwords; `kind` 0 — other kinds are kept as fields), `services/service/address`
//!   (sites), `notes` and `oneTimePassword` (a one-time-code seed in base64 with its algorithm,
//!   digits and period);
//! - `creditCards/creditCard` — cards: `name`, `cardholder`, `pan`, `expirationDate` (the last
//!   second of the month, ISO 8601), `securityCode`, `notes`;
//! - `notes/note` — secure notes: `title` and `text`.
//!
//! Each may have `tags/tag/name`. Items in its trash are skipped; archived ones are kept with an
//! `archived` tag; archived secrets (old passwords) are left out. Any other element with text
//! is kept as the user's own concealed field, so nothing in the file is lost because this
//! mapping does not know it.

use zeroize::{Zeroize, Zeroizing};

use super::xml::{self, Element};
use super::{host, trimmed, Format, Imported};
use crate::entry::{field, EntryKind, Field, NewEntry};
use crate::error::{Result, VaultError};
use crate::totp;

/// Elements that are bookkeeping, not content.
/// `builtinServiceLogo` names a logo bundled with Secrets; `passkeyEnabled` says whether Secrets
/// holds a passkey for the item, which its export does not carry.
const BOOKKEEPING: &[&str] = &[
    "uuid",
    "creationDate",
    "modificationDate",
    "favorite",
    "passkeyEnabled",
    "trashed",
    "archived",
    "builtinServiceLogo",
    // A card's network: the app tells it from the number.
    "brand",
];

/// One kind of item as an entry; `None` when it has nothing to keep.
type MakeEntry = fn(&Element, &[u8]) -> Option<NewEntry>;

pub(super) fn parse(bytes: &[u8]) -> Result<Imported> {
    let root = xml::parse(bytes).ok_or(VaultError::InvalidImport)?;
    let kinds: [(&str, MakeEntry); 3] = [("credential", login), ("creditCard", card), ("note", note)];
    let mut entries = Vec::new();
    let mut skipped = 0;
    let mut found = false;
    for (name, make) in kinds {
        let mut items = Vec::new();
        root.find_all(name, &mut items);
        found |= !items.is_empty();
        for item in items {
            match (!flag(item, "trashed", bytes)).then(|| make(item, bytes)).flatten() {
                Some(entry) => entries.push(entry),
                None => skipped += 1,
            }
        }
    }
    if !found {
        return Err(VaultError::InvalidImport);
    }
    Ok(Imported { format: Format::Secrets, entries, skipped })
}

/// Fields as they are collected: a value is moved in, not copied, and `Field` zeroes it from
/// there on; an empty one is dropped.
#[derive(Default)]
struct Fields(Vec<Field>);

impl Fields {
    fn add(&mut self, name: &str, mut value: Zeroizing<Vec<u8>>, concealed: bool, custom: bool) {
        if !value.is_empty() {
            self.0.push(Field { name: name.into(), value: std::mem::take(&mut *value), concealed, custom });
        }
    }

    /// Whatever else the item holds, under its element name; then its tags and `archived`.
    fn add_rest(&mut self, item: &Element, known: &[&str], bytes: &[u8]) {
        for other in &item.children {
            let name = other.name.as_str();
            if !known.contains(&name) && name != "tags" && !BOOKKEEPING.contains(&name) {
                self.add(name, trimmed(&other.text(bytes)), true, true);
            }
        }
        // A tag is an element of its own: `<tag><name>work</name><uuid>…</uuid>…</tag>`.
        for tag in item.child("tags").into_iter().flat_map(|tags| tags.children.iter()) {
            let name = tag.child("name").map_or_else(|| tag.text(bytes), |name| name.text(bytes));
            self.add(field::TAG, trimmed(&name), false, false);
        }
        if flag(item, "archived", bytes) {
            self.add(field::TAG, Zeroizing::new(b"archived".to_vec()), false, false);
        }
    }

    fn has_content(&self) -> bool {
        self.0.iter().any(|field| field.name != field::TAG)
    }
}

fn text(item: &Element, name: &str, bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    item.child(name).map(|child| trimmed(&child.text(bytes))).unwrap_or_default()
}

fn title(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

/// A card in the order the app saves one: holder, number (digits only), expiry (`MM/YY`), CVV,
/// notes. `None` with neither a name nor a number.
fn card(item: &Element, bytes: &[u8]) -> Option<NewEntry> {
    let mut fields = Fields::default();
    fields.add(field::CARDHOLDER, text(item, "cardholder", bytes), false, false);
    let pan = text(item, "pan", bytes);
    let mut digits = Zeroizing::new(pan.iter().copied().filter(u8::is_ascii_digit).collect::<Vec<u8>>());
    if digits.is_empty() {
        digits = pan;
    }
    fields.add(field::NUMBER, digits, true, false);
    fields.add(field::EXPIRY, expiry(&text(item, "expirationDate", bytes)), false, false);
    fields.add(field::CVV, text(item, "securityCode", bytes), true, false);
    fields.add(field::NOTES, text(item, "notes", bytes), true, false);
    fields.add_rest(item, &["name", "cardholder", "pan", "expirationDate", "securityCode", "notes"], bytes);
    let mut name = title(&text(item, "name", bytes));
    if name.is_empty() {
        name = title(&text(item, "brand", bytes));
    }
    (!name.is_empty() && fields.has_content()).then_some(NewEntry {
        kind: EntryKind::Card,
        title: name,
        fields: fields.0,
    })
}

/// `2029-05-31T23:59:59.000Z` → `05/29`; anything else as it is.
fn expiry(date: &[u8]) -> Zeroizing<Vec<u8>> {
    let numeric =
        |range: std::ops::Range<usize>| date.get(range).filter(|part| part.iter().all(u8::is_ascii_digit));
    match (numeric(0..4), date.get(4), numeric(5..7)) {
        (Some(year), Some(b'-'), Some(month)) => {
            let mut short = Zeroizing::new(Vec::with_capacity(5));
            short.extend_from_slice(month);
            short.push(b'/');
            short.extend_from_slice(&year[2..]);
            short
        }
        _ => Zeroizing::new(date.to_vec()),
    }
}

/// A secure note: its text, concealed like any note; kept with only a title too.
fn note(item: &Element, bytes: &[u8]) -> Option<NewEntry> {
    let mut fields = Fields::default();
    fields.add(field::NOTES, text(item, "text", bytes), true, false);
    fields.add_rest(item, &["title", "text"], bytes);
    let name = title(&text(item, "title", bytes));
    (!name.is_empty()).then_some(NewEntry { kind: EntryKind::Note, title: name, fields: fields.0 })
}

fn flag(element: &Element, name: &str, bytes: &[u8]) -> bool {
    element.child(name).is_some_and(|child| trimmed(&child.text(bytes)).as_slice() == b"1")
}

/// A login, in the order the app saves one; `None` with nothing in it.
fn login(credential: &Element, bytes: &[u8]) -> Option<NewEntry> {
    let text = |name: &str| text(credential, name, bytes);
    let mut fields = Fields::default();
    let mut add = |name: &str, value: Zeroizing<Vec<u8>>, concealed: bool, custom: bool| {
        fields.add(name, value, concealed, custom);
    };

    let username = text("identifier");
    add(field::USERNAME, username.clone(), false, false);

    // Current secrets: the first password is the entry's; a secret of another kind that is a
    // one-time-code secret is its code (a password never is, even one that looks like base32);
    // anything else is the user's own field.
    let mut otp = false;
    if let Some(code) = one_time_password(credential, bytes) {
        otp = true;
        add(field::TOTP, code, true, false);
    }
    let mut password = false;
    let secrets =
        credential.child("secrets").into_iter().flat_map(|secrets| secrets.children_named("secret"));
    let mut extra = Vec::new();
    for secret in secrets.filter(|secret| !flag(secret, "archived", bytes)) {
        let value = secret.child("secretValue").map(|value| trimmed(&value.text(bytes))).unwrap_or_default();
        let kind = secret.child("kind").map(|kind| trimmed(&kind.text(bytes))).unwrap_or_default();
        if kind.as_slice() == b"0" && !password {
            password = true;
            add(field::PASSWORD, value, true, false);
        } else if kind.as_slice() != b"0" && !otp && totp::parse(&value).is_ok() {
            otp = true;
            add(field::TOTP, value, true, false);
        } else {
            extra.push((if kind.as_slice() == b"0" { "Password" } else { "Secret" }, value));
        }
    }

    let services =
        credential.child("services").into_iter().flat_map(|services| services.children_named("service"));
    let mut first_host = None;
    for service in services {
        let address =
            service.child("address").map(|address| trimmed(&address.text(bytes))).unwrap_or_default();
        first_host = first_host.or_else(|| host(&address));
        add(field::URL, address, false, false);
    }
    add(field::NOTES, text("notes"), true, false);
    for (name, value) in extra {
        add(name, value, true, true);
    }
    let known = ["name", "identifier", "secrets", "services", "notes", "oneTimePassword", "oneTimePasswords"];
    fields.add_rest(credential, &known, bytes);

    let name = title(&text("name"));
    let title = if !name.is_empty() {
        name
    } else if let Some(host) = first_host {
        host
    } else {
        title(&username)
    };
    (!title.is_empty() && fields.has_content()).then_some(NewEntry {
        kind: EntryKind::Login,
        title,
        fields: fields.0,
    })
}

/// The item's one-time code as the app stores it: the seed in base32, or an `otpauth://` link
/// when the algorithm, digits or period are not the usual SHA1, 6 and 30. `None` when there is
/// none or it does not make a valid code.
fn one_time_password(credential: &Element, bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let otp = credential
        .child("oneTimePassword")
        .or_else(|| credential.child("oneTimePasswords").and_then(|all| all.child("oneTimePassword")))?;
    let text = |name: &str| otp.child(name).map(|child| trimmed(&child.text(bytes))).unwrap_or_default();
    let key = base64(&text("seed"))?;
    let mut secret = base32(&key);
    let algorithm = String::from_utf8_lossy(&text("algorithm")).to_ascii_uppercase();
    let digits = String::from_utf8_lossy(&text("digits")).into_owned();
    let period = String::from_utf8_lossy(&text("period")).into_owned();
    let usual = matches!(algorithm.as_str(), "" | "SHA1")
        && matches!(digits.as_str(), "" | "6")
        && matches!(period.as_str(), "" | "30");
    if !usual {
        let mut link = Zeroizing::new(Vec::with_capacity(96 + secret.len()));
        link.extend_from_slice(b"otpauth://totp/?secret=");
        link.extend_from_slice(&secret);
        for (key, value) in [("algorithm", algorithm), ("digits", digits), ("period", period)] {
            if !value.is_empty() {
                link.extend_from_slice(format!("&{key}={value}").as_bytes());
            }
        }
        secret = link;
    }
    totp::parse(&secret).is_ok().then_some(secret)
}

/// RFC 4648 base64 (standard alphabet, padding optional); `None` if it is not.
fn base64(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 3 / 4));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in text.iter().take_while(|&&byte| byte != b'=') {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    buffer.zeroize();
    (!out.is_empty()).then_some(out)
}

/// RFC 4648 base32, upper case, without padding.
fn base32(key: &[u8]) -> Zeroizing<Vec<u8>> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Zeroizing::new(Vec::with_capacity(key.len().div_ceil(5) * 8));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in key {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize]);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize]);
    }
    buffer.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_base32_round_trip() {
        // RFC 4648 test vectors.
        assert_eq!(base64(b"Zm9vYmFy").unwrap().as_slice(), b"foobar");
        assert_eq!(base64(b"Zm9vYg==").unwrap().as_slice(), b"foob");
        assert_eq!(base32(b"foobar").as_slice(), b"MZXW6YTBOI");
        assert_eq!(base32(b"fo").as_slice(), b"MZXQ");
        assert!(base64(b"not base64!").is_none());
    }
}
