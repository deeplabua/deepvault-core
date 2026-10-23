//! The XML export of Secrets (macOS): `<credential>` items with a `name`, an `identifier`
//! (user name), `secrets/secret` (passwords; `kind` 0 — other kinds are kept as fields),
//! `services/service/address` (sites), `notes` and `oneTimePassword` (a one-time-code seed in
//! base64 with its algorithm, digits and period). Items in its trash are skipped; archived ones
//! are kept with an `archived` tag; archived secrets (old passwords) are left out.
//! Any other element with text is kept as the user's own concealed field, so nothing in the
//! file is lost because this mapping does not know it.

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
];

pub(super) fn parse(bytes: &[u8]) -> Result<Imported> {
    let root = xml::parse(bytes).ok_or(VaultError::InvalidImport)?;
    let mut credentials = Vec::new();
    root.find_all("credential", &mut credentials);
    if credentials.is_empty() {
        return Err(VaultError::InvalidImport);
    }
    let mut entries = Vec::new();
    let mut skipped = 0;
    for credential in credentials {
        match entry(credential, bytes) {
            Some(entry) => entries.push(entry),
            None => skipped += 1,
        }
    }
    Ok(Imported { format: Format::Secrets, entries, skipped })
}

fn flag(element: &Element, name: &str, bytes: &[u8]) -> bool {
    element.child(name).is_some_and(|child| trimmed(&child.text(bytes)).as_slice() == b"1")
}

/// One item, in the order the app saves a login; `None` for one in the trash or with nothing.
fn entry(credential: &Element, bytes: &[u8]) -> Option<NewEntry> {
    if flag(credential, "trashed", bytes) {
        return None;
    }
    let text =
        |name: &str| credential.child(name).map(|child| trimmed(&child.text(bytes))).unwrap_or_default();
    let mut fields = Vec::new();
    let mut add = |name: &str, mut value: Zeroizing<Vec<u8>>, concealed: bool, custom: bool| {
        if !value.is_empty() {
            // Moved, not copied: `Field` zeroes it from here on.
            fields.push(Field { name: name.into(), value: std::mem::take(&mut *value), concealed, custom });
        }
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
    // Whatever else the item holds, under its element name.
    let known =
        ["name", "identifier", "secrets", "services", "notes", "tags", "oneTimePassword", "oneTimePasswords"];
    for other in &credential.children {
        if !known.contains(&other.name.as_str()) && !BOOKKEEPING.contains(&other.name.as_str()) {
            add(&other.name, trimmed(&other.text(bytes)), true, true);
        }
    }
    if let Some(tags) = credential.child("tags") {
        for tag in &tags.children {
            add(field::TAG, trimmed(&tag.text(bytes)), false, false);
        }
    }
    if flag(credential, "archived", bytes) {
        add(field::TAG, Zeroizing::new(b"archived".to_vec()), false, false);
    }

    let name = String::from_utf8_lossy(&text("name")).into_owned();
    let title = if !name.is_empty() {
        name
    } else if let Some(host) = first_host {
        host
    } else {
        String::from_utf8_lossy(&username).into_owned()
    };
    let has_content = fields.iter().any(|field| field.name != field::TAG);
    (!title.is_empty() && has_content).then_some(NewEntry { kind: EntryKind::Login, title, fields })
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
