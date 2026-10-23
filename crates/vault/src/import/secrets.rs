//! The XML export of Secrets (macOS): `<credential>` items with a `name`, an `identifier`
//! (user name), `secrets/secret` (passwords; `kind` 0 — other kinds are kept as fields),
//! `services/service/address` (sites) and `notes`. Items in its trash are skipped; archived
//! ones are kept with an `archived` tag; archived secrets (old passwords) are left out.
//! Any other element with text is kept as the user's own concealed field, so nothing in the
//! file is lost because this mapping does not know it.

use zeroize::Zeroizing;

use super::xml::{self, Element};
use super::{host, trimmed, Format, Imported};
use crate::entry::{field, EntryKind, Field, NewEntry};
use crate::error::{Result, VaultError};
use crate::totp;

/// Elements that are bookkeeping, not content.
const BOOKKEEPING: &[&str] =
    &["uuid", "creationDate", "modificationDate", "favorite", "passkeyEnabled", "trashed", "archived"];

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
    let (mut password, mut otp) = (false, false);
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
    let known = ["name", "identifier", "secrets", "services", "notes", "tags"];
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
