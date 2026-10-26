//! KeePass KDBX (ADR-0008): a KDBX 4.x or 3.1 file read into new entries, and a vault's
//! entries written as KDBX 4.0 — ChaCha20 with Argon2id, as KeePassXC makes them.
//!
//! The file, the key, the decrypted XML and every protected value stay in zeroed-on-drop
//! buffers here; nothing is written to disk. What KeePass has and a vault has not — groups,
//! history, the recycle bin, icons — becomes tags or is left out.

mod crypto;
mod header;
mod xml;

use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::entry::{field, EntryKind, Field, NewEntry};
use crate::error::{Result, VaultError};
use crate::import::{Format, Imported};
use crate::passkey::{base64url_decode, base64url_encode, pem_to_der, Passkey};

pub use crypto::Key;

/// A field of an attachment (as the app stores one): the file's name, a zero byte, its content.
pub(crate) const ATTACHMENT: &str = "attachment";

/// The string that says which DeepVault kind an exported entry was, so a KDBX made by
/// DeepVault comes back as cards, bank accounts, keys… rather than logins.
const KIND_STRING: &str = "DeepVault-Kind";

/// The entries of a KDBX file opened with `key`. `WrongPassword` when the key does not open
/// it, `Corrupted` when it is damaged, `InvalidImport` when it is not KDBX, `UnsupportedVersion`
/// for KDBX 1.x/2.x or a cipher or key derivation not supported (Twofish).
pub fn read(file: &[u8], key: &Key) -> Result<Imported> {
    let (header, payload) = header::Header::parse(file)?;
    let plain = crypto::decrypt(&header, payload, file, key)?;
    let (stream, binaries, xml) = if header.major >= 4 {
        let inner = header::Inner::parse(&plain)?;
        (inner.stream, inner.binaries, Zeroizing::new(plain[inner.end..].to_vec()))
    } else {
        let stream = header.inner_stream.clone().ok_or(VaultError::Corrupted)?;
        (stream, Vec::new(), plain)
    };
    let parsed = xml::read(&xml, crypto::InnerStream::new(&stream)?, binaries)?;
    let mut entries = Vec::with_capacity(parsed.entries.len());
    let mut skipped = parsed.skipped;
    for entry in parsed.entries {
        match new_entry(entry) {
            Some(new) => entries.push(new),
            None => skipped += 1,
        }
    }
    Ok(Imported { format: Format::KeePass, entries, skipped })
}

/// `entries` as a KDBX 4.0 file for `key`, all in one group, tags as KeePass tags.
pub fn write(entries: &[ExportEntry], key: &Key, entropy: &mut dyn Entropy) -> Result<Vec<u8>> {
    let mut stream_key = Zeroizing::new([0u8; 64]);
    entropy.fill(stream_key.as_mut());
    let mut binaries = Vec::new();
    let xml_entries: Vec<xml::Entry> =
        entries.iter().flat_map(|entry| export_entry(entry, &mut binaries)).collect();
    let xml = xml::write(&xml_entries, &mut crypto::InnerStream::chacha(stream_key.as_ref()), entropy);
    crypto::encrypt(stream_key.as_ref(), &binaries, &xml, key, entropy)
}

/// A live entry as `Vault::export_kdbx` hands it here.
pub struct ExportEntry {
    pub kind: EntryKind,
    pub title: String,
    pub fields: Vec<Field>,
    pub created: u64,
    pub modified: u64,
}

// MARK: - KeePass → DeepVault

/// One KeePass entry as a new entry: a login (or a note when it has nothing but notes), its
/// group path and tags as tags, its strings and files as fields. `None`: nothing in it.
fn new_entry(entry: xml::Entry) -> Option<NewEntry> {
    let kind = entry
        .strings
        .iter()
        .find(|s| s.key == KIND_STRING)
        .and_then(|s| kind_named(std::str::from_utf8(&s.value).ok()?));
    let mut fields = Vec::new();
    let mut title = String::new();
    let mut has = (false, false); // a password or a site, notes
    let mut push = |name: &str, value: &[u8], concealed: bool, custom: bool| {
        if !value.is_empty() {
            fields.push(Field { name: name.into(), value: value.to_vec(), concealed, custom });
        }
    };
    for string in &entry.strings {
        let value = &string.value[..];
        match string.key.as_str() {
            "Title" => title = String::from_utf8_lossy(value).trim().to_owned(),
            "UserName" => push(field::USERNAME, value, false, false),
            "Password" => {
                has.0 |= !value.is_empty();
                push(field::PASSWORD, value, true, false);
            }
            "URL" => {
                has.0 |= !value.is_empty();
                push(field::URL, value, false, false);
            }
            "Notes" => {
                has.1 |= !value.is_empty();
                push(field::NOTES, value, kind.is_none(), false);
            }
            // KeePassXC's and KeePass 2.47's one-time codes.
            "otp" | "TimeOtp-Secret-Base32" => push(field::TOTP, value, true, false),
            KIND_STRING => {}
            key if key.starts_with("KPEX_PASSKEY_") => {}
            key if key.starts_with("KP2A_URL") => push(field::URL, value, false, false),
            // DeepVault's own names, from an export of DeepVault's.
            key if kind.is_some() && known_field(key) => push(key, value, string.protected, false),
            key => push(key, value, string.protected, true),
        }
    }
    if let Some(passkey) = passkey_field(&entry.strings, entry.created) {
        has.0 = true;
        fields.push(passkey);
    }
    for (name, content) in &entry.files {
        let mut value = Vec::with_capacity(name.len() + 1 + content.len());
        value.extend_from_slice(name.replace('\0', "").as_bytes());
        value.push(0);
        value.extend_from_slice(content);
        fields.push(Field { name: ATTACHMENT.into(), value, concealed: true, custom: false });
    }
    for tag in entry.group.iter().chain(entry.tags.iter()) {
        if !fields.iter().any(|f| f.name == field::TAG && f.value.eq_ignore_ascii_case(tag.as_bytes())) {
            fields.push(Field {
                name: field::TAG.into(),
                value: tag.clone().into_bytes(),
                concealed: false,
                custom: false,
            });
        }
    }
    if title.is_empty() && fields.iter().all(|f| f.name == field::TAG) {
        return None;
    }
    let kind = kind.unwrap_or(if has.0 || !has.1 { EntryKind::Login } else { EntryKind::Note });
    if title.is_empty() {
        title = fields
            .iter()
            .find(|f| f.name == field::URL)
            .and_then(|f| crate::import::host(&f.value))
            .unwrap_or_else(|| "KeePass".into());
    }
    Some(NewEntry { kind, title, fields })
}

fn kind_named(name: &str) -> Option<EntryKind> {
    Some(match name {
        "login" => EntryKind::Login,
        "password" => EntryKind::Password,
        "note" => EntryKind::Note,
        "card" => EntryKind::Card,
        "bank_account" => EntryKind::BankAccount,
        "software_license" => EntryKind::SoftwareLicense,
        "environment" => EntryKind::Environment,
        "ssh_key" => EntryKind::SshKey,
        "generated_password" => EntryKind::GeneratedPassword,
        _ => return None,
    })
}

fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Login => "login",
        EntryKind::Password => "password",
        EntryKind::Note => "note",
        EntryKind::Card => "card",
        EntryKind::BankAccount => "bank_account",
        EntryKind::SoftwareLicense => "software_license",
        EntryKind::Environment => "environment",
        EntryKind::SshKey => "ssh_key",
        EntryKind::GeneratedPassword => "generated_password",
    }
}

/// A field name the app knows (not a custom one), for entries coming back from DeepVault.
fn known_field(name: &str) -> bool {
    [
        field::NOTES,
        field::CARDHOLDER,
        field::NUMBER,
        field::EXPIRY,
        field::CVV,
        field::BANK,
        field::HOLDER,
        field::IBAN,
        field::SWIFT,
        field::PIN,
        field::LICENSE_KEY,
        field::LICENSED_TO,
        field::EMAIL,
        field::VERSION,
        field::PURCHASED,
        field::SHELL,
        field::SSH_PRIVATE_KEY,
        field::SSH_PUBLIC_KEY,
        "ssh_secure_enclave",
    ]
    .contains(&name)
}

// MARK: - DeepVault → KeePass

/// A live entry as a KeePass entry: Title, UserName, Password, URL and Notes as KeePass has
/// them, more sites as `KP2A_URL_n`, one-time codes as KeePassXC's `otp`, files as binaries,
/// everything else as strings under DeepVault's names (protected when concealed), and — for
/// a kind KeePass has not — `DeepVault-Kind`. A passkey as KeePassXC keeps one (`KPEX_PASSKEY_*`,
/// one per entry): the first in the entry, each other in an entry of its own.
fn export_entry(entry: &ExportEntry, binaries: &mut Vec<(bool, Zeroizing<Vec<u8>>)>) -> Vec<xml::Entry> {
    let mut passkeys = Vec::new();
    let mut strings = vec![xml::StringField::new("Title", entry.title.as_bytes(), false)];
    let mut tags = Vec::new();
    let mut files = Vec::new();
    let (mut urls, mut notes) = (0, 0);
    for f in &entry.fields {
        let value = &f.value[..];
        if f.custom {
            let key = if ["Title", "UserName", "Password", "URL", "Notes", "otp", KIND_STRING]
                .contains(&f.name.as_str())
            {
                format!("{} (DeepVault)", f.name)
            } else {
                f.name.clone()
            };
            strings.push(xml::StringField::new(&key, value, f.concealed));
            continue;
        }
        match f.name.as_str() {
            n if n == field::USERNAME => strings.push(xml::StringField::new("UserName", value, false)),
            n if n == field::PASSWORD => strings.push(xml::StringField::new("Password", value, true)),
            n if n == field::URL => {
                let key = if urls == 0 { "URL".to_owned() } else { format!("KP2A_URL_{urls}") };
                urls += 1;
                strings.push(xml::StringField::new(&key, value, false));
            }
            n if n == field::NOTES => {
                notes += 1;
                let key = if notes == 1 { "Notes".to_owned() } else { format!("Notes {notes}") };
                strings.push(xml::StringField::new(&key, value, f.concealed));
            }
            n if n == field::TOTP => {
                let text = String::from_utf8_lossy(value);
                let uri = if text.starts_with("otpauth://") {
                    text.into_owned()
                } else {
                    format!("otpauth://totp/{}?secret={}", percent(&entry.title), text.replace(' ', ""))
                };
                strings.push(xml::StringField::new("otp", uri.as_bytes(), true));
            }
            n if n == field::TAG => tags.push(String::from_utf8_lossy(value).into_owned()),
            n if n == field::ICON || n == field::LINK => {}
            n if n == field::PASSKEY => {
                if let Ok(passkey) = Passkey::from_bytes(value) {
                    passkeys.push(passkey);
                }
            }
            ATTACHMENT => {
                let split = value.iter().position(|&b| b == 0);
                let (name, content) = match split {
                    Some(at) => (String::from_utf8_lossy(&value[..at]).into_owned(), &value[at + 1..]),
                    None => (String::new(), value),
                };
                files.push((if name.is_empty() { "file".into() } else { name }, binaries.len()));
                binaries.push((true, Zeroizing::new(content.to_vec())));
            }
            other => strings.push(xml::StringField::new(other, value, f.concealed)),
        }
    }
    if !matches!(entry.kind, EntryKind::Login | EntryKind::Note) {
        strings.push(xml::StringField::new(KIND_STRING, kind_name(entry.kind).as_bytes(), false));
    }
    let mut passkeys = passkeys.into_iter();
    if let Some(first) = passkeys.next() {
        strings.extend(passkey_strings(&first));
    }
    let mut out = vec![xml::Entry {
        strings,
        tags: tags.clone(),
        group: None,
        files: Vec::new(),
        refs: files,
        created: entry.created,
        modified: entry.modified,
    }];
    for passkey in passkeys {
        let title = format!("{} ({})", entry.title, passkey.user_name);
        let mut strings = vec![
            xml::StringField::new("Title", title.as_bytes(), false),
            xml::StringField::new("UserName", passkey.user_name.as_bytes(), false),
            xml::StringField::new("URL", format!("https://{}", passkey.rp_id).as_bytes(), false),
        ];
        strings.extend(passkey_strings(&passkey));
        out.push(xml::Entry {
            strings,
            tags: tags.clone(),
            group: None,
            files: Vec::new(),
            refs: Vec::new(),
            created: entry.created,
            modified: entry.modified,
        });
    }
    out
}

/// KeePassXC's strings for a passkey; the key as a protected PEM.
fn passkey_strings(passkey: &Passkey) -> Vec<xml::StringField> {
    let mut out = vec![
        xml::StringField::new(KPEX_RP, passkey.rp_id.as_bytes(), false),
        xml::StringField::new(KPEX_USERNAME, passkey.user_name.as_bytes(), false),
        xml::StringField::new(KPEX_CREDENTIAL_ID, base64url_encode(&passkey.credential_id).as_bytes(), true),
        xml::StringField::new(KPEX_USER_HANDLE, base64url_encode(&passkey.user_handle).as_bytes(), true),
    ];
    if let Ok(pem) = passkey.pem() {
        out.push(xml::StringField::new(KPEX_KEY, pem.as_bytes(), true));
    }
    out
}

const KPEX_RP: &str = "KPEX_PASSKEY_RELYING_PARTY";
const KPEX_USERNAME: &str = "KPEX_PASSKEY_USERNAME";
const KPEX_CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
const KPEX_USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
const KPEX_KEY: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";

/// A KeePassXC passkey (its `KPEX_PASSKEY_*` strings) as a `passkey` field; `None` when one
/// is missing or the key is not P-256.
fn passkey_field(strings: &[xml::StringField], created: u64) -> Option<Field> {
    let get = |key: &str| {
        strings.iter().find(|s| s.key == key).map(|s| String::from_utf8_lossy(&s.value).into_owned())
    };
    let rp = get(KPEX_RP)?;
    let pem = Zeroizing::new(get(KPEX_KEY)?);
    let der = pem_to_der(&pem)?;
    let credential = base64url_decode(&get(KPEX_CREDENTIAL_ID)?)?;
    let handle = get(KPEX_USER_HANDLE).and_then(|h| base64url_decode(&h)).unwrap_or_default();
    let user = get(KPEX_USERNAME).unwrap_or_default();
    let passkey = Passkey::imported(&rp, &credential, &handle, &user, &user, &der, created)?;
    Some(Field { name: field::PASSKEY.into(), value: passkey.to_bytes(), concealed: true, custom: false })
}

/// For a label in an `otpauth://` URI.
fn percent(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
