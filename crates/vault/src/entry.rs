//! What a vault keeps: entries made of named fields. Each entry is serialised to CBOR and
//! sealed on its own (PRD 04: per-entry encryption, so sync can merge entry by entry).

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::format::cbor_bytes;

/// Field names the app knows. Any other name is a custom field (Pro, v0.5).
pub mod field {
    pub const URL: &str = "url";
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const NOTES: &str = "notes";
    pub const CARDHOLDER: &str = "cardholder";
    pub const NUMBER: &str = "number";
    pub const EXPIRY: &str = "expiry";
    pub const CVV: &str = "cvv";
    /// A bank account's bank, holder, IBAN (or account number), SWIFT/BIC and PIN (concealed).
    pub const BANK: &str = "bank";
    pub const HOLDER: &str = "holder";
    pub const IBAN: &str = "iban";
    pub const SWIFT: &str = "swift";
    pub const PIN: &str = "pin";
    /// A software licence's key (concealed), owner, e-mail, version and purchase date.
    pub const LICENSE_KEY: &str = "license_key";
    pub const LICENSED_TO: &str = "licensed_to";
    pub const EMAIL: &str = "email";
    pub const VERSION: &str = "version";
    pub const PURCHASED: &str = "purchased";
    /// A TOTP secret: `otpauth://totp/…` or base32 (concealed).
    pub const TOTP: &str = "totp";
    /// The entry's picture, a small PNG the user chose (not concealed: it is in the index).
    pub const ICON: &str = "icon";
    /// A tag (any kind of entry; repeated for several, not concealed: it is in the index).
    pub const TAG: &str = "tag";
    /// Another entry this one is linked to, by its id as 32 lowercase hex digits (repeated for
    /// several, not concealed: it is in the index, so the other entry can show the link back).
    pub const LINK: &str = "link";
    /// A variable of an `environment` entry given to every new shell without asking (ADR-0005,
    /// «Завжди в шелі»): the variable's name, repeated for several; not concealed.
    pub const SHELL: &str = "shell";
    /// An SSH key's private half, `openssh-key-v1` unencrypted (concealed; ADR-0006).
    pub const SSH_PRIVATE_KEY: &str = "ssh_private_key";
    /// An SSH key's public line, `ssh-ed25519 AAAA… comment` (not concealed).
    pub const SSH_PUBLIC_KEY: &str = "ssh_public_key";
    /// A passkey of a login (ADR-0010): CBOR with its site, id, user and P-256 key (concealed;
    /// repeated for several).
    pub const PASSKEY: &str = "passkey";
    /// Another entry with the same site and user name that is another account, by its id as 32
    /// lowercase hex digits (`Vault::mark_distinct`; repeated, on both entries; not concealed:
    /// in the index, so the audit does not offer the pair as duplicates).
    pub const DISTINCT: &str = "distinct";
}

/// Stored by name (`login`, `password`, `note`, `card`, `bank_account`,
/// `software_license`, `environment`, `ssh_key`, `generated_password`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Login,
    Note,
    Card,
    BankAccount,
    SoftwareLicense,
    /// A password alone: an archive's, a router's, an app-specific one.
    Password,
    /// Environment variables (ADR-0005): custom fields named `KEY`, for `deepvault run` / `env`.
    Environment,
    /// An SSH key for the agent (ADR-0006): `ssh_private_key`, `ssh_public_key`.
    SshKey,
    /// A password the generator made and the user copied, kept so it can be found later (with
    /// `password`, as a `password` entry has).
    GeneratedPassword,
}

/// One named value. `concealed` values (passwords, notes, card numbers) stay out of the index
/// and are decrypted only when asked for. A `custom` field is one the user named: its name is
/// only a label, never one of `field` — a custom «password» is not the entry's password.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    #[serde(with = "cbor_bytes")]
    pub value: Vec<u8>,
    pub concealed: bool,
    /// Left out when false, so a field without it is stored as it was before custom fields.
    #[serde(default, skip_serializing_if = "is_false")]
    pub custom: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// An entry as the app hands it in.
pub struct NewEntry {
    pub kind: EntryKind,
    pub title: String,
    pub fields: Vec<Field>,
}

/// The encrypted payload of a block. A deleted entry stays as a tombstone (no title, no
/// fields) so a merge can tell «deleted» from «never seen».
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    #[zeroize(skip)]
    pub kind: EntryKind,
    pub title: String,
    pub fields: Vec<Field>,
    pub created_at: u64,
    pub updated_at: u64,
    /// When a value of it was last copied or its site opened (`Vault::mark_used`); not a
    /// change, so not `updated_at`. Left out while 0 (never), so such an entry is stored as it
    /// was before.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub used_at: u64,
    /// Starred by the user (`Vault::set_favorite`). Left out while false, so such an entry is
    /// stored as it was before.
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    /// When the user deleted it (`Vault::trash_entry`): in Recently Deleted until it is
    /// restored or deleted for good. Left out while 0 (live), so a live entry is stored as it
    /// was before.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub trashed_at: u64,
    pub deleted: bool,
}

impl Entry {
    /// The first field the app knows by `name` (custom fields are only labels).
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| !field.custom && field.name == name)
    }

    /// CBOR in a buffer that is zeroed on drop. Reserved up front so the buffer does not
    /// grow — growing would leave copies of the plaintext behind in freed memory.
    pub fn to_cbor(&self) -> Zeroizing<Vec<u8>> {
        let size = 256
            + self.title.len()
            + self.fields.iter().map(|f| 32 + f.name.len() + f.value.len()).sum::<usize>();
        let mut buf = Zeroizing::new(Vec::with_capacity(size));
        ciborium::into_writer(self, &mut *buf).expect("an entry always serialises");
        buf
    }

    pub fn from_cbor(bytes: &[u8]) -> Option<Self> {
        crate::format::from_cbor(bytes)
    }
}

/// What the entry list shows: no concealed field. Kept in memory while the vault is unlocked,
/// zeroed when it locks.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EntrySummary {
    pub id: [u8; 16],
    #[zeroize(skip)]
    pub kind: EntryKind,
    pub title: String,
    pub url: Option<String>,
    pub username: Option<String>,
    /// The first `icon` field's bytes (a small PNG), for the list.
    pub icon: Option<Vec<u8>>,
    /// The entry has a one-time-code field (the list shows a clock).
    pub has_otp: bool,
    /// The entry keeps a passkey (ADR-0010): the sidebar's «Passkeys».
    pub has_passkey: bool,
    /// The entry's tags, in order (for the sidebar and search).
    pub tags: Vec<String>,
    /// The ids (32 lowercase hex digits) of the entries this one links to, in order.
    pub links: Vec<String>,
    /// The ids of the entries marked as another account, not a duplicate of this one.
    pub distinct: Vec<String>,
    /// A card's last four digits (`•••• 4417` in the list), from its `number` field: the rest
    /// of the number stays sealed.
    pub card_last4: Option<String>,
    /// The card network from the number's first digits (`visa`, `mastercard`, `americanexpress`,
    /// `discover`, `jcb`, `dinersclub`, `unionpay`, `maestro`, `mir`) for its logo.
    pub card_network: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    /// 0: never used.
    pub used_at: u64,
    pub favorite: bool,
    /// When it went to Recently Deleted; 0: live.
    pub trashed_at: u64,
}

impl EntrySummary {
    pub(crate) fn new(id: [u8; 16], entry: &Entry) -> Self {
        let visible = |name: &str| {
            entry
                .field(name)
                .filter(|field| !field.concealed)
                .and_then(|field| String::from_utf8(field.value.clone()).ok())
        };
        Self {
            id,
            kind: entry.kind,
            title: entry.title.clone(),
            url: visible(field::URL),
            username: visible(field::USERNAME),
            icon: entry.field(field::ICON).filter(|field| !field.concealed).map(|field| field.value.clone()),
            has_otp: entry.field(field::TOTP).is_some(),
            has_passkey: entry.fields.iter().any(|field| field.name == field::PASSKEY && !field.custom),
            card_network: entry.field(field::NUMBER).and_then(|field| card_network(&field.value)),
            card_last4: entry.field(field::NUMBER).and_then(|field| {
                let digits: Vec<u8> = field.value.iter().copied().filter(u8::is_ascii_digit).collect();
                (digits.len() >= 12)
                    .then(|| String::from_utf8_lossy(&digits[digits.len() - 4..]).into_owned())
            }),
            tags: entry
                .fields
                .iter()
                .filter(|field| field.name == field::TAG && !field.concealed && !field.custom)
                .filter_map(|field| String::from_utf8(field.value.clone()).ok())
                .collect(),
            links: entry
                .fields
                .iter()
                .filter(|field| field.name == field::LINK && !field.concealed && !field.custom)
                .filter_map(|field| String::from_utf8(field.value.clone()).ok())
                .collect(),
            distinct: entry
                .fields
                .iter()
                .filter(|field| field.name == field::DISTINCT && !field.concealed && !field.custom)
                .filter_map(|field| String::from_utf8(field.value.clone()).ok())
                .collect(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
            used_at: entry.used_at,
            favorite: entry.favorite,
            trashed_at: entry.trashed_at,
        }
    }
}

/// One field of an entry as the detail screen lists it: every name in order, the value only
/// when it is not concealed (and is UTF-8). Concealed values come one at a time through
/// `Vault::secret`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FieldSummary {
    pub name: String,
    pub concealed: bool,
    pub custom: bool,
    pub value: Option<String>,
}

impl FieldSummary {
    pub(crate) fn new(field: &Field) -> Self {
        Self {
            name: field.name.clone(),
            concealed: field.concealed,
            custom: field.custom,
            value: if field.concealed { None } else { String::from_utf8(field.value.clone()).ok() },
        }
    }
}

/// The network of a card number by its leading digits (IIN ranges); `None` when unknown.
fn card_network(number: &[u8]) -> Option<String> {
    let digits: Vec<u32> =
        number.iter().filter(|b| b.is_ascii_digit()).map(|b| u32::from(b - b'0')).collect();
    if digits.len() < 12 {
        return None;
    }
    let prefix = |n: usize| digits[..n].iter().fold(0u32, |acc, d| acc * 10 + d);
    let network = match (prefix(1), prefix(2), prefix(4)) {
        (4, _, _) => "visa",
        (_, 34 | 37, _) => "americanexpress",
        (_, 51..=55, _) | (_, _, 2221..=2720) => "mastercard",
        (_, _, 2200..=2204) => "mir",
        (_, 36 | 38 | 39, _) | (_, 30, _) => "dinersclub",
        (_, 62, _) => "unionpay",
        (_, 65, _) | (_, _, 6011) => "discover",
        (_, _, 3528..=3589) => "jcb",
        (_, 50 | 56..=58, _) | (_, 63 | 67, _) => "maestro",
        _ => return None,
    };
    Some(network.to_string())
}
