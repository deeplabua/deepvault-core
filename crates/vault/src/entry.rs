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
    /// A TOTP secret: `otpauth://totp/…` or base32 (concealed).
    pub const TOTP: &str = "totp";
    /// The entry's picture, a small PNG the user chose (not concealed: it is in the index).
    pub const ICON: &str = "icon";
    /// A tag (any kind of entry; repeated for several, not concealed: it is in the index).
    pub const TAG: &str = "tag";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Login,
    Note,
    Card,
}

/// One named value. `concealed` values (passwords, notes, card numbers) stay out of the index
/// and are decrypted only when asked for.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    #[serde(with = "cbor_bytes")]
    pub value: Vec<u8>,
    pub concealed: bool,
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
    pub deleted: bool,
}

impl Entry {
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
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
    /// The entry's tags, in order (for the sidebar and search).
    pub tags: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
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
            tags: entry
                .fields
                .iter()
                .filter(|field| field.name == field::TAG && !field.concealed)
                .filter_map(|field| String::from_utf8(field.value.clone()).ok())
                .collect(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
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
    pub value: Option<String>,
}

impl FieldSummary {
    pub(crate) fn new(field: &Field) -> Self {
        Self {
            name: field.name.clone(),
            concealed: field.concealed,
            value: if field.concealed { None } else { String::from_utf8(field.value.clone()).ok() },
        }
    }
}
