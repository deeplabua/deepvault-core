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
            updated_at: entry.updated_at,
        }
    }
}
