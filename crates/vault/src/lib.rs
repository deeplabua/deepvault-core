//! The DeepVault vault: the `.dvault` v1 file format and its key hierarchy (PRD 04).
//!
//! ```text
//! master password ─Argon2id(salt, params)─► KEK_pw ─┐
//! device key (Secure Enclave, Touch ID) ──► KEK_se ─┼─ XChaCha20-Poly1305 wraps VK (slots)
//!                                                   ┘
//! VK (32 random bytes) ─HKDF-SHA256(vault_id)─► K_header_mac, K_file_mac, K_entries
//! ```
//!
//! Bytes in, bytes out: no file system, no network, no logging. Secrets live in zeroed-on-drop
//! containers without `Debug`.

pub mod aead;
mod entropy;
mod entry;
mod error;
mod format;
pub mod kdf;
pub mod keys;
mod secret;
mod vault;

pub use entropy::{Entropy, SystemEntropy};
pub use entry::{field, EntryKind, EntrySummary, Field, NewEntry};
pub use error::{Result, VaultError};
pub use format::{MAGIC, VERSION};
pub use kdf::KdfParams;
pub use secret::{Key, SecretBytes};
pub use vault::Vault;

/// Deterministic pieces for test vectors. Behind the `testing` feature: never in the app.
#[cfg(feature = "testing")]
pub mod testing {
    pub use crate::entropy::ScriptedEntropy;

    use crate::entry::{Entry, NewEntry};

    /// The CBOR an entry is sealed as.
    pub fn entry_plaintext(new: NewEntry, created_at: u64, updated_at: u64) -> Vec<u8> {
        let entry = Entry {
            kind: new.kind,
            title: new.title,
            fields: new.fields,
            created_at,
            updated_at,
            deleted: false,
        };
        entry.to_cbor().to_vec()
    }
}
