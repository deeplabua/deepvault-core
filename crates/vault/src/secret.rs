//! Containers for secrets: zeroed on drop, and without `Debug`, `Display` or `Serialize`, so a
//! secret cannot be printed or logged by accident.

use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;

/// A 256-bit key: the vault key, a key-encryption key or a subkey.
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    /// An all-zero key to be filled in place, so the bytes never sit in a stack copy.
    pub(crate) fn zeroed() -> Self {
        Self(Zeroizing::new([0; KEY_LEN]))
    }

    /// `None` unless `bytes` is exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let mut key = Self::zeroed();
        key.0.copy_from_slice(bytes);
        Some(key)
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }
}

/// Secret bytes of any length: a decrypted field, a serialised entry.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Hands the bytes over (to the FFI layer, which passes them to Swift). From here on
    /// zeroing them is the receiver's job.
    pub fn into_unprotected(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0)
    }
}
