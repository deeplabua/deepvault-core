//! The key hierarchy (PRD 04, «Иерархия ключей»): a random vault key (VK) wrapped in slots by
//! key-encryption keys, and subkeys derived from VK with HKDF-SHA256.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::aead::{self, NONCE_LEN, TAG_LEN};
use crate::format::{MAGIC, VERSION};
use crate::secret::{Key, KEY_LEN};

pub const VAULT_ID_LEN: usize = 16;
pub const WRAPPED_VK_LEN: usize = KEY_LEN + TAG_LEN;
pub const MAC_LEN: usize = 32;

/// What unlocks a slot. The password and recovery slots live in the file header; the device
/// slot (Touch ID, a key behind the Secure Enclave) lives in this Mac's Keychain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Password,
    Recovery,
    Device,
}

impl SlotKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Recovery => "recovery",
            Self::Device => "device",
        }
    }

    pub(crate) fn from_label(label: &str) -> Option<Self> {
        [Self::Password, Self::Recovery, Self::Device].into_iter().find(|kind| kind.label() == label)
    }
}

/// Associated data that binds a ciphertext to its purpose, this format version and this vault:
/// `"DVLT" ‖ version (u16 LE) ‖ purpose ‖ 0x00 ‖ vault_id ‖ extra`.
pub fn aad(purpose: &str, vault_id: &[u8; VAULT_ID_LEN], extra: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 2 + purpose.len() + 1 + VAULT_ID_LEN + extra.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&VERSION.to_le_bytes());
    aad.extend_from_slice(purpose.as_bytes());
    aad.push(0);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(extra);
    aad
}

fn slot_aad(kind: SlotKind, vault_id: &[u8; VAULT_ID_LEN]) -> Vec<u8> {
    aad("slot", vault_id, kind.label().as_bytes())
}

/// VK sealed under a KEK: 48 bytes.
pub fn wrap_vk(
    kek: &Key,
    vk: &Key,
    nonce: &[u8; NONCE_LEN],
    kind: SlotKind,
    vault_id: &[u8; VAULT_ID_LEN],
) -> Vec<u8> {
    aead::seal(kek, nonce, vk.expose(), &slot_aad(kind, vault_id))
}

/// `None` when this KEK does not open the slot.
pub fn unwrap_vk(
    kek: &Key,
    wrapped: &[u8],
    nonce: &[u8; NONCE_LEN],
    kind: SlotKind,
    vault_id: &[u8; VAULT_ID_LEN],
) -> Option<Key> {
    let vk = aead::open(kek, nonce, wrapped, &slot_aad(kind, vault_id))?;
    Key::from_slice(vk.expose())
}

/// The keys VK is never used for directly: one per purpose, so a MAC key is never a cipher key.
pub struct Subkeys {
    pub header_mac: Key,
    pub file_mac: Key,
    pub entries: Key,
}

impl Subkeys {
    /// HKDF-SHA256 with the vault id as salt and a label per purpose as info.
    pub fn derive(vk: &Key, vault_id: &[u8; VAULT_ID_LEN]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(vault_id), vk.expose());
        let expand = |info: &str| {
            let mut key = Key::zeroed();
            // 32 bytes is far below HKDF-SHA256's 8160-byte limit.
            hkdf.expand(info.as_bytes(), key.expose_mut()).expect("HKDF output length");
            key
        };
        Self {
            header_mac: expand("deepvault/v1/header-mac"),
            file_mac: expand("deepvault/v1/file-mac"),
            entries: expand("deepvault/v1/entries"),
        }
    }
}

pub fn mac(key: &Key, data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.expose()).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Compares in constant time.
pub fn verify_mac(key: &Key, data: &[u8], expected: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.expose()).expect("HMAC takes any key length");
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_opens_only_with_its_kek_kind_and_vault() {
        let kek = Key::from_slice(&[1; 32]).unwrap();
        let vk = Key::from_slice(&[2; 32]).unwrap();
        let nonce = [3; NONCE_LEN];
        let id = [4; VAULT_ID_LEN];
        let wrapped = wrap_vk(&kek, &vk, &nonce, SlotKind::Password, &id);
        assert_eq!(wrapped.len(), WRAPPED_VK_LEN);

        let opened = unwrap_vk(&kek, &wrapped, &nonce, SlotKind::Password, &id).unwrap();
        assert_eq!(opened.expose(), vk.expose());
        assert!(unwrap_vk(&kek, &wrapped, &nonce, SlotKind::Recovery, &id).is_none());
        assert!(unwrap_vk(&kek, &wrapped, &nonce, SlotKind::Password, &[5; VAULT_ID_LEN]).is_none());
        let other = Key::from_slice(&[9; 32]).unwrap();
        assert!(unwrap_vk(&other, &wrapped, &nonce, SlotKind::Password, &id).is_none());
    }

    #[test]
    fn subkeys_differ_from_each_other_and_from_the_vault_key() {
        let vk = Key::from_slice(&[2; 32]).unwrap();
        let keys = Subkeys::derive(&vk, &[4; VAULT_ID_LEN]);
        let all = [vk.expose(), keys.header_mac.expose(), keys.file_mac.expose(), keys.entries.expose()];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
