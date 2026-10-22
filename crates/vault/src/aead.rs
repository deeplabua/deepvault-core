//! XChaCha20-Poly1305 (PRD 04, «Почему XChaCha20-Poly1305»): a random 24-byte nonce per
//! message, no counter to keep.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::secret::{Key, SecretBytes};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// Ciphertext with the 16-byte tag appended.
pub fn seal(key: &Key, nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher
        .encrypt(&XNonce::from(*nonce), Payload { msg: plaintext, aad })
        // Only fails for messages longer than ChaCha20's 256 GiB keystream.
        .expect("message too long for XChaCha20-Poly1305")
}

/// `None` when the tag does not verify: wrong key, wrong AAD or changed bytes.
pub fn open(key: &Key, nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: &[u8]) -> Option<SecretBytes> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    cipher.decrypt(&XNonce::from(*nonce), Payload { msg: ciphertext, aad }).ok().map(SecretBytes::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_byte_key_or_aad_does_not_open() {
        let key = Key::from_slice(&[7; 32]).unwrap();
        let nonce = [9; NONCE_LEN];
        let sealed = seal(&key, &nonce, b"secret", b"aad");
        assert_eq!(sealed.len(), 6 + TAG_LEN);
        assert_eq!(open(&key, &nonce, &sealed, b"aad").unwrap().expose(), b"secret");

        for index in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            assert!(open(&key, &nonce, &changed, b"aad").is_none(), "byte {index}");
        }
        assert!(open(&key, &nonce, &sealed, b"aaD").is_none());
        assert!(open(&key, &[8; NONCE_LEN], &sealed, b"aad").is_none());
        assert!(open(&Key::from_slice(&[6; 32]).unwrap(), &nonce, &sealed, b"aad").is_none());
    }
}
