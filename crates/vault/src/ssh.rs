//! SSH keys for the agent (ADR-0006): ed25519 keys made or imported in the `openssh-key-v1`
//! format `ssh-keygen` writes (unencrypted), their public line, and signatures in the SSH wire
//! format. The private key stays here: callers get the public line and signatures only.
//!
//! ```text
//! "openssh-key-v1\0" string cipher("none") string kdf("none") string kdfoptions("") uint32 1
//! string public-blob   string private-section:
//!     uint32 check uint32 check string "ssh-ed25519" string pub(32) string seed‖pub(64)
//!     string comment   padding 1, 2, 3… to a multiple of 8
//! ```

use crate::{Entropy, Result, VaultError};
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

pub const ED25519: &str = "ssh-ed25519";
const MAGIC: &[u8] = b"openssh-key-v1\0";
const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// An ed25519 key read from its private form. The seed is zeroed on drop.
pub struct Ed25519Key {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    pub comment: String,
}

impl Ed25519Key {
    /// A new key from 32 random bytes.
    pub fn generate(entropy: &mut dyn Entropy, comment: &str) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        entropy.fill(seed.as_mut());
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Self { seed, public, comment: comment.to_string() }
    }

    /// The `-----BEGIN OPENSSH PRIVATE KEY-----` text, unencrypted. `Encrypted` for a key with
    /// a passphrase (remove it with `ssh-keygen -p -N ""` first); `Invalid` for anything else.
    pub fn from_openssh(text: &str) -> std::result::Result<Self, KeyError> {
        let body: String = text
            .trim()
            .strip_prefix(BEGIN)
            .and_then(|rest| rest.trim_end().strip_suffix(END))
            .ok_or(KeyError::Invalid)?
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let bytes = Zeroizing::new(base64_decode(&body).ok_or(KeyError::Invalid)?);
        let mut reader = Reader(bytes.strip_prefix(MAGIC).ok_or(KeyError::Invalid)?);
        let cipher = reader.string()?;
        let kdf = reader.string()?;
        let _options = reader.string()?;
        if cipher != b"none" || kdf != b"none" {
            return Err(KeyError::Encrypted);
        }
        if reader.u32()? != 1 {
            return Err(KeyError::Invalid);
        }
        let _public_blob = reader.string()?;
        let mut private = Reader(reader.string()?);
        if private.u32()? != private.u32()? {
            return Err(KeyError::Invalid);
        }
        if private.string()? != ED25519.as_bytes() {
            return Err(KeyError::Unsupported);
        }
        let public: [u8; 32] = private.string()?.try_into().map_err(|_| KeyError::Invalid)?;
        let both = private.string()?;
        if both.len() != 64 || both[32..] != public {
            return Err(KeyError::Invalid);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&both[..32]);
        if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != public {
            return Err(KeyError::Invalid);
        }
        let comment = String::from_utf8(private.string()?.to_vec()).map_err(|_| KeyError::Invalid)?;
        Ok(Self { seed, public, comment })
    }

    /// The private key as `ssh-keygen` writes it (unencrypted); zeroed on drop.
    pub fn to_openssh(&self, entropy: &mut dyn Entropy) -> Zeroizing<String> {
        let mut check = [0u8; 4];
        entropy.fill(&mut check);
        let mut private = Zeroizing::new(Vec::new());
        private.extend_from_slice(&check);
        private.extend_from_slice(&check);
        put_string(&mut private, ED25519.as_bytes());
        put_string(&mut private, &self.public);
        let mut both = Zeroizing::new(Vec::with_capacity(64));
        both.extend_from_slice(self.seed.as_ref());
        both.extend_from_slice(&self.public);
        put_string(&mut private, &both);
        put_string(&mut private, self.comment.as_bytes());
        let mut pad = 1u8;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad += 1;
        }
        let mut out = Zeroizing::new(MAGIC.to_vec());
        put_string(&mut out, b"none");
        put_string(&mut out, b"none");
        put_string(&mut out, b"");
        out.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut out, &self.public_blob());
        put_string(&mut out, &private);
        let encoded = Zeroizing::new(base64_encode(&out));
        let mut text = Zeroizing::new(String::from(BEGIN));
        text.push('\n');
        for line in encoded.as_bytes().chunks(70) {
            text.push_str(std::str::from_utf8(line).unwrap_or_default());
            text.push('\n');
        }
        text.push_str(END);
        text.push('\n');
        text
    }

    /// `string "ssh-ed25519" string pub` — what the agent lists and `authorized_keys` holds.
    pub fn public_blob(&self) -> Vec<u8> {
        public_blob(&self.public)
    }

    /// `ssh-ed25519 AAAA… comment`, as in a `.pub` file.
    pub fn public_line(&self) -> String {
        let line = format!("{ED25519} {}", base64_encode(&self.public_blob()));
        if self.comment.is_empty() {
            line
        } else {
            format!("{line} {}", self.comment)
        }
    }

    /// `SHA256:…` as `ssh-keygen -lf` prints it.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.public_blob());
        format!("SHA256:{}", base64_encode(&digest).trim_end_matches('='))
    }

    /// The signature of `data` in the SSH wire format: `string "ssh-ed25519" string sig(64)`.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = SigningKey::from_bytes(&self.seed).sign(data).to_bytes();
        let mut out = Vec::new();
        put_string(&mut out, ED25519.as_bytes());
        put_string(&mut out, &signature);
        out
    }
}

/// Why a private key was not taken. The app says what to do about each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Not an `openssh-key-v1` private key.
    Invalid,
    /// Protected by a passphrase: remove it first (`ssh-keygen -p -N "" -f key`).
    Encrypted,
    /// Not ed25519 (RSA, ECDSA): not taken in v0.9.
    Unsupported,
}

impl From<KeyError> for VaultError {
    fn from(error: KeyError) -> Self {
        match error {
            KeyError::Invalid => VaultError::InvalidSshKey,
            KeyError::Encrypted => VaultError::EncryptedSshKey,
            KeyError::Unsupported => VaultError::UnsupportedSshKey,
        }
    }
}

/// The public blob of an ed25519 key: `string "ssh-ed25519" string pub(32)`.
pub fn public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, ED25519.as_bytes());
    put_string(&mut out, public);
    out
}

/// The public blob from a `.pub` line (`ssh-ed25519 AAAA… comment`): what the agent lists.
pub fn blob_of_line(line: &str) -> Result<Vec<u8>> {
    let mut parts = line.split_whitespace();
    let _kind = parts.next().ok_or(VaultError::InvalidSshKey)?;
    base64_decode(parts.next().ok_or(VaultError::InvalidSshKey)?).ok_or(VaultError::InvalidSshKey)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> std::result::Result<u32, KeyError> {
        let (head, rest) = self.0.split_first_chunk::<4>().ok_or(KeyError::Invalid)?;
        self.0 = rest;
        Ok(u32::from_be_bytes(*head))
    }

    fn string(&mut self) -> std::result::Result<&'a [u8], KeyError> {
        let len = self.u32()? as usize;
        if len > self.0.len() {
            return Err(KeyError::Invalid);
        }
        let (value, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(value)
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 §4).
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64, padding optional; `None` for any other character.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for bytes in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base64_decode(&base64_encode(bytes)).unwrap(), bytes);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert!(base64_decode("not base64!").is_none());
    }
}
