//! SSH keys for the agent (ADR-0006): ed25519 keys made or imported in the `openssh-key-v1`
//! format `ssh-keygen` writes (unencrypted), their public line, and signatures in the SSH wire
//! format. RSA keys are imported only, for servers that take nothing else (ADR-0011). The
//! private key stays here: callers get the public line and signatures only.
//!
//! ```text
//! "openssh-key-v1\0" string cipher("none") string kdf("none") string kdfoptions("") uint32 1
//! string public-blob   string private-section:
//!     uint32 check uint32 check string "ssh-ed25519" string pub(32) string seed‖pub(64)
//!     string comment   padding 1, 2, 3… to a multiple of 8
//!   RSA: … string "ssh-rsa" mpint n mpint e mpint d mpint iqmp mpint p mpint q string comment …
//! ```

use crate::{Entropy, Result, VaultError};
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

pub const ED25519: &str = "ssh-ed25519";
pub const RSA: &str = "ssh-rsa";
/// SIGN_REQUEST flags for an RSA key (draft-miller-ssh-agent §4.5.1); with neither, ssh asks
/// for SHA-1 (`ssh-rsa`), which is refused.
pub const RSA_SHA2_256: u32 = 0x02;
pub const RSA_SHA2_512: u32 = 0x04;
/// The smallest RSA modulus taken (ADR-0011): 1024-bit keys are within reach of factoring.
pub const RSA_MIN_BITS: usize = 2048;
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
        let bytes = unarmor(text)?;
        let mut private = private_section(&bytes)?;
        if private.string()? != ED25519.as_bytes() {
            return Err(KeyError::Unsupported);
        }
        Self::read(&mut private)
    }

    /// The rest of the private section, after the key type.
    fn read(private: &mut Reader) -> std::result::Result<Self, KeyError> {
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
        let mut key = Zeroizing::new(Vec::new());
        put_string(&mut key, ED25519.as_bytes());
        put_string(&mut key, &self.public);
        let mut both = Zeroizing::new(Vec::with_capacity(64));
        both.extend_from_slice(self.seed.as_ref());
        both.extend_from_slice(&self.public);
        put_string(&mut key, &both);
        armor(entropy, &self.public_blob(), &key, &self.comment)
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
    /// Neither ed25519 nor RSA of 2048 bits or more (ECDSA, DSA, a short RSA key), or an RSA
    /// signature asked for with SHA-1.
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

/// An RSA key imported from `ssh-keygen`'s private form (ADR-0011); never made here. Signs
/// `rsa-sha2-256` / `rsa-sha2-512`, blinded with fresh randomness each time.
pub struct RsaKey {
    key: rsa::RsaPrivateKey,
    /// The components as read, for writing the key back; the secret ones zeroed on drop.
    n: Vec<u8>,
    e: Vec<u8>,
    /// d, iqmp, p, q.
    secret: [Zeroizing<Vec<u8>>; 4],
    pub comment: String,
}

impl RsaKey {
    /// The rest of the private section, after the key type.
    fn read(private: &mut Reader) -> std::result::Result<Self, KeyError> {
        let n = mpint(private.string()?);
        let e = mpint(private.string()?);
        let mut secret: [Zeroizing<Vec<u8>>; 4] = Default::default();
        for part in &mut secret {
            part.extend_from_slice(mpint(private.string()?));
        }
        if n.is_empty() || n.len() * 8 < RSA_MIN_BITS {
            return Err(KeyError::Unsupported);
        }
        let comment = String::from_utf8(private.string()?.to_vec()).map_err(|_| KeyError::Invalid)?;
        // Every secret number at the modulus's width: no size that depends on its value.
        let bits = (n.len() * 8).div_ceil(64) as u32 * 64;
        let uint = |bytes: &[u8]| rsa::BoxedUint::from_be_slice(bytes, bits).map_err(|_| KeyError::Invalid);
        let [d, _, p, q] = &secret;
        let key = rsa::RsaPrivateKey::from_components(
            rsa::BoxedUint::from_be_slice_vartime(n),
            rsa::BoxedUint::from_be_slice_vartime(e),
            uint(d)?,
            vec![uint(p)?, uint(q)?],
        )
        .map_err(|_| KeyError::Invalid)?;
        Ok(Self { key, n: n.to_vec(), e: e.to_vec(), secret, comment })
    }

    fn to_openssh(&self, entropy: &mut dyn Entropy) -> Zeroizing<String> {
        let mut key = Zeroizing::new(Vec::new());
        put_string(&mut key, RSA.as_bytes());
        put_mpint(&mut key, &self.n);
        put_mpint(&mut key, &self.e);
        for part in &self.secret {
            put_mpint(&mut key, part);
        }
        armor(entropy, &self.public_blob(), &key, &self.comment)
    }

    /// `string "ssh-rsa" mpint e mpint n`.
    pub fn public_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, RSA.as_bytes());
        put_mpint(&mut out, &self.e);
        put_mpint(&mut out, &self.n);
        out
    }

    /// `string "rsa-sha2-512" string sig` (or 256, as `flags` ask); SHA-1 is refused.
    fn sign(&self, data: &[u8], flags: u32) -> std::result::Result<Vec<u8>, KeyError> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        let (name, signature) = if flags & RSA_SHA2_512 != 0 {
            let signer = SigningKey::<sha2::Sha512>::new(self.key.clone());
            ("rsa-sha2-512", signer.try_sign_with_rng(&mut SystemRng, data).map(|s| s.to_vec()))
        } else if flags & RSA_SHA2_256 != 0 {
            let signer = SigningKey::<sha2::Sha256>::new(self.key.clone());
            ("rsa-sha2-256", signer.try_sign_with_rng(&mut SystemRng, data).map(|s| s.to_vec()))
        } else {
            return Err(KeyError::Unsupported);
        };
        let signature = signature.map_err(|_| KeyError::Invalid)?;
        let mut out = Vec::new();
        put_string(&mut out, name.as_bytes());
        put_string(&mut out, &signature);
        Ok(out)
    }
}

/// The blinding randomness for an RSA signature: the system's, as `SystemEntropy` draws it.
struct SystemRng;

impl rsa::rand_core::TryRng for SystemRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        crate::entropy::SystemEntropy.fill(dst);
        Ok(())
    }
}

impl rsa::rand_core::TryCryptoRng for SystemRng {}

/// Any SSH key the agent signs with.
pub enum PrivateKey {
    Ed25519(Ed25519Key),
    Rsa(Box<RsaKey>),
}

impl PrivateKey {
    /// The `-----BEGIN OPENSSH PRIVATE KEY-----` text, unencrypted: ed25519, or RSA of
    /// `RSA_MIN_BITS` or more. Errors as `Ed25519Key::from_openssh`.
    pub fn from_openssh(text: &str) -> std::result::Result<Self, KeyError> {
        let bytes = unarmor(text)?;
        let mut private = private_section(&bytes)?;
        match private.string()? {
            kind if kind == ED25519.as_bytes() => Ed25519Key::read(&mut private).map(Self::Ed25519),
            kind if kind == RSA.as_bytes() => RsaKey::read(&mut private).map(|key| Self::Rsa(Box::new(key))),
            _ => Err(KeyError::Unsupported),
        }
    }

    pub fn to_openssh(&self, entropy: &mut dyn Entropy) -> Zeroizing<String> {
        match self {
            Self::Ed25519(key) => key.to_openssh(entropy),
            Self::Rsa(key) => key.to_openssh(entropy),
        }
    }

    pub fn public_blob(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.public_blob(),
            Self::Rsa(key) => key.public_blob(),
        }
    }

    /// `ssh-rsa AAAA… comment`, as in a `.pub` file.
    pub fn public_line(&self) -> String {
        match self {
            Self::Ed25519(key) => key.public_line(),
            Self::Rsa(key) => {
                let line = format!("{RSA} {}", base64_encode(&key.public_blob()));
                if key.comment.is_empty() {
                    line
                } else {
                    format!("{line} {}", key.comment)
                }
            }
        }
    }

    /// `SHA256:…` as `ssh-keygen -lf` prints it.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.public_blob());
        format!("SHA256:{}", base64_encode(&digest).trim_end_matches('='))
    }

    /// The signature of `data` in the SSH wire format; `flags` from the agent's SIGN_REQUEST
    /// choose the RSA hash (ed25519 has one).
    pub fn sign(&self, data: &[u8], flags: u32) -> std::result::Result<Vec<u8>, KeyError> {
        match self {
            Self::Ed25519(key) => Ok(key.sign(data)),
            Self::Rsa(key) => key.sign(data, flags),
        }
    }
}

/// The bytes inside the `-----BEGIN OPENSSH PRIVATE KEY-----` armour; zeroed on drop.
fn unarmor(text: &str) -> std::result::Result<Zeroizing<Vec<u8>>, KeyError> {
    let body = Zeroizing::new(
        text.trim()
            .strip_prefix(BEGIN)
            .and_then(|rest| rest.trim_end().strip_suffix(END))
            .ok_or(KeyError::Invalid)?
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>(),
    );
    Ok(Zeroizing::new(base64_decode(&body).ok_or(KeyError::Invalid)?))
}

/// The private section of an unencrypted `openssh-key-v1` key, after its two check words.
fn private_section(bytes: &[u8]) -> std::result::Result<Reader<'_>, KeyError> {
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
    Ok(private)
}

/// `key` (its type and numbers) wrapped as `ssh-keygen` writes a private key: check words,
/// the comment, padding, the armour. Zeroed on drop.
fn armor(entropy: &mut dyn Entropy, public_blob: &[u8], key: &[u8], comment: &str) -> Zeroizing<String> {
    let mut check = [0u8; 4];
    entropy.fill(&mut check);
    let mut private = Zeroizing::new(Vec::new());
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    private.extend_from_slice(key);
    put_string(&mut private, comment.as_bytes());
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
    put_string(&mut out, public_blob);
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

/// An mpint's magnitude: without the zero byte SSH puts before a set top bit.
fn mpint(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0, rest @ ..] => rest,
        _ => bytes,
    }
}

/// A positive mpint: a zero byte first when the top bit is set.
fn put_mpint(out: &mut Vec<u8>, magnitude: &[u8]) {
    if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
        out.extend_from_slice(&(magnitude.len() as u32 + 1).to_be_bytes());
        out.push(0);
        out.extend_from_slice(magnitude);
    } else {
        put_string(out, magnitude);
    }
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
