//! KDBX keys and ciphers: the composite key (password, key file), its transformation
//! (Argon2d/id, AES-KDF), the outer cipher (AES-256-CBC, ChaCha20), KDBX 4's HMAC blocks and
//! KDBX 3.1's hashed blocks, and the inner stream that hides protected values.

use std::io::{Read, Write};

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, StreamCipher};
use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use super::header::{Cipher, Header, Inner, Kdf, StreamSpec};
use crate::entropy::Entropy;
use crate::error::{Result, VaultError};

/// What opens a KDBX file: its password, a key file, or both.
pub struct Key<'a> {
    pub password: Option<&'a [u8]>,
    pub key_file: Option<&'a [u8]>,
}

impl Key<'_> {
    /// SHA-256 of the parts' hashes, in order: KeePass's composite key.
    fn composite(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut hasher = Sha256::new();
        if let Some(password) = self.password {
            hasher.update(Sha256::digest(password));
        }
        if let Some(file) = self.key_file {
            hasher.update(key_file_key(file)?.as_ref());
        }
        if self.password.is_none() && self.key_file.is_none() {
            return Err(VaultError::WrongPassword);
        }
        Ok(Zeroizing::new(hasher.finalize().into()))
    }
}

/// A key file's 32 bytes: KeePass's XML (version 1.0 base64, 2.0 hex), 32 raw bytes, 64 hex
/// digits, or else the SHA-256 of the whole file.
fn key_file_key(file: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let text = std::str::from_utf8(file).ok().map(str::trim);
    if let Some(text) = text.filter(|t| t.contains("<KeyFile")) {
        let data = between(text, "<Data", "</Data>").ok_or(VaultError::InvalidKey)?;
        let data = data.split_once('>').map_or(data, |(_, rest)| rest);
        let bytes = if text.contains("<Version>2.0") {
            let digits: String = data.chars().filter(|c| !c.is_whitespace()).collect();
            hex(&digits).ok_or(VaultError::InvalidKey)?
        } else {
            crate::ssh::base64_decode(data.trim()).ok_or(VaultError::InvalidKey)?
        };
        return bytes.try_into().map(Zeroizing::new).map_err(|_| VaultError::InvalidKey);
    }
    if file.len() == 32 {
        return Ok(Zeroizing::new(file.try_into().unwrap()));
    }
    if let Some(bytes) = text.filter(|t| t.len() == 64).and_then(hex) {
        return Ok(Zeroizing::new(bytes.try_into().unwrap()));
    }
    Ok(Zeroizing::new(Sha256::digest(file).into()))
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = text.find(start)?;
    let to = text[from..].find(end)? + from;
    Some(&text[from + start.len()..to])
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

/// The composite key through the file's KDF.
fn transformed(kdf: &Kdf, key: &Key) -> Result<Zeroizing<[u8; 32]>> {
    let composite = key.composite()?;
    let mut out = Zeroizing::new([0u8; 32]);
    match kdf {
        Kdf::Aes { seed, rounds } => {
            let cipher = Aes256::new_from_slice(seed).map_err(|_| VaultError::Corrupted)?;
            let mut blocks = Zeroizing::new(*composite);
            for _ in 0..*rounds {
                for half in blocks.chunks_mut(16) {
                    cipher.encrypt_block(half.try_into().unwrap());
                }
            }
            out.copy_from_slice(&Sha256::digest(blocks.as_ref()));
        }
        Kdf::Argon2 { id, salt, memory, iterations, parallelism, version } => {
            let version = if *version == 0x10 { Version::V0x10 } else { Version::V0x13 };
            let params = Params::new(
                u32::try_from(memory / 1024).map_err(|_| VaultError::Corrupted)?,
                u32::try_from(*iterations).map_err(|_| VaultError::Corrupted)?,
                *parallelism,
                Some(32),
            )
            .map_err(|_| VaultError::Corrupted)?;
            let algorithm = if *id { Algorithm::Argon2id } else { Algorithm::Argon2d };
            Argon2::new(algorithm, version, params)
                .hash_password_into(composite.as_ref(), salt, out.as_mut())
                .map_err(|_| VaultError::Corrupted)?;
        }
    }
    Ok(out)
}

/// The payload of a KDBX file decrypted, its blocks checked and joined, gunzipped: KDBX 4's
/// inner header and XML, or KDBX 3.1's XML.
pub(super) fn decrypt(header: &Header, payload: &[u8], file: &[u8], key: &Key) -> Result<Zeroizing<Vec<u8>>> {
    let transformed = transformed(&header.kdf, key)?;
    let cipher_key = Zeroizing::new(<[u8; 32]>::from(
        Sha256::new().chain_update(&header.master_seed).chain_update(transformed.as_ref()).finalize(),
    ));
    let joined = if header.major >= 4 {
        let hmac_key = Zeroizing::new(<[u8; 64]>::from(
            Sha512::new()
                .chain_update(&header.master_seed)
                .chain_update(transformed.as_ref())
                .chain_update([1u8])
                .finalize(),
        ));
        // The header's hash, then its HMAC: a wrong key fails here, before anything is decrypted.
        let (hash, rest) = payload.split_at_checked(32).ok_or(VaultError::Corrupted)?;
        let (mac, mut blocks) = rest.split_at_checked(32).ok_or(VaultError::Corrupted)?;
        if hash != Sha256::digest(&file[..header.len]).as_slice() {
            return Err(VaultError::Corrupted);
        }
        if !block_mac(&hmac_key, u64::MAX, &[&file[..header.len]]).verify_slice(mac).is_ok() {
            return Err(VaultError::WrongPassword);
        }
        let mut joined = Zeroizing::new(Vec::with_capacity(blocks.len()));
        for index in 0u64.. {
            let (mac, rest) = blocks.split_at_checked(32).ok_or(VaultError::Corrupted)?;
            let (size, rest) = rest.split_at_checked(4).ok_or(VaultError::Corrupted)?;
            let len = u32::from_le_bytes(size.try_into().unwrap()) as usize;
            let (data, rest) = rest.split_at_checked(len).ok_or(VaultError::Corrupted)?;
            if block_mac(&hmac_key, index, &[&index.to_le_bytes(), size, data]).verify_slice(mac).is_err() {
                return Err(VaultError::Corrupted);
            }
            if len == 0 {
                break;
            }
            joined.extend_from_slice(data);
            blocks = rest;
        }
        outer(header.cipher, &cipher_key, &header.iv, &joined, false)?
    } else {
        // KDBX 3.1: a wrong key shows as bad padding or other first bytes.
        let plain = outer(header.cipher, &cipher_key, &header.iv, payload, false)
            .map_err(|_| VaultError::WrongPassword)?;
        let start = header.start_bytes.as_deref().ok_or(VaultError::Corrupted)?;
        if plain.get(..start.len()) != Some(start) {
            return Err(VaultError::WrongPassword);
        }
        let mut blocks = &plain[start.len()..];
        let mut joined = Zeroizing::new(Vec::with_capacity(blocks.len()));
        loop {
            let (_, rest) = blocks.split_at_checked(4).ok_or(VaultError::Corrupted)?;
            let (hash, rest) = rest.split_at_checked(32).ok_or(VaultError::Corrupted)?;
            let (size, rest) = rest.split_at_checked(4).ok_or(VaultError::Corrupted)?;
            let len = u32::from_le_bytes(size.try_into().unwrap()) as usize;
            let (data, rest) = rest.split_at_checked(len).ok_or(VaultError::Corrupted)?;
            if len == 0 {
                break;
            }
            if hash != Sha256::digest(data).as_slice() {
                return Err(VaultError::Corrupted);
            }
            joined.extend_from_slice(data);
            blocks = rest;
        }
        joined
    };
    if !header.compressed {
        return Ok(joined);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(joined.len() * 4));
    flate2::read::GzDecoder::new(&joined[..]).read_to_end(&mut out).map_err(|_| VaultError::Corrupted)?;
    Ok(out)
}

/// A KDBX 4.0 file: Argon2id (64 MiB, 3 passes, 2 lanes), ChaCha20, gzip, 1 MiB HMAC blocks.
pub(super) fn encrypt(
    stream_key: &[u8],
    binaries: &[(bool, Zeroizing<Vec<u8>>)],
    xml: &[u8],
    key: &Key,
    entropy: &mut dyn Entropy,
) -> Result<Vec<u8>> {
    let (mut master_seed, mut iv, mut salt) = ([0u8; 32], [0u8; 12], [0u8; 32]);
    entropy.fill(&mut master_seed);
    entropy.fill(&mut iv);
    entropy.fill(&mut salt);
    let (memory, iterations, parallelism) = (64 * 1024 * 1024, 3, 2);
    let header_bytes = Header::write(&master_seed, &iv, &salt, memory, iterations, parallelism);
    let kdf = Kdf::Argon2 { id: true, salt: salt.to_vec(), memory, iterations, parallelism, version: 0x13 };
    let transformed = transformed(&kdf, key)?;
    let cipher_key = Zeroizing::new(<[u8; 32]>::from(
        Sha256::new().chain_update(master_seed).chain_update(transformed.as_ref()).finalize(),
    ));
    let hmac_key = Zeroizing::new(<[u8; 64]>::from(
        Sha512::new()
            .chain_update(master_seed)
            .chain_update(transformed.as_ref())
            .chain_update([1u8])
            .finalize(),
    ));

    let mut plain = Inner::write(stream_key, binaries);
    plain.extend_from_slice(xml);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&plain).map_err(|_| VaultError::Corrupted)?;
    let packed = Zeroizing::new(gz.finish().map_err(|_| VaultError::Corrupted)?);
    let encrypted = outer(super::header::Cipher::ChaCha20, &cipher_key, &iv, &packed, true)?;

    let mut out = header_bytes.clone();
    out.extend_from_slice(&Sha256::digest(&header_bytes));
    out.extend_from_slice(&block_mac(&hmac_key, u64::MAX, &[&header_bytes]).finalize().into_bytes());
    let chunks: Vec<&[u8]> = encrypted.chunks(1024 * 1024).chain(std::iter::once(&[][..])).collect();
    for (index, data) in chunks.into_iter().enumerate() {
        let size = (data.len() as u32).to_le_bytes();
        let mac = block_mac(&hmac_key, index as u64, &[&(index as u64).to_le_bytes(), &size, data])
            .finalize()
            .into_bytes();
        out.extend_from_slice(&mac);
        out.extend_from_slice(&size);
        out.extend_from_slice(data);
    }
    Ok(out)
}

/// HMAC-SHA-256 under block `index`'s key, over `parts`.
fn block_mac(hmac_key: &[u8; 64], index: u64, parts: &[&[u8]]) -> Hmac<Sha256> {
    let key = Zeroizing::new(<[u8; 64]>::from(
        Sha512::new().chain_update(index.to_le_bytes()).chain_update(hmac_key).finalize(),
    ));
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref()).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    mac
}

/// The outer cipher one way or the other.
fn outer(
    cipher: Cipher,
    key: &[u8; 32],
    iv: &[u8],
    data: &[u8],
    encrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    match cipher {
        Cipher::Aes256 => {
            let iv: &[u8; 16] = iv.try_into().map_err(|_| VaultError::Corrupted)?;
            if encrypt {
                Ok(Zeroizing::new(
                    cbc::Encryptor::<Aes256>::new(key.into(), iv.into()).encrypt_padded_vec::<Pkcs7>(data),
                ))
            } else {
                cbc::Decryptor::<Aes256>::new(key.into(), iv.into())
                    .decrypt_padded_vec::<Pkcs7>(data)
                    .map(Zeroizing::new)
                    .map_err(|_| VaultError::WrongPassword)
            }
        }
        Cipher::ChaCha20 => {
            let iv: &[u8; 12] = iv.try_into().map_err(|_| VaultError::Corrupted)?;
            let mut out = Zeroizing::new(data.to_vec());
            chacha20::ChaCha20::new(key.into(), iv.into()).apply_keystream(&mut out);
            Ok(out)
        }
    }
}

/// The stream protected values are XORed with, in the order they appear in the XML.
pub(super) struct InnerStream(Box<dyn StreamCipher>);

impl InnerStream {
    pub fn new(spec: &StreamSpec) -> Result<Self> {
        match spec.id {
            // Salsa20 (KDBX 3.1): SHA-256 of the key, a fixed nonce.
            2 => {
                let key = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&spec.key[..])));
                let nonce: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
                let key_ref: &[u8; 32] = &key;
                Ok(InnerStream(Box::new(salsa20::Salsa20::new(key_ref.into(), (&nonce).into()))))
            }
            3 => Ok(Self::chacha(&spec.key)),
            _ => Err(VaultError::UnsupportedVersion(4)),
        }
    }

    /// ChaCha20 (KDBX 4): key and nonce from SHA-512 of the stream key.
    pub fn chacha(stream_key: &[u8]) -> Self {
        let hash = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(stream_key)));
        let key: &[u8; 32] = hash[..32].try_into().unwrap();
        let nonce: &[u8; 12] = hash[32..44].try_into().unwrap();
        InnerStream(Box::new(chacha20::ChaCha20::new(key.into(), nonce.into())))
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        self.0.apply_keystream(data);
    }
}
