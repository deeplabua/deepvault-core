//! The outer header of a KDBX file (3.1 and 4.x) and the inner one of 4.x, read and written.
//! Nothing secret here but the inner stream's key and the inner binaries (zeroed on drop).

use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub(super) const SIGNATURE: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];
pub(super) const AES256: [u8; 16] = hex16("31c1f2e6bf714350be5805216afc5aff");
pub(super) const CHACHA20: [u8; 16] = hex16("d6038a2b8b6f4cb5a524339a31dbb59a");
pub(super) const AES_KDF: [u8; 16] = hex16("c9d9f39a628a4460bf740d08c18a4fea");
pub(super) const ARGON2D: [u8; 16] = hex16("ef636ddf8c29444b91f7a9a403e30a0c");
pub(super) const ARGON2ID: [u8; 16] = hex16("9e298b1956db4773b23dfc3ec6f0a1e6");

const fn hex16(text: &str) -> [u8; 16] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Cipher {
    Aes256,
    ChaCha20,
}

#[derive(Clone)]
pub(super) enum Kdf {
    Aes { seed: Vec<u8>, rounds: u64 },
    Argon2 { id: bool, salt: Vec<u8>, memory: u64, iterations: u64, parallelism: u32, version: u32 },
}

/// Which stream hides protected values, and its key.
#[derive(Clone)]
pub(super) struct StreamSpec {
    pub id: u32,
    pub key: Zeroizing<Vec<u8>>,
}

pub(super) struct Header {
    pub major: u16,
    pub cipher: Cipher,
    pub compressed: bool,
    pub master_seed: Vec<u8>,
    pub iv: Vec<u8>,
    pub kdf: Kdf,
    /// KDBX 3.1: the first bytes of the decrypted payload, and the inner stream.
    pub start_bytes: Option<Vec<u8>>,
    pub inner_stream: Option<StreamSpec>,
    /// The header's bytes, for its hash and HMAC (4.x).
    pub len: usize,
}

impl Header {
    /// The header and what follows it.
    pub fn parse(file: &[u8]) -> Result<(Self, &[u8])> {
        if file.len() < 12 || file[..8] != SIGNATURE {
            return Err(VaultError::InvalidImport);
        }
        let minor = u16::from_le_bytes([file[8], file[9]]);
        let major = u16::from_le_bytes([file[10], file[11]]);
        let _ = minor;
        if major != 3 && major != 4 {
            return Err(VaultError::UnsupportedVersion(major));
        }
        let mut at = 12;
        let (mut cipher, mut compressed, mut master_seed, mut iv) = (None, false, None, None);
        let (mut kdf, mut seed, mut rounds) = (None, None, None);
        let (mut stream_key, mut start_bytes, mut stream_id) = (None, None, None);
        loop {
            let id = *file.get(at).ok_or(VaultError::Corrupted)?;
            let (size, skip) = if major >= 4 {
                (u32::from_le_bytes(take(file, at + 1, 4)?.try_into().unwrap()) as usize, 5)
            } else {
                (u16::from_le_bytes(take(file, at + 1, 2)?.try_into().unwrap()) as usize, 3)
            };
            let data = take(file, at + skip, size)?;
            at += skip + size;
            match id {
                0 => break,
                2 => {
                    cipher = Some(match data {
                        d if d == AES256 => Cipher::Aes256,
                        d if d == CHACHA20 => Cipher::ChaCha20,
                        // Twofish and anything else.
                        _ => return Err(VaultError::UnsupportedVersion(major)),
                    })
                }
                3 => compressed = data.first().copied().unwrap_or(0) == 1,
                4 => master_seed = Some(data.to_vec()),
                5 => seed = Some(data.to_vec()),
                6 => rounds = Some(u64::from_le_bytes(data.try_into().map_err(|_| VaultError::Corrupted)?)),
                7 => iv = Some(data.to_vec()),
                8 => stream_key = Some(Zeroizing::new(data.to_vec())),
                9 => start_bytes = Some(data.to_vec()),
                10 => {
                    stream_id = Some(u32::from_le_bytes(data.try_into().map_err(|_| VaultError::Corrupted)?))
                }
                11 => kdf = Some(kdf_of(&Variants::parse(data)?)?),
                _ => {}
            }
        }
        let kdf = match (major, kdf) {
            (4, Some(kdf)) => kdf,
            (3, _) => Kdf::Aes {
                seed: seed.ok_or(VaultError::Corrupted)?,
                rounds: rounds.ok_or(VaultError::Corrupted)?,
            },
            _ => return Err(VaultError::Corrupted),
        };
        let inner_stream = match (stream_id, stream_key) {
            (Some(id), Some(key)) => Some(StreamSpec { id, key }),
            _ => None,
        };
        let header = Header {
            major,
            cipher: cipher.ok_or(VaultError::Corrupted)?,
            compressed,
            master_seed: master_seed.ok_or(VaultError::Corrupted)?,
            iv: iv.ok_or(VaultError::Corrupted)?,
            kdf,
            start_bytes,
            inner_stream,
            len: at,
        };
        Ok((header, &file[at..]))
    }

    /// A KDBX 4.0 header: ChaCha20, gzip, Argon2id.
    pub fn write(
        master_seed: &[u8],
        iv: &[u8],
        salt: &[u8],
        memory: u64,
        iterations: u64,
        parallelism: u32,
    ) -> Vec<u8> {
        let mut out = SIGNATURE.to_vec();
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        let mut field = |id: u8, data: &[u8]| {
            out.push(id);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        };
        field(2, &CHACHA20);
        field(3, &1u32.to_le_bytes());
        field(4, master_seed);
        field(7, iv);
        let mut kdf = Variants::default();
        kdf.push("$UUID", 0x42, ARGON2ID.to_vec());
        kdf.push("S", 0x42, salt.to_vec());
        kdf.push("P", 0x04, parallelism.to_le_bytes().to_vec());
        kdf.push("M", 0x05, memory.to_le_bytes().to_vec());
        kdf.push("I", 0x05, iterations.to_le_bytes().to_vec());
        kdf.push("V", 0x04, 0x13u32.to_le_bytes().to_vec());
        field(11, &kdf.bytes());
        field(0, b"\r\n\r\n");
        out
    }
}

/// The inner header of KDBX 4.x: the protected values' stream and the files.
pub(super) struct Inner {
    pub stream: StreamSpec,
    pub binaries: Vec<Zeroizing<Vec<u8>>>,
    /// Where the XML starts.
    pub end: usize,
}

impl Inner {
    pub fn parse(plain: &[u8]) -> Result<Self> {
        let (mut at, mut id, mut key, mut binaries) = (0, None, None, Vec::new());
        loop {
            let kind = *plain.get(at).ok_or(VaultError::Corrupted)?;
            let size = u32::from_le_bytes(take(plain, at + 1, 4)?.try_into().unwrap()) as usize;
            let data = take(plain, at + 5, size)?;
            at += 5 + size;
            match kind {
                0 => break,
                1 => id = Some(u32::from_le_bytes(data.try_into().map_err(|_| VaultError::Corrupted)?)),
                2 => key = Some(Zeroizing::new(data.to_vec())),
                // A flags byte, then the file.
                3 => binaries.push(Zeroizing::new(data.get(1..).unwrap_or_default().to_vec())),
                _ => {}
            }
        }
        Ok(Inner {
            stream: StreamSpec {
                id: id.ok_or(VaultError::Corrupted)?,
                key: key.ok_or(VaultError::Corrupted)?,
            },
            binaries,
            end: at,
        })
    }

    pub fn write(stream_key: &[u8], binaries: &[(bool, Zeroizing<Vec<u8>>)]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        let field = |out: &mut Vec<u8>, kind: u8, parts: &[&[u8]]| {
            out.push(kind);
            out.extend_from_slice(&(parts.iter().map(|p| p.len()).sum::<usize>() as u32).to_le_bytes());
            for part in parts {
                out.extend_from_slice(part);
            }
        };
        field(&mut out, 1, &[&3u32.to_le_bytes()]);
        field(&mut out, 2, &[stream_key]);
        for (protected, content) in binaries {
            field(&mut out, 3, &[&[u8::from(*protected)], content]);
        }
        field(&mut out, 0, &[]);
        out
    }
}

fn take(bytes: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    bytes.get(at..at.checked_add(len).ok_or(VaultError::Corrupted)?).ok_or(VaultError::Corrupted)
}

/// KDBX 4's VariantDictionary: typed values by name (the KDF's parameters).
#[derive(Default)]
struct Variants(Vec<(String, u8, Vec<u8>)>);

impl Variants {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut items = Vec::new();
        let mut at = 2; // version 0x0100
        loop {
            let kind = *data.get(at).ok_or(VaultError::Corrupted)?;
            if kind == 0 {
                break;
            }
            let name_len = u32::from_le_bytes(take(data, at + 1, 4)?.try_into().unwrap()) as usize;
            let name = String::from_utf8_lossy(take(data, at + 5, name_len)?).into_owned();
            let value_at = at + 5 + name_len;
            let value_len = u32::from_le_bytes(take(data, value_at, 4)?.try_into().unwrap()) as usize;
            items.push((name, kind, take(data, value_at + 4, value_len)?.to_vec()));
            at = value_at + 4 + value_len;
        }
        Ok(Variants(items))
    }

    fn get(&self, name: &str) -> Option<&[u8]> {
        self.0.iter().find(|(n, _, _)| n == name).map(|(_, _, v)| &v[..])
    }

    fn push(&mut self, name: &str, kind: u8, value: Vec<u8>) {
        self.0.push((name.into(), kind, value));
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![0x00, 0x01];
        for (name, kind, value) in &self.0 {
            out.push(*kind);
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        }
        out.push(0);
        out
    }
}

fn kdf_of(variants: &Variants) -> Result<Kdf> {
    let uuid = variants.get("$UUID").ok_or(VaultError::Corrupted)?;
    let u64_of = |name: &str| -> Result<u64> {
        let value = variants.get(name).ok_or(VaultError::Corrupted)?;
        Ok(u64::from_le_bytes(value.try_into().map_err(|_| VaultError::Corrupted)?))
    };
    let u32_of = |name: &str| -> Result<u32> {
        let value = variants.get(name).ok_or(VaultError::Corrupted)?;
        Ok(u32::from_le_bytes(value.try_into().map_err(|_| VaultError::Corrupted)?))
    };
    if uuid == AES_KDF {
        return Ok(Kdf::Aes {
            seed: variants.get("S").ok_or(VaultError::Corrupted)?.to_vec(),
            rounds: u64_of("R")?,
        });
    }
    if uuid == ARGON2D || uuid == ARGON2ID {
        return Ok(Kdf::Argon2 {
            id: uuid == ARGON2ID,
            salt: variants.get("S").ok_or(VaultError::Corrupted)?.to_vec(),
            memory: u64_of("M")?,
            iterations: u64_of("I")?,
            parallelism: u32_of("P")?,
            version: u32_of("V").unwrap_or(0x13),
        });
    }
    Err(VaultError::UnsupportedVersion(4))
}
