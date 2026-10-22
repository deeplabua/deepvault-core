//! The `.dvault` file, version 1 (PRD 04, «Формат файла»). All integers little-endian.
//!
//! ```text
//! magic        "DVLT"                                   4 B
//! version      u16 = 1                                  2 B
//! header_len   u32 (≤ 64 KiB)                           4 B
//! header       CBOR Header                              header_len B
//! header_mac   HMAC-SHA256(K_header_mac, magic … header)    32 B
//! block_count  u32                                      4 B
//! block × n    entry_id 16 B ‖ nonce 24 B ‖ ct_len u32 ‖ ciphertext+tag (ct_len B)
//! file_mac     HMAC-SHA256(K_file_mac, magic … last block)  32 B
//! ```
//!
//! The header is in the clear (KDF parameters, salt, wrapped VK — nothing secret) but
//! authenticated by `header_mac`; `file_mac` covers the whole file, so dropping, reordering
//! or replaying a block is detected. Blocks are bound to the vault and their entry id by AAD,
//! not to the header, so a password change rewrites one slot and no entry.
//!
//! The format is frozen once its test vectors are committed (core/tests/vectors): any change
//! is a new version, and this one stays readable.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::aead::{NONCE_LEN, TAG_LEN};
use crate::error::{Result, VaultError};
use crate::kdf::SALT_LEN;
use crate::keys::{self, Subkeys, MAC_LEN, VAULT_ID_LEN};

pub const MAGIC: &[u8; 4] = b"DVLT";
pub const VERSION: u16 = 1;
pub const MAX_HEADER_LEN: usize = 64 * 1024;
const PREFIX_LEN: usize = 4 + 2 + 4;
pub(crate) const ENTRY_ID_LEN: usize = 16;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    #[serde(with = "cbor_bytes")]
    pub vault_id: [u8; VAULT_ID_LEN],
    pub created_at: u64,
    pub kdf: KdfHeader,
    pub slots: Vec<SlotHeader>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KdfHeader {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    #[serde(with = "cbor_bytes")]
    pub salt: [u8; SALT_LEN],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SlotHeader {
    pub kind: String,
    #[serde(with = "cbor_bytes")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "cbor_bytes")]
    pub wrapped_vk: Vec<u8>,
}

pub(crate) struct Block {
    pub entry_id: [u8; ENTRY_ID_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// A file cut into its parts, before any key is known. Nothing in it is trusted yet.
pub(crate) struct RawFile<'a> {
    pub header: Header,
    /// What `header_mac` covers.
    pub header_region: &'a [u8],
    pub header_mac: &'a [u8],
    /// What `file_mac` covers.
    pub file_region: &'a [u8],
    pub file_mac: &'a [u8],
    pub blocks: Vec<Block>,
}

/// Checks the structure only: lengths, the header's CBOR. Cheap, so a damaged file is
/// refused before the KDF runs.
pub(crate) fn parse(file: &[u8]) -> Result<RawFile<'_>> {
    let mut reader = Reader { data: file, pos: 0 };
    if reader.take(4)? != MAGIC {
        return Err(VaultError::Corrupted);
    }
    let version = reader.u16()?;
    if version != VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let header_len = reader.u32()? as usize;
    if header_len > MAX_HEADER_LEN {
        return Err(VaultError::Corrupted);
    }
    let header_bytes = reader.take(header_len)?;
    let header: Header = from_cbor(header_bytes).ok_or(VaultError::Corrupted)?;
    let header_region = &file[..reader.pos];
    let header_mac = reader.take(MAC_LEN)?;

    let count = reader.u32()? as usize;
    let smallest_block = ENTRY_ID_LEN + NONCE_LEN + 4 + TAG_LEN;
    let mut blocks = Vec::with_capacity(count.min(reader.remaining() / smallest_block));
    for _ in 0..count {
        let entry_id = reader.array()?;
        let nonce = reader.array()?;
        let len = reader.u32()? as usize;
        if len < TAG_LEN {
            return Err(VaultError::Corrupted);
        }
        blocks.push(Block { entry_id, nonce, ciphertext: reader.take(len)?.to_vec() });
    }
    let file_region = &file[..reader.pos];
    let file_mac = reader.take(MAC_LEN)?;
    if reader.remaining() != 0 {
        return Err(VaultError::Corrupted);
    }
    Ok(RawFile { header, header_region, header_mac, file_region, file_mac, blocks })
}

pub(crate) fn write(header: &Header, blocks: &[Block], keys: &Subkeys) -> Vec<u8> {
    let header_bytes = to_cbor(header);
    assert!(header_bytes.len() <= MAX_HEADER_LEN, "header over 64 KiB");
    let body: usize = blocks.iter().map(|b| ENTRY_ID_LEN + NONCE_LEN + 4 + b.ciphertext.len()).sum();
    let mut out = Vec::with_capacity(PREFIX_LEN + header_bytes.len() + MAC_LEN + 4 + body + MAC_LEN);

    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_bytes);
    let header_mac = keys::mac(&keys.header_mac, &out);
    out.extend_from_slice(&header_mac);

    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    for block in blocks {
        out.extend_from_slice(&block.entry_id);
        out.extend_from_slice(&block.nonce);
        out.extend_from_slice(&(block.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&block.ciphertext);
    }
    let file_mac = keys::mac(&keys.file_mac, &out);
    out.extend_from_slice(&file_mac);
    out
}

pub(crate) fn to_cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR into a Vec does not fail");
    out
}

/// Exactly one CBOR item and nothing after it.
pub(crate) fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let mut rest = bytes;
    let value = ciborium::from_reader(&mut rest).ok()?;
    rest.is_empty().then_some(value)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.remaining() {
            return Err(VaultError::Corrupted);
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("take returns N bytes"))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
}

/// Byte strings as CBOR byte strings (major type 2), not as arrays of integers — serde's
/// default for `Vec<u8>` and `[u8; N]`.
pub(crate) mod cbor_bytes {
    use serde::de::{self, Deserializer, Visitor};
    use serde::Serializer;
    use std::fmt;

    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value.as_ref())
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: TryFrom<Vec<u8>>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let bytes = deserializer.deserialize_byte_buf(BytesVisitor)?;
        let len = bytes.len();
        T::try_from(bytes)
            .map_err(|_| de::Error::invalid_length(len, &"a byte string of the expected length"))
    }

    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
            Ok(v)
        }
    }
}
