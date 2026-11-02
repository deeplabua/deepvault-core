//! A file attached to an entry, kept outside the vault file (ADR-0014): `files/<id>` in the
//! vault package, sealed in chunks under a key of its own. All header integers little-endian.
//!
//! ```text
//! magic         "DVLF"                                    4 B
//! version       u16 = 1                                   2 B
//! file_id       16 B
//! chunk_size    u32 (1 MiB)                               4 B
//! nonce_prefix  19 B, random
//! chunk × n     XChaCha20-Poly1305(file key, nonce, chunk, AAD)   ≤ chunk_size + 16 B each
//! ```
//!
//! The STREAM construction (Hoang–Reyhanitabar–Rogaway–Vizár, as RustCrypto's `aead-stream`)
//! over the core's XChaCha20-Poly1305: chunk `i` is sealed with the nonce
//! `nonce_prefix ‖ i (u32 big-endian) ‖ last (1 byte: 1 for the last chunk, 0 before)`. The
//! counter catches reordered or repeated chunks, the flag a file cut at a chunk boundary.
//! Every chunk but the last holds exactly `chunk_size` bytes; the last holds 1 to `chunk_size`
//! (none only for an empty file). AAD binds the chunks to the file and the vault it was made
//! for: `"DVLT" ‖ u16le(2) ‖ "file" ‖ 0x00 ‖ vault_id ‖ file_id` — fixed at 2, whatever version
//! the vault file is later, so the file never has to be sealed again.
//!
//! The file's key is 32 random bytes kept only in the entry's `file` field (`FileRef`), under
//! the vault key. So a file is copied to another vault as it is, and a file whose entry was
//! deleted for good has no key anywhere. `FileRef::sha256` (of the content) says the file is
//! the one the entry was saved with.
//!
//! Memory does not grow with the file: `FileWriter` and `FileReader` take and give pieces, and
//! hold at most one chunk of content, in a zeroed-on-drop buffer.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, NONCE_LEN, TAG_LEN};
use crate::entropy::Entropy;
use crate::error::{Result, VaultError};
use crate::format::{self, cbor_bytes};
use crate::keys::{self, VAULT_ID_LEN};
use crate::secret::{Key, SecretBytes};

pub const FILE_MAGIC: &[u8; 4] = b"DVLF";
pub const FILE_VERSION: u16 = 1;
pub const FILE_ID_LEN: usize = 16;
/// Content per chunk as DeepVault writes it.
pub const CHUNK_SIZE: usize = 1024 * 1024;
pub const NONCE_PREFIX_LEN: usize = 19;
pub const FILE_HEADER_LEN: usize = 4 + 2 + FILE_ID_LEN + 4 + NONCE_PREFIX_LEN;
/// The largest file an entry takes (ADR-0014: 2 GB).
pub const FILE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// The format version the AAD of a file's chunks says, for good (see the module comment).
const FILE_AAD_VERSION: u16 = 2;
/// What a reader takes from a header it has not written: no chunk too small to be one, none so
/// large it would hold a whole file in memory.
const CHUNK_SIZE_RANGE: std::ops::RangeInclusive<usize> = 16..=16 * 1024 * 1024;

/// What an entry's `file` field holds (CBOR): which file, for which vault, its name, size,
/// key, SHA-256 and when it was added. No `Debug`: it holds the file's key.
pub struct FileRef {
    pub id: [u8; FILE_ID_LEN],
    /// The vault the file was sealed for (its AAD); a copy in another vault keeps it.
    pub vault: [u8; VAULT_ID_LEN],
    pub name: String,
    pub size: u64,
    key: Key,
    pub sha256: [u8; 32],
    pub created: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRef {
    #[serde(with = "cbor_bytes")]
    id: [u8; FILE_ID_LEN],
    #[serde(with = "cbor_bytes")]
    vault: [u8; VAULT_ID_LEN],
    name: String,
    size: u64,
    #[serde(with = "cbor_bytes")]
    key: Vec<u8>,
    #[serde(with = "cbor_bytes")]
    sha256: [u8; 32],
    created: u64,
}

impl Drop for RawRef {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl FileRef {
    /// The field value: CBOR, in a buffer zeroed on drop (it holds the key).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let raw = RawRef {
            id: self.id,
            vault: self.vault,
            name: self.name.clone(),
            size: self.size,
            key: self.key.expose().to_vec(),
            sha256: self.sha256,
            created: self.created,
        };
        Zeroizing::new(format::to_cbor(&raw))
    }

    /// `None` when `value` is not a `file` field's CBOR.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let raw: RawRef = format::from_cbor(value)?;
        let key = Key::from_slice(&raw.key)?;
        Some(Self {
            id: raw.id,
            vault: raw.vault,
            name: raw.name.clone(),
            size: raw.size,
            key,
            sha256: raw.sha256,
            created: raw.created,
        })
    }

    /// The same file under another name (the user renamed it): same id, key and content.
    pub fn renamed(&self, name: &str) -> Self {
        Self {
            id: self.id,
            vault: self.vault,
            name: name.replace('\0', ""),
            size: self.size,
            key: Key::from_slice(self.key.expose()).expect("32 bytes"),
            sha256: self.sha256,
            created: self.created,
        }
    }

    /// `files/<id>`: the id as 32 lowercase hex digits.
    pub fn file_name(&self) -> String {
        hex(&self.id)
    }

    /// A reader of the file's bytes, piece by piece.
    pub fn reader(&self) -> FileReader {
        FileReader::new(self)
    }

    /// The whole content of a file held in memory (tests, small files). `Corrupted` unless it
    /// is exactly the file this ref describes.
    pub fn open(&self, file: &[u8]) -> Result<SecretBytes> {
        let mut reader = self.reader();
        let mut content = Zeroizing::new(Vec::with_capacity(self.size.min(FILE_MAX_BYTES) as usize));
        content.extend_from_slice(reader.update(file)?.expose());
        content.extend_from_slice(reader.finish()?.expose());
        Ok(SecretBytes::new(std::mem::take(&mut *content)))
    }
}

/// `"DVLT" ‖ u16le(2) ‖ "file" ‖ 0x00 ‖ vault_id ‖ file_id`.
fn file_aad(vault: &[u8; VAULT_ID_LEN], id: &[u8; FILE_ID_LEN]) -> Vec<u8> {
    keys::aad_for(FILE_AAD_VERSION, "file", vault, id)
}

fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u32, last: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(last);
    nonce
}

/// Seals a new file piece by piece: `header()` first, then what each `update` returns, then
/// what `finish` returns, written in that order to `files/<id>`.
pub struct FileWriter {
    id: [u8; FILE_ID_LEN],
    vault: [u8; VAULT_ID_LEN],
    name: String,
    created: u64,
    key: Key,
    prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size: usize,
    aad: Vec<u8>,
    /// Content not sealed yet: at most one chunk, kept until it is known whether it is the last.
    pending: Zeroizing<Vec<u8>>,
    counter: u32,
    size: u64,
    sha256: Sha256,
}

impl FileWriter {
    /// Randomness: file id (16), key (32), nonce prefix (19).
    pub(crate) fn new(
        entropy: &mut dyn Entropy,
        vault: [u8; VAULT_ID_LEN],
        name: &str,
        chunk_size: usize,
    ) -> Self {
        assert!(CHUNK_SIZE_RANGE.contains(&chunk_size), "chunk size out of range");
        let mut id = [0; FILE_ID_LEN];
        while id == [0; FILE_ID_LEN] {
            entropy.fill(&mut id);
        }
        let mut key = Key::zeroed();
        entropy.fill(key.expose_mut());
        let mut prefix = [0; NONCE_PREFIX_LEN];
        entropy.fill(&mut prefix);
        Self {
            id,
            vault,
            name: name.replace('\0', ""),
            created: entropy.now(),
            key,
            prefix,
            chunk_size,
            aad: file_aad(&vault, &id),
            pending: Zeroizing::new(Vec::with_capacity(chunk_size)),
            counter: 0,
            size: 0,
            sha256: Sha256::new(),
        }
    }

    /// `new` with scripted randomness and chunks of any size in range, for test vectors.
    #[cfg(feature = "testing")]
    pub fn new_with(
        entropy: &mut dyn Entropy,
        vault: [u8; VAULT_ID_LEN],
        name: &str,
        chunk_size: usize,
    ) -> Self {
        Self::new(entropy, vault, name, chunk_size)
    }

    pub fn id(&self) -> [u8; FILE_ID_LEN] {
        self.id
    }

    /// The first `FILE_HEADER_LEN` bytes of the file.
    pub fn header(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FILE_HEADER_LEN);
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(&FILE_VERSION.to_le_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&(self.chunk_size as u32).to_le_bytes());
        out.extend_from_slice(&self.prefix);
        out
    }

    /// Takes the next piece of content; returns the chunks it completed (possibly none).
    /// `FileTooLarge` past `FILE_MAX_BYTES`.
    pub fn update(&mut self, mut data: &[u8]) -> Result<Vec<u8>> {
        if self.size + data.len() as u64 > FILE_MAX_BYTES {
            return Err(VaultError::FileTooLarge);
        }
        self.size += data.len() as u64;
        self.sha256.update(data);
        let mut out = Vec::new();
        while !data.is_empty() {
            if self.pending.len() == self.chunk_size {
                // More content follows: the pending chunk is not the last.
                out.extend(self.seal(false)?);
            }
            let take = (self.chunk_size - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(out)
    }

    /// The last chunk, and the ref the entry keeps.
    pub fn finish(mut self) -> Result<(Vec<u8>, FileRef)> {
        let last = self.seal(true)?;
        let sha256: [u8; 32] = std::mem::take(&mut self.sha256).finalize().into();
        let file = FileRef {
            id: self.id,
            vault: self.vault,
            name: std::mem::take(&mut self.name),
            size: self.size,
            key: Key::from_slice(self.key.expose()).expect("32 bytes"),
            sha256,
            created: self.created,
        };
        Ok((last, file))
    }

    fn seal(&mut self, last: bool) -> Result<Vec<u8>> {
        let nonce = chunk_nonce(&self.prefix, self.counter, last);
        let sealed = aead::seal(&self.key, &nonce, &self.pending, &self.aad);
        self.pending.zeroize();
        self.pending.clear();
        self.counter = self.counter.checked_add(1).ok_or(VaultError::FileTooLarge)?;
        Ok(sealed)
    }
}

/// Opens a file piece by piece: `update` with the file's bytes in order (any sizes), then
/// `finish`. Content comes out as soon as a chunk is known not to be the last; `finish` checks
/// the last chunk, the size and the SHA-256. Until `finish` returns `Ok`, what came out may be
/// a file cut short or changed: the caller removes what it wrote when anything fails.
pub struct FileReader {
    id: [u8; FILE_ID_LEN],
    key: Key,
    aad: Vec<u8>,
    expected_size: u64,
    expected_sha256: [u8; 32],
    header: Option<([u8; NONCE_PREFIX_LEN], usize)>,
    /// Bytes not opened yet: the header, then at most one sealed chunk and a piece of the next.
    buffered: Vec<u8>,
    counter: u32,
    size: u64,
    sha256: Sha256,
}

impl FileReader {
    fn new(file: &FileRef) -> Self {
        Self {
            id: file.id,
            key: Key::from_slice(file.key.expose()).expect("32 bytes"),
            aad: file_aad(&file.vault, &file.id),
            expected_size: file.size,
            expected_sha256: file.sha256,
            header: None,
            buffered: Vec::new(),
            counter: 0,
            size: 0,
            sha256: Sha256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<SecretBytes> {
        self.buffered.extend_from_slice(data);
        let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        if self.header.is_none() {
            if self.buffered.len() < FILE_HEADER_LEN {
                return Ok(SecretBytes::new(Vec::new()));
            }
            self.header = Some(self.parse_header()?);
            self.buffered.drain(..FILE_HEADER_LEN);
        }
        let (_, chunk_size) = self.header.expect("parsed");
        let sealed_len = chunk_size + TAG_LEN;
        // A chunk is opened only once a byte after it is here: then it is not the last.
        let ready = (self.buffered.len().saturating_sub(1)) / sealed_len;
        // Reserved up front: a growing buffer would leave copies of the content in freed memory.
        out.reserve_exact(ready * chunk_size);
        let mut start = 0;
        while self.buffered.len() - start > sealed_len {
            let chunk = self.open_chunk(start, sealed_len, false)?;
            out.extend_from_slice(chunk.expose());
            start += sealed_len;
        }
        self.buffered.drain(..start);
        Ok(SecretBytes::new(std::mem::take(&mut *out)))
    }

    /// The content of the last chunk. `Corrupted` when the file is cut short, changed, longer
    /// than it was or not the one the entry was saved with.
    pub fn finish(mut self) -> Result<SecretBytes> {
        let Some((_, chunk_size)) = self.header else { return Err(VaultError::Corrupted) };
        let len = self.buffered.len();
        if len < TAG_LEN || len > chunk_size + TAG_LEN {
            return Err(VaultError::Corrupted);
        }
        let last = self.open_chunk(0, len, true)?;
        // Only an empty file has an empty last chunk.
        if last.expose().is_empty() && self.counter > 1 {
            return Err(VaultError::Corrupted);
        }
        let sha256: [u8; 32] = std::mem::take(&mut self.sha256).finalize().into();
        if self.size != self.expected_size || sha256 != self.expected_sha256 {
            return Err(VaultError::Corrupted);
        }
        Ok(last)
    }

    fn parse_header(&self) -> Result<([u8; NONCE_PREFIX_LEN], usize)> {
        let header = &self.buffered[..FILE_HEADER_LEN];
        let version = u16::from_le_bytes([header[4], header[5]]);
        if &header[..4] != FILE_MAGIC {
            return Err(VaultError::Corrupted);
        }
        if version != FILE_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        if header[6..6 + FILE_ID_LEN] != self.id {
            return Err(VaultError::Corrupted);
        }
        let at = 6 + FILE_ID_LEN;
        let chunk_size = u32::from_le_bytes(header[at..at + 4].try_into().expect("4 bytes")) as usize;
        if !CHUNK_SIZE_RANGE.contains(&chunk_size) {
            return Err(VaultError::Corrupted);
        }
        let prefix = header[at + 4..FILE_HEADER_LEN].try_into().expect("19 bytes");
        Ok((prefix, chunk_size))
    }

    fn open_chunk(&mut self, start: usize, len: usize, last: bool) -> Result<SecretBytes> {
        let (prefix, _) = self.header.expect("parsed");
        let nonce = chunk_nonce(&prefix, self.counter, last);
        let sealed = &self.buffered[start..start + len];
        let content = aead::open(&self.key, &nonce, sealed, &self.aad).ok_or(VaultError::Corrupted)?;
        self.counter = self.counter.checked_add(1).ok_or(VaultError::Corrupted)?;
        self.size += content.expose().len() as u64;
        if self.size > self.expected_size {
            return Err(VaultError::Corrupted);
        }
        self.sha256.update(content.expose());
        Ok(content)
    }
}

/// The size of the file `FileWriter` makes for `size` bytes of content in chunks of
/// `chunk_size`.
pub fn sealed_size(size: u64, chunk_size: usize) -> u64 {
    let chunks = size.div_ceil(chunk_size as u64).max(1);
    FILE_HEADER_LEN as u64 + size + chunks * TAG_LEN as u64
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A file id from its 32 hex digits (a name in `files/`).
pub fn parse_file_id(text: &str) -> Option<[u8; FILE_ID_LEN]> {
    if text.len() != FILE_ID_LEN * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut id = [0; FILE_ID_LEN];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SystemEntropy;

    fn seal(content: &[u8], chunk: usize, pieces: usize) -> (Vec<u8>, FileRef) {
        let mut writer = FileWriter::new(&mut SystemEntropy, [7; VAULT_ID_LEN], "scan.pdf", chunk);
        let mut out = writer.header();
        for piece in content.chunks(pieces.max(1)) {
            out.extend(writer.update(piece).unwrap());
        }
        let (last, file) = writer.finish().unwrap();
        out.extend(last);
        (out, file)
    }

    fn open_in_pieces(file: &FileRef, bytes: &[u8], piece: usize) -> Result<Vec<u8>> {
        let mut reader = file.reader();
        let mut out = Vec::new();
        for part in bytes.chunks(piece) {
            out.extend_from_slice(reader.update(part)?.expose());
        }
        out.extend_from_slice(reader.finish()?.expose());
        Ok(out)
    }

    #[test]
    fn content_comes_back_whatever_the_pieces_and_chunk_boundaries() {
        for size in [0, 1, 15, 16, 17, 31, 32, 33, 64, 100] {
            let content: Vec<u8> = (0..size).map(|i| i as u8).collect();
            for pieces in [1, 7, 16, 1000] {
                let (bytes, file) = seal(&content, 16, pieces);
                assert_eq!(bytes.len() as u64, sealed_size(size as u64, 16), "size {size}");
                assert_eq!(file.size, size as u64);
                for piece in [1, 5, 32, 10_000] {
                    assert_eq!(open_in_pieces(&file, &bytes, piece).unwrap(), content, "size {size}");
                }
            }
        }
    }

    #[test]
    fn a_changed_reordered_cut_or_lengthened_file_is_refused() {
        let content: Vec<u8> = (0..48).collect();
        let (bytes, file) = seal(&content, 16, 48);
        let chunk = 16 + TAG_LEN;
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(file.open(&changed).is_err(), "byte {index}");
        }
        // Chunks 0 and 1 swapped.
        let mut swapped = bytes[..FILE_HEADER_LEN].to_vec();
        swapped.extend_from_slice(&bytes[FILE_HEADER_LEN + chunk..FILE_HEADER_LEN + 2 * chunk]);
        swapped.extend_from_slice(&bytes[FILE_HEADER_LEN..FILE_HEADER_LEN + chunk]);
        swapped.extend_from_slice(&bytes[FILE_HEADER_LEN + 2 * chunk..]);
        assert_eq!(file.open(&swapped).err(), Some(VaultError::Corrupted));
        // Cut at a chunk boundary, cut inside a chunk, a byte added, nothing at all.
        assert!(file.open(&bytes[..FILE_HEADER_LEN + 2 * chunk]).is_err());
        assert!(file.open(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(file.open(&longer).is_err());
        assert!(file.open(&bytes[..FILE_HEADER_LEN]).is_err());
        assert!(file.open(&[]).is_err());
        // Another file's id in the header; another vault's ref.
        let (other, _) = seal(&content, 16, 48);
        assert!(file.open(&other).is_err());
        let mut elsewhere = file.renamed("x");
        elsewhere.vault = [8; VAULT_ID_LEN];
        assert!(elsewhere.open(&bytes).is_err());
    }

    #[test]
    fn the_ref_round_trips_through_its_field_value() {
        let (bytes, file) = seal(b"hello", 16, 5);
        let back = FileRef::from_bytes(&file.to_bytes()).unwrap();
        assert_eq!(back.open(&bytes).unwrap().expose(), b"hello");
        assert_eq!(back.name, "scan.pdf");
        assert_eq!(back.file_name().len(), 32);
        assert_eq!(parse_file_id(&back.file_name()), Some(back.id));
        assert!(FileRef::from_bytes(b"scan.pdf\0hello").is_none());
    }
}
