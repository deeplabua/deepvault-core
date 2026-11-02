//! A v2 vault in one file (ADR-0014, «Одним файлом»): Export Backup…, and what Open Vault File…
//! and an import of a `.dvault` take. The vault file, then the files of its entries one after
//! another, then a MAC over all of it. All integers little-endian.
//!
//! ```text
//! magic       "DVLP"                                        4 B
//! version     u16 = 1                                       2 B
//! main_len    u64                                           8 B
//! main        the vault file, format v2                     main_len B
//! count       u32                                           4 B
//! table × n   file_id 16 B ‖ len u64                        24 B each
//! files       each `files/<id>` as it is, in table order    Σ len B
//! pack_mac    HMAC-SHA256(K_pack_mac, magic … last file)    32 B
//! ```
//!
//! The files are copied as they are: each is already sealed under its own key, in its entry.
//! `pack_mac` (a subkey of its own, `deepvault/v2/pack-mac`) makes a file dropped, swapped,
//! cut or added a damaged backup instead of an entry without its file. Written and read piece
//! by piece: memory does not grow with the files.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::{Result, VaultError};
use crate::file::FILE_ID_LEN;
use crate::format::{MAGIC, VERSION};
use crate::keys::MAC_LEN;
use crate::vault::Vault;

pub const PACK_MAGIC: &[u8; 4] = b"DVLP";
pub const PACK_VERSION: u16 = 1;
/// Magic, version and `main_len`: what is read first.
pub const PREFIX_LEN: usize = 4 + 2 + 8;
const TABLE_ROW_LEN: usize = FILE_ID_LEN + 8;
/// A vault file is kilobytes to a few megabytes; a header claiming more is damaged.
const MAX_MAIN_LEN: u64 = 1024 * 1024 * 1024;

/// What a file is, by its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A vault file (`DVLT`), v1 or v2.
    Vault,
    /// A vault in one file with its files (`DVLP`).
    Pack,
    Other,
}

pub fn kind(prefix: &[u8]) -> Kind {
    match prefix.get(..4) {
        Some(m) if m == MAGIC => Kind::Vault,
        Some(m) if m == PACK_MAGIC => Kind::Pack,
        _ => Kind::Other,
    }
}

/// `main_len` from the first `PREFIX_LEN` bytes of a pack: the vault file comes next, then
/// `count` (4 B) and `count` rows of 24 bytes.
pub fn main_len(prefix: &[u8]) -> Result<u64> {
    if prefix.len() < PREFIX_LEN || kind(prefix) != Kind::Pack {
        return Err(VaultError::Corrupted);
    }
    let version = u16::from_le_bytes([prefix[4], prefix[5]]);
    if version != PACK_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let len = u64::from_le_bytes(prefix[6..14].try_into().expect("8 bytes"));
    if len > MAX_MAIN_LEN {
        return Err(VaultError::Corrupted);
    }
    Ok(len)
}

/// The length of the table after `count` (the 4 bytes after the vault file).
pub fn table_len(count: &[u8]) -> Result<u64> {
    let count: [u8; 4] = count.try_into().map_err(|_| VaultError::Corrupted)?;
    Ok(u64::from(u32::from_le_bytes(count)) * TABLE_ROW_LEN as u64)
}

/// The vault file inside a pack's head (the bytes from the start through the table).
pub fn main_of(head: &[u8]) -> Result<&[u8]> {
    let len = main_len(head)? as usize;
    head.get(PREFIX_LEN..PREFIX_LEN + len).ok_or(VaultError::Corrupted)
}

/// Writes a pack: `head()`, then each file in the order given, through `update`, then the
/// MAC from `finish`.
pub struct PackWriter {
    head: Vec<u8>,
    mac: Hmac<Sha256>,
    expected: u64,
    written: u64,
}

impl PackWriter {
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// The next bytes of the files, as they are in `files/`.
    pub fn update(&mut self, bytes: &[u8]) {
        self.written += bytes.len() as u64;
        self.mac.update(bytes);
    }

    /// `pack_mac`. `Corrupted` when the files given are not as long as the table says.
    pub fn finish(self) -> Result<[u8; MAC_LEN]> {
        if self.written != self.expected {
            return Err(VaultError::Corrupted);
        }
        Ok(self.mac.finalize().into_bytes().into())
    }
}

/// Reads a pack whose vault file opened: the files in the table, and the MAC checked over
/// what `update` was given.
pub struct PackReader {
    files: Vec<([u8; FILE_ID_LEN], u64)>,
    mac: Hmac<Sha256>,
    expected: u64,
    read: u64,
}

impl PackReader {
    /// Each file's id and length, in the order they follow.
    pub fn files(&self) -> &[([u8; FILE_ID_LEN], u64)] {
        &self.files
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.read += bytes.len() as u64;
        self.mac.update(bytes);
    }

    /// `Corrupted` unless the files were as long as the table says and `mac` is theirs.
    pub fn finish(self, mac: &[u8]) -> Result<()> {
        if self.read != self.expected || self.mac.verify_slice(mac).is_err() {
            return Err(VaultError::Corrupted);
        }
        Ok(())
    }
}

impl Vault {
    /// A pack of this vault with `files` — `(id, length of files/<id>)`, in the order they will
    /// be given. Only a v2 vault: a v1 one is a single file already (`to_bytes`).
    pub fn pack_writer(&self, files: &[([u8; FILE_ID_LEN], u64)]) -> Result<PackWriter> {
        if self.version() != VERSION {
            return Err(VaultError::UnsupportedVersion(self.version()));
        }
        let main = self.to_bytes();
        let mut head = Vec::with_capacity(PREFIX_LEN + main.len() + 4 + files.len() * TABLE_ROW_LEN);
        head.extend_from_slice(PACK_MAGIC);
        head.extend_from_slice(&PACK_VERSION.to_le_bytes());
        head.extend_from_slice(&(main.len() as u64).to_le_bytes());
        head.extend_from_slice(&main);
        head.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for (id, len) in files {
            head.extend_from_slice(id);
            head.extend_from_slice(&len.to_le_bytes());
        }
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.subkeys().pack_mac.expose())
            .expect("HMAC takes any key length");
        mac.update(&head);
        Ok(PackWriter { head, mac, expected: files.iter().map(|(_, len)| len).sum(), written: 0 })
    }

    /// A reader of the pack whose head is `head` (from the start through the table) and whose
    /// vault file this vault was opened from (`main_of`). `Corrupted` when the head is not
    /// whole or its vault file is another one.
    pub fn pack_reader(&self, head: &[u8]) -> Result<PackReader> {
        let main = main_of(head)?;
        // The vault file in the head must be this vault's, MACs and all.
        self.verify_file(main)?;
        let at = PREFIX_LEN + main.len();
        let table = table_len(head.get(at..at + 4).ok_or(VaultError::Corrupted)?)? as usize;
        let rows = head.get(at + 4..).ok_or(VaultError::Corrupted)?;
        if rows.len() != table {
            return Err(VaultError::Corrupted);
        }
        let mut files = Vec::with_capacity(table / TABLE_ROW_LEN);
        for row in rows.as_chunks::<TABLE_ROW_LEN>().0 {
            let id: [u8; FILE_ID_LEN] = row[..FILE_ID_LEN].try_into().expect("16 bytes");
            if files.iter().any(|(other, _)| *other == id) {
                return Err(VaultError::Corrupted);
            }
            files.push((id, u64::from_le_bytes(row[FILE_ID_LEN..].try_into().expect("8 bytes"))));
        }
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.subkeys().pack_mac.expose())
            .expect("HMAC takes any key length");
        mac.update(head);
        let expected = files.iter().try_fold(0u64, |sum, (_, len)| sum.checked_add(*len));
        Ok(PackReader { files, mac, expected: expected.ok_or(VaultError::Corrupted)?, read: 0 })
    }
}
