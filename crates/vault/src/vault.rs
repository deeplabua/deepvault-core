//! An unlocked vault. Locking is dropping it: the vault key, the subkeys and the entry index
//! are zeroed on drop.

use crate::aead::{self, NONCE_LEN};
use crate::entropy::{Entropy, SystemEntropy};
use crate::entry::{Entry, EntrySummary, FieldSummary, NewEntry};
use crate::error::{Result, VaultError};
use crate::format::{self, Block, Header, KdfHeader, SlotHeader, ENTRY_ID_LEN};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::keys::{self, SlotKind, Subkeys, VAULT_ID_LEN, WRAPPED_VK_LEN};
use crate::secret::{Key, SecretBytes};

const KDF_ALG: &str = "argon2id";
/// Device slot: `version (1) ‖ nonce (24 B) ‖ wrapped VK (48 B)`.
const DEVICE_SLOT_VERSION: u8 = 1;
const DEVICE_SLOT_LEN: usize = 1 + NONCE_LEN + WRAPPED_VK_LEN;

pub struct Vault {
    header: Header,
    vk: Key,
    keys: Subkeys,
    /// Every block in file order, tombstones included. Entries stay encrypted in memory; only
    /// the index is decrypted.
    blocks: Vec<Block>,
    /// Live entries, in block order.
    index: Vec<EntrySummary>,
    entropy: Box<dyn Entropy>,
}

impl Vault {
    /// A new vault with one password slot and no entries. Runs the KDF once.
    pub fn create(password: &[u8], params: KdfParams) -> Result<Self> {
        Self::create_inner(Box::new(SystemEntropy), password, params)
    }

    /// `create` with scripted randomness and time, for test vectors. Randomness is drawn in
    /// this order: vault id (16), salt (16), VK (32), slot nonce (24).
    #[cfg(feature = "testing")]
    pub fn create_with(entropy: Box<dyn Entropy>, password: &[u8], params: KdfParams) -> Result<Self> {
        Self::create_inner(entropy, password, params)
    }

    fn create_inner(mut entropy: Box<dyn Entropy>, password: &[u8], params: KdfParams) -> Result<Self> {
        params.check()?;
        let mut vault_id = [0; VAULT_ID_LEN];
        entropy.fill(&mut vault_id);
        let mut salt = [0; SALT_LEN];
        entropy.fill(&mut salt);
        let mut vk = Key::zeroed();
        entropy.fill(vk.expose_mut());
        let mut nonce = [0; NONCE_LEN];
        entropy.fill(&mut nonce);

        let kek = kdf::derive_kek(password, &salt, params)?;
        let wrapped_vk = keys::wrap_vk(&kek, &vk, &nonce, SlotKind::Password, &vault_id);
        let header = Header {
            vault_id,
            created_at: entropy.now(),
            kdf: KdfHeader { alg: KDF_ALG.into(), m_kib: params.m_kib, t: params.t, p: params.p, salt },
            slots: vec![SlotHeader { kind: SlotKind::Password.label().into(), nonce, wrapped_vk }],
        };
        let keys = Subkeys::derive(&vk, &vault_id);
        Ok(Self { header, vk, keys, blocks: Vec::new(), index: Vec::new(), entropy })
    }

    /// Opens a vault file with the master password: tries every password slot with the key
    /// derived from the header's KDF parameters.
    pub fn open(file: &[u8], password: &[u8]) -> Result<Self> {
        Self::open_inner(file, |header, params| {
            let kek = kdf::derive_kek(password, &header.kdf.salt, params)?;
            header
                .slots
                .iter()
                .filter(|slot| slot.kind == SlotKind::Password.label())
                .find_map(|slot| {
                    keys::unwrap_vk(&kek, &slot.wrapped_vk, &slot.nonce, SlotKind::Password, &header.vault_id)
                })
                .ok_or(VaultError::WrongPassword)
        })
    }

    /// Opens a vault file with a device slot from the Keychain and the 32-byte key the Secure
    /// Enclave gave for it (Touch ID). `WrongPassword` when the slot belongs to another vault
    /// or the key is not the one it was made with.
    pub fn open_with_device_key(file: &[u8], device_slot: &[u8], kek: &[u8]) -> Result<Self> {
        let kek = Key::from_slice(kek).ok_or(VaultError::InvalidKey)?;
        if device_slot.len() != DEVICE_SLOT_LEN || device_slot[0] != DEVICE_SLOT_VERSION {
            return Err(VaultError::InvalidKey);
        }
        let nonce: [u8; NONCE_LEN] = device_slot[1..1 + NONCE_LEN].try_into().expect("length checked");
        let wrapped = &device_slot[1 + NONCE_LEN..];
        Self::open_inner(file, |header, _| {
            keys::unwrap_vk(&kek, wrapped, &nonce, SlotKind::Device, &header.vault_id)
                .ok_or(VaultError::WrongPassword)
        })
    }

    fn open_inner(file: &[u8], unlock: impl FnOnce(&Header, KdfParams) -> Result<Key>) -> Result<Self> {
        let raw = format::parse(file)?;
        let params = validate(&raw.header)?;
        let vk = unlock(&raw.header, params)?;
        let keys = Subkeys::derive(&vk, &raw.header.vault_id);
        if !keys::verify_mac(&keys.header_mac, raw.header_region, raw.header_mac)
            || !keys::verify_mac(&keys.file_mac, raw.file_region, raw.file_mac)
        {
            return Err(VaultError::Corrupted);
        }

        let mut index = Vec::new();
        for (position, block) in raw.blocks.iter().enumerate() {
            if raw.blocks[..position].iter().any(|earlier| earlier.entry_id == block.entry_id) {
                return Err(VaultError::Corrupted);
            }
            let entry = decrypt(&keys, &raw.header.vault_id, block).ok_or(VaultError::Corrupted)?;
            if !entry.deleted {
                index.push(EntrySummary::new(block.entry_id, &entry));
            }
        }
        Ok(Self { header: raw.header, vk, keys, blocks: raw.blocks, index, entropy: Box::new(SystemEntropy) })
    }

    /// The whole file, ready to be written atomically by the caller.
    pub fn to_bytes(&self) -> Vec<u8> {
        format::write(&self.header, &self.blocks, &self.keys)
    }

    /// Wraps the vault key for Touch ID: `kek` is the 32-byte key the app derives through the
    /// Secure Enclave. The slot is kept in the Keychain, not in the file.
    pub fn device_slot(&mut self, kek: &[u8]) -> Result<Vec<u8>> {
        let kek = Key::from_slice(kek).ok_or(VaultError::InvalidKey)?;
        let mut nonce = [0; NONCE_LEN];
        self.entropy.fill(&mut nonce);
        let mut slot = Vec::with_capacity(DEVICE_SLOT_LEN);
        slot.push(DEVICE_SLOT_VERSION);
        slot.extend_from_slice(&nonce);
        slot.extend(keys::wrap_vk(&kek, &self.vk, &nonce, SlotKind::Device, &self.header.vault_id));
        Ok(slot)
    }

    /// Live entries, oldest first.
    pub fn entries(&self) -> &[EntrySummary] {
        &self.index
    }

    /// Seals a new entry and returns its id. Randomness: entry id (16), nonce (24).
    pub fn add_entry(&mut self, new: NewEntry) -> [u8; ENTRY_ID_LEN] {
        let mut id = [0; ENTRY_ID_LEN];
        while id == [0; ENTRY_ID_LEN] || self.blocks.iter().any(|block| block.entry_id == id) {
            self.entropy.fill(&mut id);
        }
        let now = self.entropy.now();
        let entry = Entry {
            kind: new.kind,
            title: new.title,
            fields: new.fields,
            created_at: now,
            updated_at: now,
            deleted: false,
        };
        self.index.push(EntrySummary::new(id, &entry));
        let block = self.seal(id, &entry);
        self.blocks.push(block);
        id
    }

    /// Replaces the entry with a tombstone: its kind and dates stay, the content goes.
    pub fn delete_entry(&mut self, id: &[u8; ENTRY_ID_LEN]) -> Result<()> {
        let position = self.index.iter().position(|summary| &summary.id == id).ok_or(VaultError::NotFound)?;
        let block = self.block_index(id)?;
        let old =
            decrypt(&self.keys, &self.header.vault_id, &self.blocks[block]).ok_or(VaultError::Corrupted)?;
        let tombstone = Entry {
            kind: old.kind,
            title: String::new(),
            fields: Vec::new(),
            created_at: old.created_at,
            updated_at: self.entropy.now(),
            deleted: true,
        };
        self.blocks[block] = self.seal(*id, &tombstone);
        self.index.remove(position);
        Ok(())
    }

    /// Replaces a live entry's kind, title and fields. Its id, place and creation date stay;
    /// it is sealed again under a fresh nonce. Randomness: nonce (24).
    pub fn update_entry(&mut self, id: &[u8; ENTRY_ID_LEN], new: NewEntry) -> Result<()> {
        let position = self.index.iter().position(|summary| &summary.id == id).ok_or(VaultError::NotFound)?;
        let block = self.block_index(id)?;
        let old =
            decrypt(&self.keys, &self.header.vault_id, &self.blocks[block]).ok_or(VaultError::Corrupted)?;
        let entry = Entry {
            kind: new.kind,
            title: new.title,
            fields: new.fields,
            created_at: old.created_at,
            updated_at: self.entropy.now().max(old.updated_at),
            deleted: false,
        };
        self.index[position] = EntrySummary::new(*id, &entry);
        self.blocks[block] = self.seal(*id, &entry);
        Ok(())
    }

    /// The fields of a live entry, in order, without concealed values.
    pub fn fields(&self, id: &[u8; ENTRY_ID_LEN]) -> Result<Vec<FieldSummary>> {
        let entry = self.live(id)?;
        Ok(entry.fields.iter().map(FieldSummary::new).collect())
    }

    /// The field at `index` (as `fields` lists them) of a live entry, decrypted for this call
    /// only. For entries with several fields of one name (sites, notes).
    pub fn secret_at(&self, id: &[u8; ENTRY_ID_LEN], index: usize) -> Result<SecretBytes> {
        let entry = self.live(id)?;
        let field = entry.fields.get(index).ok_or(VaultError::NotFound)?;
        Ok(SecretBytes::new(field.value.clone()))
    }

    /// The one-time code of the TOTP field at `index` at `unix_time`. The secret stays here.
    pub fn totp(&self, id: &[u8; ENTRY_ID_LEN], index: usize, unix_time: u64) -> Result<crate::TotpCode> {
        let entry = self.live(id)?;
        let field = entry.fields.get(index).ok_or(VaultError::NotFound)?;
        crate::totp::code(&field.value, unix_time)
    }

    /// One field of a live entry, decrypted for this call only.
    pub fn secret(&self, id: &[u8; ENTRY_ID_LEN], field: &str) -> Result<SecretBytes> {
        let entry = self.live(id)?;
        let field = entry.field(field).ok_or(VaultError::NotFound)?;
        Ok(SecretBytes::new(field.value.clone()))
    }

    pub fn vault_id(&self) -> [u8; VAULT_ID_LEN] {
        self.header.vault_id
    }

    pub fn kdf_params(&self) -> KdfParams {
        KdfParams { m_kib: self.header.kdf.m_kib, t: self.header.kdf.t, p: self.header.kdf.p }
    }

    /// A live entry, decrypted; dropped (and zeroed) by the caller.
    fn live(&self, id: &[u8; ENTRY_ID_LEN]) -> Result<Entry> {
        if !self.index.iter().any(|summary| &summary.id == id) {
            return Err(VaultError::NotFound);
        }
        let block = &self.blocks[self.block_index(id)?];
        decrypt(&self.keys, &self.header.vault_id, block).ok_or(VaultError::Corrupted)
    }

    fn block_index(&self, id: &[u8; ENTRY_ID_LEN]) -> Result<usize> {
        self.blocks.iter().position(|block| &block.entry_id == id).ok_or(VaultError::NotFound)
    }

    fn seal(&mut self, id: [u8; ENTRY_ID_LEN], entry: &Entry) -> Block {
        let mut nonce = [0; NONCE_LEN];
        self.entropy.fill(&mut nonce);
        let aad = keys::aad("entry", &self.header.vault_id, &id);
        let ciphertext = aead::seal(&self.keys.entries, &nonce, &entry.to_cbor(), &aad);
        Block { entry_id: id, nonce, ciphertext }
    }
}

fn decrypt(keys: &Subkeys, vault_id: &[u8; VAULT_ID_LEN], block: &Block) -> Option<Entry> {
    let aad = keys::aad("entry", vault_id, &block.entry_id);
    let plaintext = aead::open(&keys.entries, &block.nonce, &block.ciphertext, &aad)?;
    Entry::from_cbor(plaintext.expose())
}

/// What the header must say before its KDF is run. A header that fails here is damaged (or
/// crafted): refused as `Corrupted` before any work.
fn validate(header: &Header) -> Result<KdfParams> {
    let params = KdfParams { m_kib: header.kdf.m_kib, t: header.kdf.t, p: header.kdf.p };
    let slots_ok = header.slots.iter().all(|slot| {
        matches!(SlotKind::from_label(&slot.kind), Some(SlotKind::Password | SlotKind::Recovery))
            && slot.wrapped_vk.len() == WRAPPED_VK_LEN
    });
    let has_password = header.slots.iter().any(|slot| slot.kind == SlotKind::Password.label());
    if header.kdf.alg != KDF_ALG || params.check().is_err() || !slots_ok || !has_password {
        return Err(VaultError::Corrupted);
    }
    Ok(params)
}
