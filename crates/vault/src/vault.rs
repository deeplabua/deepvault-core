//! An unlocked vault. Locking is dropping it: the vault key, the subkeys and the entry index
//! are zeroed on drop.

use crate::aead::{self, NONCE_LEN};
use crate::entropy::{Entropy, SystemEntropy};
use crate::entry::{field, Entry, EntryKind, EntrySummary, Field, FieldSummary, NewEntry};
use crate::error::{Result, VaultError};
use crate::file::{FileRef, FileWriter, CHUNK_SIZE, FILE_ID_LEN};
use crate::format::{self, Block, Header, KdfHeader, SlotHeader, ENTRY_ID_LEN, VERSION};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::keys::{self, SlotKind, Subkeys, VAULT_ID_LEN, WRAPPED_VK_LEN};
use crate::secret::{Key, SecretBytes};
use zeroize::Zeroizing;

const KDF_ALG: &str = "argon2id";
/// The fields `Vault::search` reads, when not concealed (notes always; custom fields by name).
const SEARCHED: &[&str] = &[
    field::URL,
    field::USERNAME,
    field::TAG,
    field::SHELL,
    field::EMAIL,
    field::CARDHOLDER,
    field::BANK,
    field::HOLDER,
    field::LICENSED_TO,
    field::VERSION,
];
/// Device slot: `version (1) ‖ nonce (24 B) ‖ wrapped VK (48 B)`.
const DEVICE_SLOT_VERSION: u8 = 1;
const DEVICE_SLOT_LEN: usize = 1 + NONCE_LEN + WRAPPED_VK_LEN;

pub struct Vault {
    /// The file version: `VERSION` (2), or 1 for a file read that has not moved yet (`upgrade`).
    version: u16,
    header: Header,
    vk: Key,
    keys: Subkeys,
    /// Every block in file order, tombstones included. Entries stay encrypted in memory; only
    /// the index is decrypted.
    blocks: Vec<Block>,
    /// Live entries, in block order.
    index: Vec<EntrySummary>,
    /// Entries in Recently Deleted, in block order: kept whole until restored or deleted for good.
    trash: Vec<EntrySummary>,
    entropy: Box<dyn Entropy>,
}

/// A passkey's public facts (`Vault::passkeys`): its entry, site, id and user. Not the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    pub entry: [u8; ENTRY_ID_LEN],
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub user_name: String,
}

/// One password the audit looked at (`Vault::audit`): where it is, how strong it is, and the
/// group of entries sharing it (`None`: no other entry has it). Never the password itself.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AuditItem {
    pub id: [u8; ENTRY_ID_LEN],
    /// The field's position, as `fields` lists them.
    pub index: usize,
    pub strength: crate::strength::Strength,
    pub reused: Option<usize>,
}

impl Vault {
    /// A new vault with one password slot and no entries. Runs the KDF once.
    pub fn create(password: &[u8], params: KdfParams) -> Result<Self> {
        Self::create_inner(VERSION, Box::new(SystemEntropy), password, params)
    }

    /// `create` with scripted randomness and time, for test vectors. Randomness is drawn in
    /// this order: vault id (16), salt (16), VK (32), slot nonce (24).
    #[cfg(feature = "testing")]
    pub fn create_with(entropy: Box<dyn Entropy>, password: &[u8], params: KdfParams) -> Result<Self> {
        Self::create_inner(VERSION, entropy, password, params)
    }

    /// `create_with`, writing format v1: the v1 vector, and vaults as DeepVault made them before
    /// v2, for the tests of `upgrade`.
    #[cfg(feature = "testing")]
    pub fn create_v1_with(entropy: Box<dyn Entropy>, password: &[u8], params: KdfParams) -> Result<Self> {
        Self::create_inner(format::VERSION_1, entropy, password, params)
    }

    fn create_inner(
        version: u16,
        mut entropy: Box<dyn Entropy>,
        password: &[u8],
        params: KdfParams,
    ) -> Result<Self> {
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
        Ok(Self {
            version,
            header,
            vk,
            keys,
            blocks: Vec::new(),
            index: Vec::new(),
            trash: Vec::new(),
            entropy,
        })
    }

    /// Randomness and time from `entropy` from now on: a vault opened in a test, at a set time.
    #[cfg(feature = "testing")]
    pub fn set_entropy(&mut self, entropy: Box<dyn Entropy>) {
        self.entropy = entropy;
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

        for (position, block) in raw.blocks.iter().enumerate() {
            if raw.blocks[..position].iter().any(|earlier| earlier.entry_id == block.entry_id) {
                return Err(VaultError::Corrupted);
            }
        }
        let (index, trash) = index_blocks(&keys, raw.version, &raw.header.vault_id, &raw.blocks)?;
        Ok(Self {
            version: raw.version,
            header: raw.header,
            vk,
            keys,
            blocks: raw.blocks,
            index,
            trash,
            entropy: Box::new(SystemEntropy),
        })
    }

    /// Undo: the entries as they were in `file`, a copy of this same vault saved earlier
    /// (`to_bytes` before a merge). Its MACs must check with this vault's keys — another vault
    /// or a damaged copy is refused and nothing changes. The header (slots, KDF) stays as it is
    /// now: only the entries go back — and the format version, so a move to v2 whose files could
    /// not be written goes back to the v1 bytes saved before it.
    pub fn revert_to(&mut self, file: &[u8]) -> Result<()> {
        let (version, _, blocks) = self.own_copy(file)?;
        let (index, trash) = index_blocks(&self.keys, version, &self.header.vault_id, &blocks)?;
        self.version = version;
        self.blocks = blocks;
        self.index = index;
        self.trash = trash;
        Ok(())
    }

    /// Takes in another copy of this vault — the file as another device wrote it (iCloud Drive),
    /// or a conflict version the sync kept — entry by entry (ADR-0016). `base` is the file as
    /// this vault was last read or written, when the caller kept it: an entry changed only on one
    /// side since then takes that side; one changed on both (or with no base) takes the version
    /// changed last (`updated_at`), and the other version's password and one-time code go to its
    /// history (`field::PREVIOUS`) — nothing is lost. An entry deleted for good on one side and
    /// changed on the other goes to Recently Deleted instead. Entries only one side has are
    /// kept. The header (key slots, KDF) takes the side that changed it; changed on both:
    /// `Diverged`, and nothing changes. Another vault or a damaged copy: `Corrupted`. All or
    /// nothing. The caller saves when `outgoing` is not 0. Randomness: a nonce (24) per entry
    /// sealed anew.
    pub fn merge_file(&mut self, theirs: &[u8], base: Option<&[u8]>) -> Result<MergeReport> {
        let (version, their_header, their_blocks) = self.own_copy(theirs)?;
        // A base that is not a copy of this vault (damaged) is no help: merged as with none.
        let base = base.and_then(|base| self.own_copy(base).ok());
        if version != self.version {
            return Err(VaultError::Diverged);
        }
        let mut report = MergeReport::default();
        let ours_header = format::to_cbor(&self.header);
        let theirs_header = format::to_cbor(&their_header);
        let mut new_header = None;
        if ours_header != theirs_header {
            match base.as_ref().map(|(_, header, _)| format::to_cbor(header)) {
                Some(base) if base == ours_header => new_header = Some(their_header),
                Some(base) if base == theirs_header => report.outgoing += 1,
                _ => return Err(VaultError::Diverged),
            }
        }
        let base_blocks: &[Block] = base.as_ref().map_or(&[], |(_, _, blocks)| blocks);
        let find = |blocks: &[Block], id: &[u8; ENTRY_ID_LEN]| -> Option<usize> {
            blocks.iter().position(|block| &block.entry_id == id)
        };

        let mut blocks = self.blocks.clone();
        for block in blocks.iter_mut() {
            let id = block.entry_id;
            let Some(theirs) = find(&their_blocks, &id).map(|at| &their_blocks[at]) else {
                report.outgoing += 1;
                continue;
            };
            if same_block(block, theirs) {
                continue;
            }
            let ours_entry = decrypt(&self.keys, self.version, &self.header.vault_id, block)?;
            let theirs_entry = decrypt(&self.keys, self.version, &self.header.vault_id, theirs)?;
            if ours_entry.to_cbor() == theirs_entry.to_cbor() {
                continue;
            }
            let base = find(base_blocks, &id).map(|at| &base_blocks[at]);
            let ours_unchanged = base.is_some_and(|base| same_block(base, block));
            let theirs_unchanged = base.is_some_and(|base| same_block(base, theirs));
            let merged = if ours_unchanged {
                theirs_entry.clone()
            } else if theirs_unchanged {
                ours_entry.clone()
            } else {
                let base = base
                    .map(|base| decrypt(&self.keys, self.version, &self.header.vault_id, base))
                    .transpose()?;
                resolve(&ours_entry, &theirs_entry, base.as_ref())
            };
            report.count(Some(&ours_entry), &merged);
            let merged_cbor = merged.to_cbor();
            if merged_cbor == theirs_entry.to_cbor() {
                *block = theirs.clone();
            } else {
                report.outgoing += 1;
                if merged_cbor != ours_entry.to_cbor() {
                    *block = self.seal(id, &merged);
                }
            }
        }
        for theirs in &their_blocks {
            if find(&blocks, &theirs.entry_id).is_some() {
                continue;
            }
            // Here before and taken out since (`revert_to`, an undone import): it stays out
            // unless the other side changed it.
            if find(base_blocks, &theirs.entry_id).is_some_and(|at| same_block(&base_blocks[at], theirs)) {
                continue;
            }
            let entry = decrypt(&self.keys, self.version, &self.header.vault_id, theirs)?;
            report.count(None, &entry);
            blocks.push(theirs.clone());
        }

        let (index, trash) = index_blocks(&self.keys, self.version, &self.header.vault_id, &blocks)?;
        if let Some(header) = new_header {
            self.header = header;
        }
        self.blocks = blocks;
        self.index = index;
        self.trash = trash;
        Ok(report)
    }

    /// A copy of this vault's file, checked: its id, its MACs under this vault's keys, one block
    /// per entry. `Corrupted` for another vault or a damaged copy.
    fn own_copy(&self, file: &[u8]) -> Result<(u16, Header, Vec<Block>)> {
        let raw = format::parse(file)?;
        if raw.header.vault_id != self.header.vault_id
            || !keys::verify_mac(&self.keys.header_mac, raw.header_region, raw.header_mac)
            || !keys::verify_mac(&self.keys.file_mac, raw.file_region, raw.file_mac)
        {
            return Err(VaultError::Corrupted);
        }
        for (position, block) in raw.blocks.iter().enumerate() {
            if raw.blocks[..position].iter().any(|earlier| earlier.entry_id == block.entry_id) {
                return Err(VaultError::Corrupted);
            }
        }
        Ok((raw.version, raw.header, raw.blocks))
    }

    /// The whole file, ready to be written atomically by the caller.
    pub fn to_bytes(&self) -> Vec<u8> {
        format::write(self.version, &self.header, &self.blocks, &self.keys)
    }

    /// Replaces the master password (PRD 04: one slot rewritten, no entry). `current` must open
    /// a password slot of this vault — the vault being unlocked is not enough, so a Mac left
    /// unlocked does not give the password away. The vault key stays: entries, recovery slots and
    /// device slots (Touch ID) are untouched. Every password slot gives way to one new slot under
    /// a fresh salt; the KDF parameters stay. Runs the KDF twice. Randomness: salt (16), nonce (24).
    ///
    /// Copies of the file made before still open with the old password: they hold the same vault
    /// key under the old slot.
    pub fn change_password(&mut self, current: &[u8], new: &[u8]) -> Result<()> {
        let params = self.kdf_params();
        let kek = kdf::derive_kek(current, &self.header.kdf.salt, params)?;
        let opens =
            self.header.slots.iter().filter(|slot| slot.kind == SlotKind::Password.label()).any(|slot| {
                keys::unwrap_vk(
                    &kek,
                    &slot.wrapped_vk,
                    &slot.nonce,
                    SlotKind::Password,
                    &self.header.vault_id,
                )
                .is_some()
            });
        if !opens {
            return Err(VaultError::WrongPassword);
        }

        let mut salt = [0; SALT_LEN];
        self.entropy.fill(&mut salt);
        let mut nonce = [0; NONCE_LEN];
        self.entropy.fill(&mut nonce);
        let kek = kdf::derive_kek(new, &salt, params)?;
        let wrapped_vk = keys::wrap_vk(&kek, &self.vk, &nonce, SlotKind::Password, &self.header.vault_id);
        self.header.slots.retain(|slot| slot.kind != SlotKind::Password.label());
        self.header
            .slots
            .insert(0, SlotHeader { kind: SlotKind::Password.label().into(), nonce, wrapped_vk });
        self.header.kdf.salt = salt;
        Ok(())
    }

    /// Marks a live entry as a favourite or not. Not a change of its content: `updated_at`
    /// stays, as with `mark_used`. Randomness: nonce (24).
    pub fn set_favorite(&mut self, id: &[u8; ENTRY_ID_LEN], favorite: bool) -> Result<()> {
        let position = self.index.iter().position(|summary| &summary.id == id).ok_or(VaultError::NotFound)?;
        let block = self.block_index(id)?;
        let mut entry = decrypt(&self.keys, self.version, &self.header.vault_id, &self.blocks[block])?;
        entry.favorite = favorite;
        self.index[position] = EntrySummary::new(*id, &entry);
        self.blocks[block] = self.seal(*id, &entry);
        Ok(())
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
            used_at: 0,
            favorite: false,
            trashed_at: 0,
            deleted: false,
        };
        self.index.push(EntrySummary::new(id, &entry));
        let block = self.seal(id, &entry);
        self.blocks.push(block);
        id
    }

    /// A new ed25519 SSH key made here (ADR-0006): the private half never leaves the core.
    pub fn add_ssh_key(&mut self, title: &str, comment: &str) -> [u8; ENTRY_ID_LEN] {
        let key = crate::ssh::Ed25519Key::generate(&mut *self.entropy, comment);
        self.add_ssh_entry(title, &crate::ssh::PrivateKey::Ed25519(key))
    }

    /// An SSH key from its `-----BEGIN OPENSSH PRIVATE KEY-----` text (unencrypted ed25519, or
    /// RSA of 2048 bits or more, ADR-0011); stored re-encoded, so the vault holds one canonical
    /// form.
    pub fn import_ssh_key(&mut self, title: &str, private_key: &[u8]) -> Result<[u8; ENTRY_ID_LEN]> {
        let text = std::str::from_utf8(private_key).map_err(|_| VaultError::InvalidSshKey)?;
        let key = crate::ssh::PrivateKey::from_openssh(text)?;
        Ok(self.add_ssh_entry(title, &key))
    }

    fn add_ssh_entry(&mut self, title: &str, key: &crate::ssh::PrivateKey) -> [u8; ENTRY_ID_LEN] {
        let private = key.to_openssh(&mut *self.entropy);
        self.add_entry(NewEntry {
            kind: EntryKind::SshKey,
            title: title.to_string(),
            fields: vec![
                Field {
                    name: field::SSH_PRIVATE_KEY.into(),
                    value: private.as_bytes().to_vec(),
                    concealed: true,
                    custom: false,
                },
                Field {
                    name: field::SSH_PUBLIC_KEY.into(),
                    value: key.public_line().into_bytes(),
                    concealed: false,
                    custom: false,
                },
            ],
        })
    }

    /// The signature of `data` by the SSH key of a live `ssh_key` entry, in the SSH wire format;
    /// `flags` are the agent's SIGN_REQUEST flags (an RSA key's hash). The private key is read,
    /// used and zeroed here.
    pub fn ssh_sign(&self, id: &[u8; ENTRY_ID_LEN], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        let entry = self.live(id)?;
        if entry.kind != EntryKind::SshKey {
            return Err(VaultError::NotFound);
        }
        let field = entry.field(field::SSH_PRIVATE_KEY).ok_or(VaultError::NotFound)?;
        let text = std::str::from_utf8(&field.value).map_err(|_| VaultError::InvalidSshKey)?;
        Ok(crate::ssh::PrivateKey::from_openssh(text)?.sign(data, flags)?)
    }

    /// A new passkey (ADR-0010) for `rp_id` and the user: added to `entry` (a login of that
    /// site), or to a new login titled `rp_id`. The key is made here and never leaves; the
    /// platform gets the credential id and the attestation object. The caller saves.
    pub fn passkey_register(
        &mut self,
        entry: Option<&[u8; ENTRY_ID_LEN]>,
        rp_id: &str,
        user_handle: &[u8],
        user_name: &str,
        user_display: &str,
    ) -> Result<([u8; ENTRY_ID_LEN], crate::passkey::Registration)> {
        let passkey =
            crate::passkey::Passkey::new(rp_id, user_handle, user_name, user_display, self.entropy.as_mut());
        let registration = passkey.registration()?;
        let field =
            Field { name: field::PASSKEY.into(), value: passkey.to_bytes(), concealed: true, custom: false };
        let id = match entry {
            Some(id) => {
                let old = self.live(id)?;
                let mut fields = old.fields.clone();
                fields.push(field);
                self.update_entry(id, NewEntry { kind: old.kind, title: old.title.clone(), fields })?;
                *id
            }
            None => {
                let mut fields = vec![];
                if !user_name.is_empty() {
                    fields.push(Field {
                        name: field::USERNAME.into(),
                        value: user_name.as_bytes().to_vec(),
                        concealed: false,
                        custom: false,
                    });
                }
                fields.push(Field {
                    name: field::URL.into(),
                    value: format!("https://{rp_id}").into_bytes(),
                    concealed: false,
                    custom: false,
                });
                fields.push(field);
                self.add_entry(NewEntry { kind: EntryKind::Login, title: rp_id.into(), fields })
            }
        };
        Ok((id, registration))
    }

    /// The live passkeys for `rp_id` (every site when `None`): where they are and for whom —
    /// never a key.
    pub fn passkeys(&self, rp_id: Option<&str>) -> Vec<PasskeyInfo> {
        let mut out = Vec::new();
        for summary in &self.index {
            let Ok(entry) = self.live(&summary.id) else { continue };
            for field in entry.fields.iter().filter(|f| f.name == field::PASSKEY && !f.custom) {
                let Ok(passkey) = crate::passkey::Passkey::from_bytes(&field.value) else { continue };
                if rp_id.is_some_and(|rp| rp != passkey.rp_id) {
                    continue;
                }
                out.push(PasskeyInfo {
                    entry: summary.id,
                    rp_id: passkey.rp_id.clone(),
                    credential_id: passkey.credential_id.clone(),
                    user_handle: passkey.user_handle.clone(),
                    user_name: passkey.user_name.clone(),
                });
            }
        }
        out
    }

    /// Signs a sign-in to `rp_id` with the passkey `credential_id`: authenticator data and the
    /// signature; the key stays here.
    pub fn passkey_assert(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        client_data_hash: &[u8],
    ) -> Result<(PasskeyInfo, crate::passkey::Assertion)> {
        for summary in &self.index {
            let Ok(entry) = self.live(&summary.id) else { continue };
            for field in entry.fields.iter().filter(|f| f.name == field::PASSKEY && !f.custom) {
                let Ok(passkey) = crate::passkey::Passkey::from_bytes(&field.value) else { continue };
                if passkey.rp_id == rp_id && passkey.credential_id == credential_id {
                    let assertion = passkey.assert(client_data_hash)?;
                    let info = PasskeyInfo {
                        entry: summary.id,
                        rp_id: passkey.rp_id.clone(),
                        credential_id: passkey.credential_id.clone(),
                        user_handle: passkey.user_handle.clone(),
                        user_name: passkey.user_name.clone(),
                    };
                    return Ok((info, assertion));
                }
            }
        }
        Err(VaultError::NotFound)
    }

    /// Removes the passkey `credential_id` from `entry`: the rest of the entry stays as it is,
    /// the key goes with the field. The caller saves.
    pub fn passkey_delete(&mut self, entry: &[u8; ENTRY_ID_LEN], credential_id: &[u8]) -> Result<()> {
        let old = self.live(entry)?;
        let mut fields = old.fields.clone();
        let before = fields.len();
        fields.retain(|f| {
            f.name != field::PASSKEY
                || f.custom
                || crate::passkey::Passkey::from_bytes(&f.value)
                    .map_or(true, |p| p.credential_id != credential_id)
        });
        if fields.len() == before {
            return Err(VaultError::NotFound);
        }
        let new = NewEntry { kind: old.kind, title: old.title.clone(), fields };
        self.update_entry(entry, new)
    }

    /// Adds another password manager's entries (`import::parse`), leaving out those the vault
    /// already has — so importing the same export again, or a newer one, adds only what is new
    /// and keeps what the user did here (pictures, links, edits). An entry is already there when
    /// a live one has its kind, title and fields, whatever their order, not counting what an
    /// import never brings: tags, the picture, links. Its tags are added to that entry.
    pub fn import(&mut self, entries: Vec<NewEntry>) -> Result<Merged> {
        self.import_labelled(entries, None)
    }

    /// `import`, with the new entries — not those the vault had — tagged `label` (the app's
    /// «Imported from 1Password»), so what an import brought can be found and looked over.
    pub fn import_labelled(&mut self, entries: Vec<NewEntry>, label: Option<&str>) -> Result<Merged> {
        let label = label.map(str::trim).filter(|l| !l.is_empty());
        let mut existing = Vec::with_capacity(self.index.len());
        for summary in &self.index {
            let entry = self.live(&summary.id)?;
            let key = Comparable::of(entry.kind, &entry.title, &entry.fields);
            existing.push((summary.id, key, false));
        }
        let mut merged = Merged::default();
        for new in entries {
            let key = Comparable::of(new.kind, &new.title, &new.fields);
            let Some(found) = existing.iter_mut().find(|(_, other, used)| !used && *other == key) else {
                let mut new = new;
                if let Some(label) = label {
                    let known = new.fields.iter().any(|field| {
                        field.name == field::TAG
                            && !field.custom
                            && field.value.eq_ignore_ascii_case(label.as_bytes())
                    });
                    if !known {
                        new.fields.push(Field {
                            name: field::TAG.into(),
                            value: label.as_bytes().to_vec(),
                            concealed: false,
                            custom: false,
                        });
                    }
                }
                self.add_entry(new);
                merged.added += 1;
                continue;
            };
            found.2 = true;
            merged.matched += 1;
            let id = found.0;
            let mut entry = self.live(&id)?;
            let mut tagged = false;
            for tag in new.fields.iter().filter(|field| field.name == field::TAG && !field.custom) {
                let known = entry.fields.iter().any(|field| {
                    field.name == field::TAG && !field.custom && field.value.eq_ignore_ascii_case(&tag.value)
                });
                if !known {
                    entry.fields.push(tag.clone());
                    tagged = true;
                }
            }
            if tagged {
                let fields = std::mem::take(&mut entry.fields);
                self.update_entry(&id, NewEntry { kind: entry.kind, title: entry.title.clone(), fields })?;
                merged.tagged += 1;
            }
        }
        Ok(merged)
    }

    /// Every live entry as `import` takes them — kind, title, fields — for moving the entries of
    /// one vault into another (a backup restored into the vault in use). Dates are not carried:
    /// the receiving vault gives its own. The values stay zeroed-on-drop fields.
    pub fn export_entries(&self) -> Result<Vec<NewEntry>> {
        self.index
            .iter()
            .map(|summary| {
                let entry = self.live(&summary.id)?;
                Ok(NewEntry { kind: entry.kind, title: entry.title.clone(), fields: entry.fields.clone() })
            })
            .collect()
    }

    /// Moves a live entry to Recently Deleted: whole, still sealed, out of `entries` (so out of
    /// search, AutoFill, the CLI, the SSH agent, passkeys, the audit and exports) and into
    /// `trashed`. Randomness: nonce (24).
    pub fn trash_entry(&mut self, id: &[u8; ENTRY_ID_LEN]) -> Result<()> {
        let position = self.index.iter().position(|summary| &summary.id == id).ok_or(VaultError::NotFound)?;
        let block = self.block_index(id)?;
        let mut entry = decrypt(&self.keys, self.version, &self.header.vault_id, &self.blocks[block])?;
        let now = self.entropy.now();
        entry.trashed_at = now.max(1);
        entry.updated_at = now.max(entry.updated_at);
        self.index.remove(position);
        self.trash.push(EntrySummary::new(*id, &entry));
        self.sort_by_block(true);
        self.blocks[block] = self.seal(*id, &entry);
        Ok(())
    }

    /// Brings an entry back from Recently Deleted, as it was. Randomness: nonce (24).
    pub fn restore_entry(&mut self, id: &[u8; ENTRY_ID_LEN]) -> Result<()> {
        let position = self.trash.iter().position(|summary| &summary.id == id).ok_or(VaultError::NotFound)?;
        let block = self.block_index(id)?;
        let mut entry = decrypt(&self.keys, self.version, &self.header.vault_id, &self.blocks[block])?;
        entry.trashed_at = 0;
        entry.updated_at = self.entropy.now().max(entry.updated_at);
        self.trash.remove(position);
        self.index.push(EntrySummary::new(*id, &entry));
        self.sort_by_block(false);
        self.blocks[block] = self.seal(*id, &entry);
        Ok(())
    }

    /// The entries in Recently Deleted, oldest block first; `trashed_at` says when each went.
    pub fn trashed(&self) -> &[EntrySummary] {
        &self.trash
    }

    /// Deletes for good the entries in Recently Deleted for `older_than` seconds or more (0:
    /// all of them — «Empty Recently Deleted»). Returns how many went.
    pub fn purge_trash(&mut self, older_than: u64) -> Result<usize> {
        let now = self.entropy.now();
        let due: Vec<[u8; ENTRY_ID_LEN]> = self
            .trash
            .iter()
            .filter(|summary| older_than == 0 || now.saturating_sub(summary.trashed_at) >= older_than)
            .map(|summary| summary.id)
            .collect();
        for id in &due {
            self.delete_entry(id)?;
        }
        Ok(due.len())
    }

    /// Replaces the entry — live or in Recently Deleted — with a tombstone: its kind and dates
    /// stay, the content goes. For good.
    pub fn delete_entry(&mut self, id: &[u8; ENTRY_ID_LEN]) -> Result<()> {
        let live = self.index.iter().position(|summary| &summary.id == id);
        let trashed = self.trash.iter().position(|summary| &summary.id == id);
        if live.is_none() && trashed.is_none() {
            return Err(VaultError::NotFound);
        }
        let block = self.block_index(id)?;
        let old = decrypt(&self.keys, self.version, &self.header.vault_id, &self.blocks[block])?;
        let tombstone = Entry {
            kind: old.kind,
            title: String::new(),
            fields: Vec::new(),
            created_at: old.created_at,
            updated_at: self.entropy.now(),
            used_at: 0,
            favorite: false,
            trashed_at: 0,
            deleted: true,
        };
        self.blocks[block] = self.seal(*id, &tombstone);
        if let Some(position) = live {
            self.index.remove(position);
        }
        if let Some(position) = trashed {
            self.trash.remove(position);
        }
        Ok(())
    }

    /// Merges `others` into `keep` (Merge N Entries): one entry stays, with `choice.title` and
    /// the password of `choice.password_from` (the kept entry's when `None`); every other
    /// password it differs from stays as a concealed custom field named
    /// `choice.previous_password`, a different one-time code as `choice.previous_code`. Sites,
    /// tags, notes, passkeys, links, custom and other fields come together, each once; the user
    /// name and picture are the kept entry's (another's when it has none). It is a favourite
    /// when any was; created when the first was, used when the last was. `others` go to Recently
    /// Deleted, and links to them now point to `keep`. Randomness: a nonce (24) per entry sealed.
    pub fn merge(
        &mut self,
        keep: &[u8; ENTRY_ID_LEN],
        others: &[[u8; ENTRY_ID_LEN]],
        choice: MergeChoice,
    ) -> Result<()> {
        let mut seen = vec![*keep];
        for id in others {
            if seen.contains(id) {
                return Err(VaultError::NotFound);
            }
            seen.push(*id);
        }
        if others.is_empty() {
            return Err(VaultError::NotFound);
        }
        let kept = self.live(keep)?;
        let rest = others.iter().map(|id| self.live(id)).collect::<Result<Vec<_>>>()?;
        let all: Vec<&Entry> = std::iter::once(&kept).chain(rest.iter()).collect();
        let merged_ids: Vec<String> = seen.iter().map(hex).collect();

        let password = |entry: &Entry| entry.field(field::PASSWORD).map(|f| f.value.clone());
        let from = choice.password_from.unwrap_or(*keep);
        let chosen = seen.iter().position(|id| *id == from).ok_or(VaultError::NotFound)?;
        let main = password(all[chosen]).or_else(|| all.iter().find_map(|entry| password(entry)));

        let mut fields: Vec<Field> = Vec::new();
        fn add(fields: &mut Vec<Field>, field: Field) {
            if !fields
                .iter()
                .any(|f| f.name == field.name && f.value == field.value && f.custom == field.custom)
            {
                fields.push(field);
            }
        }
        let has = |fields: &[Field], name: &str| fields.iter().any(|f| !f.custom && f.name == name);
        for (position, entry) in all.iter().enumerate() {
            for f in &entry.fields {
                let known = |name: &str| !f.custom && f.name == name;
                if known(field::PASSWORD) {
                    continue;
                }
                if choice.leave_out_of.iter().any(|(id, name)| *id == seen[position] && known(name)) {
                    continue;
                }
                if !f.custom
                    && !f.concealed
                    && choice.leave_out.iter().any(|(name, value)| *name == f.name && *value == f.value)
                {
                    continue;
                }
                if (known(field::LINK) || known(field::DISTINCT))
                    && merged_ids.iter().any(|id| id.as_bytes() == f.value.as_slice())
                {
                    continue;
                }
                if position > 0 {
                    if (known(field::USERNAME) || known(field::ICON)) && has(&fields, &f.name) {
                        continue;
                    }
                    if known(field::TOTP) && has(&fields, field::TOTP) {
                        if !fields.iter().any(|g| !g.custom && g.name == field::TOTP && g.value == f.value) {
                            add(
                                &mut fields,
                                Field {
                                    name: choice.previous_code.into(),
                                    value: f.value.clone(),
                                    concealed: true,
                                    custom: true,
                                },
                            );
                        }
                        continue;
                    }
                }
                add(&mut fields, f.clone());
            }
            if position == 0 {
                if let Some(main) = &main {
                    let at = fields
                        .iter()
                        .position(|f| !f.custom && f.name == field::USERNAME)
                        .map_or(0, |i| i + 1);
                    fields.insert(
                        at,
                        Field {
                            name: field::PASSWORD.into(),
                            value: main.clone(),
                            concealed: true,
                            custom: false,
                        },
                    );
                }
            }
        }
        for entry in &all {
            if let Some(other) = password(entry) {
                if main.as_ref() != Some(&other) {
                    add(
                        &mut fields,
                        Field {
                            name: choice.previous_password.into(),
                            value: other,
                            concealed: true,
                            custom: true,
                        },
                    );
                }
            }
        }

        let title = choice.title.trim();
        let entry = Entry {
            kind: kept.kind,
            title: if title.is_empty() { kept.title.clone() } else { title.to_owned() },
            fields,
            created_at: all.iter().map(|e| e.created_at).min().unwrap_or(kept.created_at),
            updated_at: self.entropy.now().max(kept.updated_at),
            used_at: all.iter().map(|e| e.used_at).max().unwrap_or(0),
            favorite: all.iter().any(|e| e.favorite),
            trashed_at: 0,
            deleted: false,
        };
        let position =
            self.index.iter().position(|summary| &summary.id == keep).ok_or(VaultError::NotFound)?;
        let block = self.block_index(keep)?;
        self.index[position] = EntrySummary::new(*keep, &entry);
        self.blocks[block] = self.seal(*keep, &entry);
        drop(entry);
        for id in others {
            self.trash_entry(id)?;
        }

        // Links to the merged-away entries now go to the kept one.
        let kept_hex = hex(keep);
        let gone: Vec<String> = others.iter().map(hex).collect();
        let linking: Vec<[u8; ENTRY_ID_LEN]> = self
            .index
            .iter()
            .filter(|s| &s.id != keep && s.links.iter().chain(&s.distinct).any(|l| gone.contains(l)))
            .map(|s| s.id)
            .collect();
        for id in linking {
            let entry = self.live(&id)?;
            let mut fields: Vec<Field> = Vec::new();
            for f in &entry.fields {
                let mut f = f.clone();
                if !f.custom
                    && (f.name == field::LINK || f.name == field::DISTINCT)
                    && gone.iter().any(|g| g.as_bytes() == f.value.as_slice())
                {
                    f.value = kept_hex.as_bytes().to_vec();
                }
                add(&mut fields, f);
            }
            self.update_entry(&id, NewEntry { kind: entry.kind, title: entry.title.clone(), fields })?;
        }
        Ok(())
    }

    /// Notes that two live entries with the same site and user name are different accounts:
    /// the audit stops offering them as duplicates. On both entries; their content stays.
    /// Randomness: a nonce (24) per entry changed.
    pub fn mark_distinct(&mut self, a: &[u8; ENTRY_ID_LEN], b: &[u8; ENTRY_ID_LEN]) -> Result<()> {
        if a == b {
            return Err(VaultError::NotFound);
        }
        self.live(a)?;
        self.live(b)?;
        for (id, other) in [(a, b), (b, a)] {
            let entry = self.live(id)?;
            let other = hex(other);
            if entry
                .fields
                .iter()
                .any(|f| !f.custom && f.name == field::DISTINCT && f.value == other.as_bytes())
            {
                continue;
            }
            let mut fields = entry.fields.clone();
            fields.push(Field {
                name: field::DISTINCT.into(),
                value: other.into_bytes(),
                concealed: false,
                custom: false,
            });
            self.update_entry(id, NewEntry { kind: entry.kind, title: entry.title.clone(), fields })?;
        }
        Ok(())
    }

    /// Takes back `mark_distinct`: the pair can be offered as duplicates again.
    pub fn forget_distinct(&mut self, a: &[u8; ENTRY_ID_LEN], b: &[u8; ENTRY_ID_LEN]) -> Result<()> {
        for (id, other) in [(a, b), (b, a)] {
            let Ok(entry) = self.live(id) else { continue };
            let other = hex(other);
            let mark = |f: &Field| !f.custom && f.name == field::DISTINCT && f.value == other.as_bytes();
            if !entry.fields.iter().any(mark) {
                continue;
            }
            let fields = entry.fields.iter().filter(|f| !mark(f)).cloned().collect();
            self.update_entry(id, NewEntry { kind: entry.kind, title: entry.title.clone(), fields })?;
        }
        Ok(())
    }

    /// Replaces a live entry's kind, title and fields. Its id, place and creation date stay;
    /// it is sealed again under a fresh nonce. Randomness: nonce (24).
    pub fn update_entry(&mut self, id: &[u8; ENTRY_ID_LEN], new: NewEntry) -> Result<()> {
        let position = self.index.iter().position(|summary| &summary.id == id).ok_or(VaultError::NotFound)?;
        let block = self.block_index(id)?;
        let old = decrypt(&self.keys, self.version, &self.header.vault_id, &self.blocks[block])?;
        let mut fields = new.fields;
        keep_history(&old.fields, &mut fields, self.entropy.now());
        let entry = Entry {
            kind: new.kind,
            title: new.title,
            fields,
            created_at: old.created_at,
            updated_at: self.entropy.now().max(old.updated_at),
            used_at: old.used_at,
            favorite: old.favorite,
            trashed_at: 0,
            deleted: false,
        };
        self.index[position] = EntrySummary::new(*id, &entry);
        self.blocks[block] = self.seal(*id, &entry);
        Ok(())
    }

    /// Notes that a live entry was used now (a value copied, its site opened), for «Recently
    /// Used». Its content and `updated_at` stay; it is sealed again under a fresh nonce.
    /// Randomness: nonce (24).
    pub fn mark_used(&mut self, id: &[u8; ENTRY_ID_LEN]) -> Result<()> {
        let position = self.index.iter().position(|summary| &summary.id == id).ok_or(VaultError::NotFound)?;
        let block = self.block_index(id)?;
        let mut entry = decrypt(&self.keys, self.version, &self.header.vault_id, &self.blocks[block])?;
        entry.used_at = self.entropy.now().max(entry.used_at);
        self.index[position] = EntrySummary::new(*id, &entry);
        self.blocks[block] = self.seal(*id, &entry);
        Ok(())
    }

    /// The fields of an entry — live or in Recently Deleted — in order, without concealed values.
    pub fn fields(&self, id: &[u8; ENTRY_ID_LEN]) -> Result<Vec<FieldSummary>> {
        let entry = self.readable(id)?;
        Ok(entry.fields.iter().map(FieldSummary::new).collect())
    }

    /// The field at `index` (as `fields` lists them) of an entry — live or in Recently Deleted,
    /// to be looked at before it is restored — decrypted for this call only. For entries with
    /// several fields of one name (sites, notes).
    pub fn secret_at(&self, id: &[u8; ENTRY_ID_LEN], index: usize) -> Result<SecretBytes> {
        let entry = self.readable(id)?;
        let field = entry.fields.get(index).ok_or(VaultError::NotFound)?;
        Ok(SecretBytes::new(field.value.clone()))
    }

    /// How strong the field at `index` is (a password): rated here, so it never leaves the core.
    pub fn strength(&self, id: &[u8; ENTRY_ID_LEN], index: usize) -> Result<crate::strength::Strength> {
        let entry = self.readable(id)?;
        let field = entry.fields.get(index).ok_or(VaultError::NotFound)?;
        let text = std::str::from_utf8(&field.value).map_err(|_| VaultError::NotFound)?;
        Ok(crate::strength::estimate(text))
    }

    /// Every live entry as a KDBX 4.0 file opened by `key` (ADR-0008): logins as KeePass has
    /// them, other kinds with DeepVault's field names and kind, tags as KeePass tags, files as
    /// binaries. Argon2id and ChaCha20; the caller writes it where the user chose.
    ///
    /// A v2 vault's files are read through `read` — the content of `files/<id>` for the ref —
    /// one at a time; a file `read` cannot give (not synced yet) is left out.
    pub fn export_kdbx(
        &mut self,
        key: &crate::kdbx::Key,
        read: &mut dyn FnMut(&FileRef) -> Result<SecretBytes>,
    ) -> Result<Vec<u8>> {
        let mut entries = Vec::with_capacity(self.index.len());
        for summary in &self.index {
            let entry = self.live(&summary.id)?;
            let mut fields = Vec::with_capacity(entry.fields.len());
            for f in &entry.fields {
                if f.custom || f.name != field::FILE {
                    fields.push(f.clone());
                    continue;
                }
                let Some(file) = FileRef::from_bytes(&f.value) else { continue };
                let Ok(content) = read(&file) else { continue };
                fields.push(Field {
                    name: field::ATTACHMENT.into(),
                    value: attachment_value(&file.name, content.expose()),
                    concealed: true,
                    custom: false,
                });
            }
            entries.push(crate::kdbx::ExportEntry {
                kind: entry.kind,
                title: entry.title.clone(),
                fields,
                created: entry.created_at,
                modified: entry.updated_at,
            });
        }
        crate::kdbx::write(&entries, key, self.entropy.as_mut())
    }

    /// The live entries whose words have `query` in them, ignoring case: the title, sites, user
    /// name, tags, notes (concealed or not), the names of custom fields and variables, and the
    /// values that are not concealed. Never passwords, codes, card numbers, keys or files — the
    /// search runs here, and only ids come out.
    pub fn search(&self, query: &str) -> Result<Vec<[u8; ENTRY_ID_LEN]>> {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let has =
            |bytes: &[u8]| std::str::from_utf8(bytes).is_ok_and(|text| text.to_lowercase().contains(&query));
        let mut found = Vec::new();
        for summary in &self.index {
            let entry = self.live(&summary.id)?;
            let matches = has(entry.title.as_bytes())
                || entry.fields.iter().any(|f| {
                    if f.custom {
                        has(f.name.as_bytes()) || (!f.concealed && has(&f.value))
                    } else if f.name == field::NOTES {
                        has(&f.value)
                    } else {
                        SEARCHED.contains(&f.name.as_str()) && !f.concealed && has(&f.value)
                    }
                });
            if matches {
                found.push(summary.id);
            }
        }
        Ok(found)
    }

    /// The password audit (PRD 05, Pro): every login's and password entry's `password`, how
    /// strong it is and which other entries share it — rated and compared here, so no password
    /// leaves the core. Generated passwords are left out: one in use is also in its login, and
    /// would be «reused» by itself. Entries in index order, fields in entry order.
    pub fn audit(&self) -> Vec<AuditItem> {
        let mut items = Vec::new();
        let mut values: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for summary in &self.index {
            // Changes not confirmed are a copy of an entry's password, not a reuse of it.
            if !matches!(summary.kind, EntryKind::Login | EntryKind::Password) || summary.unsaved_of.is_some()
            {
                continue;
            }
            let Ok(entry) = self.live(&summary.id) else { continue };
            for (index, field) in entry.fields.iter().enumerate() {
                if field.custom || field.name != field::PASSWORD || field.value.is_empty() {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(&field.value) else { continue };
                items.push(AuditItem {
                    id: summary.id,
                    index,
                    strength: crate::strength::estimate(text),
                    reused: None,
                });
                values.push(Zeroizing::new(field.value.clone()));
            }
        }
        // Groups of the same password in different entries, numbered from 0.
        let mut groups = 0;
        for first in 0..items.len() {
            if items[first].reused.is_some() {
                continue;
            }
            let same: Vec<usize> = (first + 1..items.len())
                .filter(|&other| {
                    items[other].reused.is_none()
                        && items[other].id != items[first].id
                        && values[other] == values[first]
                })
                .collect();
            if same.is_empty() {
                continue;
            }
            items[first].reused = Some(groups);
            for other in same {
                items[other].reused = Some(groups);
            }
            groups += 1;
        }
        items
    }

    /// The one-time code of the TOTP field at `index` at `unix_time` (of an entry live or in
    /// Recently Deleted). The secret stays here.
    pub fn totp(&self, id: &[u8; ENTRY_ID_LEN], index: usize, unix_time: u64) -> Result<crate::TotpCode> {
        let entry = self.readable(id)?;
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
        decrypt(&self.keys, self.version, &self.header.vault_id, block)
    }

    /// An entry that is live or in Recently Deleted, decrypted; for reading only.
    fn readable(&self, id: &[u8; ENTRY_ID_LEN]) -> Result<Entry> {
        if !self.trash.iter().any(|summary| &summary.id == id) {
            return self.live(id);
        }
        let block = &self.blocks[self.block_index(id)?];
        decrypt(&self.keys, self.version, &self.header.vault_id, block)
    }

    /// Puts the live entries (or those in Recently Deleted) back in block order.
    fn sort_by_block(&mut self, trash: bool) {
        let order: std::collections::HashMap<[u8; ENTRY_ID_LEN], usize> =
            self.blocks.iter().enumerate().map(|(position, block)| (block.entry_id, position)).collect();
        let list = if trash { &mut self.trash } else { &mut self.index };
        list.sort_by_key(|summary| order.get(&summary.id).copied().unwrap_or(usize::MAX));
    }

    fn block_index(&self, id: &[u8; ENTRY_ID_LEN]) -> Result<usize> {
        self.blocks.iter().position(|block| &block.entry_id == id).ok_or(VaultError::NotFound)
    }

    fn seal(&mut self, id: [u8; ENTRY_ID_LEN], entry: &Entry) -> Block {
        self.seal_as(self.version, id, entry)
    }
}

/// What `Vault::merge` keeps where the entries differ.
pub struct MergeChoice<'a> {
    pub title: &'a str,
    /// The entry whose password the merged one keeps; `None`: the kept entry's.
    pub password_from: Option<[u8; ENTRY_ID_LEN]>,
    /// The name, in the user's language, of the custom field each other password goes to.
    pub previous_password: &'a str,
    /// The same for a different one-time code.
    pub previous_code: &'a str,
    /// Visible values the user took out (a site, a tag): `(field name, value)`, left out of the
    /// merged entry wherever they come from.
    pub leave_out: &'a [(String, Vec<u8>)],
    /// Fields one entry does not bring, whatever their value — its notes, which may be
    /// concealed and are never read out to compare: `(entry, field name)`.
    pub leave_out_of: &'a [([u8; ENTRY_ID_LEN], String)],
}

/// An id as the index writes links: 32 lowercase hex digits.
fn hex(id: &[u8; ENTRY_ID_LEN]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// What `Vault::import` did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Merged {
    /// New entries.
    pub added: usize,
    /// Entries the vault had already, left as they are…
    pub matched: usize,
    /// …of which these got the import's tags.
    pub tagged: usize,
}

/// What `Vault::merge_file` did, for a line such as «Updated from Mac — 3 new · 1 changed»:
/// counts only, never a title or a value.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeReport {
    /// Entries live now that were not: new on the other side, or restored there.
    pub added: usize,
    /// Live entries whose content is now the other side's, or both sides' merged.
    pub changed: usize,
    /// Entries live before that are now in Recently Deleted or deleted for good.
    pub removed: usize,
    /// Entries (and the header) the other copy does not have as they are now: write the merged
    /// vault so that it gets them. 0: the other copy already is the merge.
    pub outgoing: usize,
}

impl MergeReport {
    /// Whether anything shown changed.
    pub fn is_empty(&self) -> bool {
        self.added == 0 && self.changed == 0 && self.removed == 0
    }

    fn count(&mut self, before: Option<&Entry>, after: &Entry) {
        let live = |entry: &Entry| !entry.deleted && entry.trashed_at == 0;
        match (before.is_some_and(live), live(after)) {
            (false, true) => self.added += 1,
            (true, false) => self.removed += 1,
            (true, true) => {
                if !same_content(before.expect("live"), after) {
                    self.changed += 1;
                }
            }
            (false, false) => {}
        }
    }
}

/// An entry as an import would bring it, for telling whether the vault has it: its kind,
/// title and fields sorted, without tags, the picture and links; a site without its scheme
/// and trailing slash (`gmail.com` is saved as `https://gmail.com`). Zeroed on drop.
#[derive(PartialEq, Eq)]
struct Comparable {
    kind: EntryKind,
    title: String,
    fields: Vec<(String, Zeroizing<Vec<u8>>, bool)>,
}

impl Comparable {
    fn of(kind: EntryKind, title: &str, fields: &[Field]) -> Self {
        let mut compared: Vec<_> = fields
            .iter()
            .filter(|field| {
                field.custom || ![field::TAG, field::ICON, field::LINK].contains(&field.name.as_str())
            })
            .map(|field| {
                let mut value = Zeroizing::new(field.value.clone());
                if !field.custom && field.name == field::URL {
                    let site = value.strip_prefix(b"https://").or_else(|| value.strip_prefix(b"http://"));
                    let site = site.unwrap_or(&value);
                    let site = site.strip_suffix(b"/").unwrap_or(site);
                    value = Zeroizing::new(site.to_ascii_lowercase());
                }
                (field.name.clone(), value, field.custom)
            })
            .collect();
        compared.sort_by(|a, b| (&a.0, a.1.as_slice(), a.2).cmp(&(&b.0, b.1.as_slice(), b.2)));
        Self { kind, title: title.trim().to_owned(), fields: compared }
    }
}

/// A block that does not authenticate is damaged; one that does but is no entry this core
/// reads was written, with this vault's key, by a newer DeepVault (a field added since): only
/// that writer could have made it, and an older one must not rewrite what it cannot read.
/// The live entries and those in Recently Deleted of `blocks`, in block order; tombstones left out.
fn index_blocks(
    keys: &Subkeys,
    version: u16,
    vault_id: &[u8; VAULT_ID_LEN],
    blocks: &[Block],
) -> Result<(Vec<EntrySummary>, Vec<EntrySummary>)> {
    let mut index = Vec::new();
    let mut trash = Vec::new();
    for block in blocks {
        let entry = decrypt(keys, version, vault_id, block)?;
        if entry.deleted {
            continue;
        }
        let summary = EntrySummary::new(block.entry_id, &entry);
        if entry.trashed_at == 0 {
            index.push(summary)
        } else {
            trash.push(summary)
        }
    }
    Ok((index, trash))
}

/// The same kind, title and fields, in order: what the entry says, not its state.
fn same_content(a: &Entry, b: &Entry) -> bool {
    a.kind == b.kind
        && a.title == b.title
        && a.fields.len() == b.fields.len()
        && a.fields.iter().zip(&b.fields).all(|(x, y)| {
            x.name == y.name && x.value == y.value && x.concealed == y.concealed && x.custom == y.custom
        })
}

/// The same sealed bytes: the entry was not sealed again since (every change takes a new nonce).
fn same_block(a: &Block, b: &Block) -> bool {
    a.nonce == b.nonce && a.ciphertext == b.ciphertext
}

/// One entry changed on both sides (ADR-0016). The version changed last wins — at the same
/// second, a live one over a tombstone, then the greater CBOR, so both devices pick the same.
/// The other one's password and one-time code go to the winner's history. A tombstone winning
/// over an entry that was changed and not deleted there sends that entry to Recently Deleted:
/// deleted for good only where it was seen deleted. Used when either side last was; starred as
/// the side that changed the star since `base` has it (a star does not change `updated_at`).
fn resolve(a: &Entry, b: &Entry, base: Option<&Entry>) -> Entry {
    // Only one side changed what the entry says; the other only its state (a star, Recently
    // Deleted, a use): the content of the one, the state merged — at any second.
    if let Some(base) = base.filter(|base| !base.deleted && !a.deleted && !b.deleted) {
        let (a_edited, b_edited) = (!same_content(a, base), !same_content(b, base));
        if a_edited != b_edited {
            let (editor, other) = if a_edited { (a, b) } else { (b, a) };
            let mut merged = editor.clone();
            merged.used_at = a.used_at.max(b.used_at);
            merged.favorite = if a.favorite != base.favorite { a.favorite } else { b.favorite };
            // Moved to or out of Recently Deleted on the other side after the edit: as it says.
            if other.trashed_at != base.trashed_at && other.updated_at >= editor.updated_at {
                merged.trashed_at = other.trashed_at;
            }
            merged.updated_at = a.updated_at.max(b.updated_at);
            return merged;
        }
    }
    let key = |entry: &Entry| (entry.updated_at, !entry.deleted);
    let a_wins = match key(a).cmp(&key(b)) {
        std::cmp::Ordering::Equal => a.to_cbor()[..] >= b.to_cbor()[..],
        order => order.is_gt(),
    };
    let (winner, loser) = if a_wins { (a, b) } else { (b, a) };
    if winner.deleted {
        if loser.deleted || loser.field(field::UNSAVED).is_some() {
            return winner.clone();
        }
        let mut rescued = loser.clone();
        rescued.trashed_at = winner.updated_at.max(1);
        rescued.updated_at = winner.updated_at;
        return rescued;
    }
    let mut merged = winner.clone();
    merged.used_at = a.used_at.max(b.used_at);
    // A star is no change (`updated_at` stays): the side that starred or unstarred it since the
    // base says; both did — the same.
    if let Some(base) = base.filter(|base| !base.deleted && !a.deleted && !b.deleted) {
        merged.favorite = if a.favorite != base.favorite { a.favorite } else { b.favorite };
    }
    if !loser.deleted {
        merge_history(&mut merged.fields, loser, winner.updated_at);
    }
    merged
}

/// `name` and value of a `previous` field (`<name>\n<seconds>\n<value>`), with its time.
fn previous_parts(field: &Field) -> Option<(&[u8], u64, &[u8])> {
    if field.custom || field.name != field::PREVIOUS {
        return None;
    }
    let mut parts = field.value.splitn(3, |byte| *byte == b'\n');
    let name = parts.next()?;
    let time = std::str::from_utf8(parts.next()?).ok()?.parse().ok()?;
    Some((name, time, parts.next()?))
}

/// Adds to `fields` (the winner's) the loser's password and one-time code — when they differ
/// from the winner's and its history has them not — as values replaced at `replaced_at` (the
/// winner's change, so the newest in its history and not the first cut),
/// and the values of the loser's history the winner's lacks. Then the history is ordered by time and cut to
/// `HISTORY_LEN` of each field, as `keep_history` keeps it. Nothing added: `fields` stay as
/// they are.
fn merge_history(fields: &mut Vec<Field>, loser: &Entry, replaced_at: u64) {
    let mut added = false;
    for name in field::KEPT_HISTORY {
        let Some(value) = loser.field(name).map(|f| &f.value).filter(|value| !value.is_empty()) else {
            continue;
        };
        let current = fields.iter().find(|f| !f.custom && f.name == name).map(|f| &f.value);
        let known = current == Some(value)
            || fields
                .iter()
                .filter_map(previous_parts)
                .any(|(of, _, old)| of == name.as_bytes() && old == &value[..]);
        if known {
            continue;
        }
        let mut previous = format!("{name}\n{replaced_at}\n").into_bytes();
        previous.extend_from_slice(value);
        fields.push(Field { name: field::PREVIOUS.into(), value: previous, concealed: true, custom: false });
        added = true;
    }
    for old in loser.fields.iter() {
        let Some((name, _, value)) = previous_parts(old) else { continue };
        if !fields.iter().filter_map(previous_parts).any(|(of, _, known)| of == name && known == value) {
            fields.push(old.clone());
            added = true;
        }
    }
    if !added {
        return;
    }
    let mut history = Vec::new();
    let mut position = 0;
    while position < fields.len() {
        if previous_parts(&fields[position]).is_some() {
            history.push(fields.remove(position));
        } else {
            position += 1;
        }
    }
    let order = |f: &Field| previous_parts(f).map(|(_, time, _)| time).unwrap_or(0);
    history.sort_by(|x, y| (order(x), &x.value).cmp(&(order(y), &y.value)));
    for name in field::KEPT_HISTORY {
        let of_name = |f: &Field| previous_parts(f).is_some_and(|(of, _, _)| of == name.as_bytes());
        let mut extra = history.iter().filter(|f| of_name(f)).count().saturating_sub(field::HISTORY_LEN);
        history.retain(|f| {
            if extra > 0 && of_name(f) {
                extra -= 1;
                return false;
            }
            true
        });
    }
    fields.extend(history);
}

fn decrypt(keys: &Subkeys, version: u16, vault_id: &[u8; VAULT_ID_LEN], block: &Block) -> Result<Entry> {
    let aad = keys::aad_for(version, "entry", vault_id, &block.entry_id);
    let plaintext =
        aead::open(&keys.entries, &block.nonce, &block.ciphertext, &aad).ok_or(VaultError::Corrupted)?;
    Entry::from_cbor(plaintext.expose()).ok_or(VaultError::NewerEntries)
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

/// The password or one-time code changed (or went): its value before is kept as a
/// `field::PREVIOUS`, dated `now`; past `HISTORY_LEN` of a field the oldest go. The earlier ones
/// come in `new` as the app read them (its draft keeps fields it does not show).
fn keep_history(old: &[Field], new: &mut Vec<Field>, now: u64) {
    let known = |fields: &[Field], name: &str| -> Option<Vec<u8>> {
        fields.iter().find(|field| !field.custom && field.name == name).map(|field| field.value.clone())
    };
    for name in field::KEPT_HISTORY {
        let before = Zeroizing::new(known(old, name).unwrap_or_default());
        let after = Zeroizing::new(known(new, name).unwrap_or_default());
        if before.is_empty() || before == after {
            continue;
        }
        let mut value = format!("{name}\n{now}\n").into_bytes();
        value.extend_from_slice(&before);
        new.push(Field { name: field::PREVIOUS.into(), value, concealed: true, custom: false });
    }
    for name in field::KEPT_HISTORY {
        let prefix = format!("{name}\n");
        let of_name: Vec<usize> = new
            .iter()
            .enumerate()
            .filter(|(_, field)| {
                !field.custom && field.name == field::PREVIOUS && field.value.starts_with(prefix.as_bytes())
            })
            .map(|(index, _)| index)
            .collect();
        let extra = of_name.len().saturating_sub(field::HISTORY_LEN);
        for index in of_name.into_iter().take(extra).rev() {
            // A field is zeroed on drop.
            drop(new.remove(index));
        }
    }
}

/// Files outside the vault file (format v2, ADR-0014): what entries say about them. The core
/// keeps no file system: `files/<id>` is read and written by the caller, through `FileWriter`,
/// `FileReader` and the callbacks here.
impl Vault {
    /// `VERSION` (2), or 1 for a vault read from a v1 file that has not moved yet.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// A writer for a new file of this vault: seal its content into `files/<id>`, then put its
    /// ref in an entry (`add_file`, or a `file` field in `update_entry`). Randomness: file id
    /// (16), key (32), nonce prefix (19).
    pub fn file_writer(&mut self, name: &str) -> FileWriter {
        FileWriter::new(&mut *self.entropy, self.header.vault_id, name, CHUNK_SIZE)
    }

    /// `file_writer` with chunks of `chunk_size` bytes, for test vectors.
    #[cfg(feature = "testing")]
    pub fn file_writer_chunked(&mut self, name: &str, chunk_size: usize) -> FileWriter {
        FileWriter::new(&mut *self.entropy, self.header.vault_id, name, chunk_size)
    }

    /// The `file` fields of an entry, live or in Recently Deleted: each one's position (as
    /// `fields` lists them) and ref.
    pub fn files(&self, id: &[u8; ENTRY_ID_LEN]) -> Result<Vec<(usize, FileRef)>> {
        let entry = self.readable(id)?;
        Ok(entry
            .fields
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.custom && f.name == field::FILE)
            .filter_map(|(index, f)| FileRef::from_bytes(&f.value).map(|file| (index, file)))
            .collect())
    }

    /// The ref of the `file` field at `index`. `NotFound` when it is no such field.
    pub fn file_at(&self, id: &[u8; ENTRY_ID_LEN], index: usize) -> Result<FileRef> {
        let entry = self.readable(id)?;
        let f = entry.fields.get(index).ok_or(VaultError::NotFound)?;
        if f.custom || f.name != field::FILE {
            return Err(VaultError::NotFound);
        }
        FileRef::from_bytes(&f.value).ok_or(VaultError::NotFound)
    }

    /// Adds a file written with `file_writer` to a live entry, after its other fields. Only a v2
    /// vault keeps files outside: `UnsupportedVersion(1)` for a v1 one. Randomness: nonce (24).
    pub fn add_file(&mut self, id: &[u8; ENTRY_ID_LEN], file: &FileRef) -> Result<()> {
        if self.version != VERSION {
            return Err(VaultError::UnsupportedVersion(self.version));
        }
        let old = self.live(id)?;
        let mut fields = old.fields.clone();
        fields.push(file_field(file));
        self.update_entry(id, NewEntry { kind: old.kind, title: old.title.clone(), fields })
    }

    /// Takes the file `file_id` out of a live entry. Its `files/<id>` stays until nothing refers
    /// to it for a week (`referenced_files`): a sync may bring the entry back. Randomness: nonce (24).
    pub fn remove_file(&mut self, id: &[u8; ENTRY_ID_LEN], file_id: &[u8; FILE_ID_LEN]) -> Result<()> {
        let old = self.live(id)?;
        let mut fields = old.fields.clone();
        let before = fields.len();
        fields.retain(|f| {
            f.custom
                || f.name != field::FILE
                || FileRef::from_bytes(&f.value).is_none_or(|r| &r.id != file_id)
        });
        if fields.len() == before {
            return Err(VaultError::NotFound);
        }
        self.update_entry(id, NewEntry { kind: old.kind, title: old.title.clone(), fields })
    }

    /// Every file an entry refers to — live, in Recently Deleted, or a copy of changes not
    /// confirmed (Unsaved) — once each: what `files/` must keep. Any other file there is left
    /// over, and goes when it is a week old.
    pub fn referenced_files(&self) -> Result<Vec<[u8; FILE_ID_LEN]>> {
        let mut ids = Vec::new();
        for block in &self.blocks {
            let entry = decrypt(&self.keys, self.version, &self.header.vault_id, block)?;
            for f in entry.fields.iter().filter(|f| !f.custom && f.name == field::FILE) {
                if let Some(file) = FileRef::from_bytes(&f.value) {
                    if !ids.contains(&file.id) {
                        ids.push(file.id);
                    }
                }
            }
        }
        Ok(ids)
    }

    /// Moves a v1 vault to v2 (ADR-0014): every `attachment` field, live or in Recently Deleted,
    /// becomes a `file` field, its content sealed into a file handed to `write` (`files/<id>`,
    /// whole: a v1 file is at most 10 MiB); every entry is sealed again with v2's AAD. Kinds,
    /// titles, dates and the order of fields stay. All or nothing: when `write` fails, the vault
    /// stays v1 as it was (files written before stay over, for the clean-up). Returns how many
    /// files moved; 0 and nothing done for a v2 vault. Randomness: per file id (16), key (32),
    /// nonce prefix (19); per entry nonce (24).
    pub fn upgrade(&mut self, write: &mut WriteFile<'_>) -> Result<usize> {
        if self.version == VERSION {
            return Ok(0);
        }
        let mut moved = 0;
        let mut blocks = Vec::with_capacity(self.blocks.len());
        for block in self.blocks.clone() {
            let mut entry = decrypt(&self.keys, self.version, &self.header.vault_id, &block)?;
            moved += self.move_attachments(&mut entry.fields, write)?;
            blocks.push(self.seal_as(VERSION, block.entry_id, &entry));
        }
        self.blocks = blocks;
        self.version = VERSION;
        Ok(moved)
    }

    /// An import's `attachment` fields (KeePass, a v1 backup) as files of this v2 vault, each
    /// sealed into a file handed to `write`, before `import`. A v1 vault leaves them as they are.
    pub fn externalize(&mut self, entries: &mut [NewEntry], write: &mut WriteFile<'_>) -> Result<usize> {
        if self.version != VERSION {
            return Ok(0);
        }
        let mut moved = 0;
        for entry in entries.iter_mut() {
            moved += self.move_attachments(&mut entry.fields, write)?;
        }
        Ok(moved)
    }

    fn move_attachments(&mut self, fields: &mut [Field], write: &mut WriteFile<'_>) -> Result<usize> {
        let mut moved = 0;
        for f in fields.iter_mut().filter(|f| !f.custom && f.name == field::ATTACHMENT) {
            let (name, content) = attachment_parts(&f.value);
            let mut writer = self.file_writer(&name);
            let mut sealed = writer.header();
            sealed.extend(writer.update(content)?);
            let (last, file) = writer.finish()?;
            sealed.extend(last);
            write(&file.id, &sealed)?;
            *f = file_field(&file);
            moved += 1;
        }
        Ok(moved)
    }

    fn seal_as(&mut self, version: u16, id: [u8; ENTRY_ID_LEN], entry: &Entry) -> Block {
        let mut nonce = [0; NONCE_LEN];
        self.entropy.fill(&mut nonce);
        let aad = keys::aad_for(version, "entry", &self.header.vault_id, &id);
        let ciphertext = aead::seal(&self.keys.entries, &nonce, &entry.to_cbor(), &aad);
        Block { entry_id: id, nonce, ciphertext }
    }

    /// `Corrupted` unless `file` is a file of this vault: its id, and MACs under its keys.
    pub(crate) fn verify_file(&self, file: &[u8]) -> Result<()> {
        let raw = format::parse(file)?;
        if raw.header.vault_id != self.header.vault_id
            || !keys::verify_mac(&self.keys.header_mac, raw.header_region, raw.header_mac)
            || !keys::verify_mac(&self.keys.file_mac, raw.file_region, raw.file_mac)
        {
            return Err(VaultError::Corrupted);
        }
        Ok(())
    }

    /// For `pack`: the vault file's keys.
    pub(crate) fn subkeys(&self) -> &Subkeys {
        &self.keys
    }
}

/// Where a new file's bytes go: `files/<id>`, written whole by the caller.
pub type WriteFile<'a> = dyn FnMut(&[u8; FILE_ID_LEN], &[u8]) -> Result<()> + 'a;

/// A `file` field for a ref.
fn file_field(file: &FileRef) -> Field {
    Field { name: field::FILE.into(), value: file.to_bytes().to_vec(), concealed: true, custom: false }
}

/// A v1 `attachment` value's name and content; a value without a zero byte is all content.
fn attachment_parts(value: &[u8]) -> (String, &[u8]) {
    match value.iter().position(|&b| b == 0) {
        Some(at) => (String::from_utf8_lossy(&value[..at]).into_owned(), &value[at + 1..]),
        None => (String::new(), value),
    }
}

/// `name ‖ 0x00 ‖ content`, in a buffer of its exact size.
fn attachment_value(name: &str, content: &[u8]) -> Vec<u8> {
    let name = name.replace('\0', "");
    let mut value = Vec::with_capacity(name.len() + 1 + content.len());
    value.extend_from_slice(name.as_bytes());
    value.push(0);
    value.extend_from_slice(content);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with_one_entry() -> Vault {
        let mut vault = Vault::create(b"pw", KdfParams::MINIMUM).expect("vault");
        vault.add_entry(NewEntry { kind: EntryKind::Note, title: "note".into(), fields: Vec::new() });
        vault
    }

    /// An entry a newer DeepVault wrote — sealed with this vault's key, with a field this core
    /// does not know — is «update the app», not «damaged»: an older app reading a file the
    /// newer one saved (Recently Deleted's `trashed_at`, 30 October) told the person it was broken.
    #[test]
    fn an_entry_with_a_field_added_later_is_newer_not_damaged() {
        let mut vault = vault_with_one_entry();
        let block = &vault.blocks[0];
        let aad = keys::aad_for(vault.version, "entry", &vault.header.vault_id, &block.entry_id);
        let plain = aead::open(&vault.keys.entries, &block.nonce, &block.ciphertext, &aad).expect("opens");
        let mut value: ciborium::Value = ciborium::from_reader(plain.expose()).expect("cbor");
        if let ciborium::Value::Map(fields) = &mut value {
            fields.push((ciborium::Value::Text("added_later".into()), ciborium::Value::Integer(1.into())));
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).expect("cbor");
        let sealed = aead::seal(&vault.keys.entries, &block.nonce, &bytes, &aad);
        vault.blocks[0].ciphertext = sealed;
        assert_eq!(Vault::open(&vault.to_bytes(), b"pw").err(), Some(VaultError::NewerEntries));

        // A changed byte in a block is still damage.
        let mut damaged = vault_with_one_entry();
        let last = damaged.blocks[0].ciphertext.len() - 1;
        damaged.blocks[0].ciphertext[last] ^= 1;
        let file = damaged.to_bytes();
        assert_eq!(Vault::open(&file, b"pw").err(), Some(VaultError::Corrupted));
    }

    /// A password or one-time code changed keeps the value before, dated, the last ten of each;
    /// a save that leaves them as they were keeps nothing new.
    #[test]
    fn the_values_before_a_change_are_kept_ten_of_each() {
        let field = |name: &str, value: &str| Field {
            name: name.into(),
            value: value.as_bytes().to_vec(),
            concealed: true,
            custom: false,
        };
        let mut vault = Vault::create(b"pw", KdfParams::MINIMUM).expect("vault");
        let id = vault.add_entry(NewEntry {
            kind: EntryKind::Login,
            title: "router".into(),
            fields: vec![field(field::PASSWORD, "first")],
        });
        // As the app saves: the fields it shows, then the ones it kept (`others`).
        let save = |vault: &mut Vault, password: &str, totp: Option<&str>| {
            let kept: Vec<Field> = vault
                .readable(&id)
                .expect("entry")
                .fields
                .iter()
                .filter(|f| f.name == field::PREVIOUS)
                .map(|f| Field {
                    name: f.name.clone(),
                    value: f.value.clone(),
                    concealed: true,
                    custom: false,
                })
                .collect();
            let mut fields = vec![field(field::PASSWORD, password)];
            fields.extend(totp.map(|code| field(field::TOTP, code)));
            fields.extend(kept);
            vault
                .update_entry(&id, NewEntry { kind: EntryKind::Login, title: "router".into(), fields })
                .expect("update");
        };
        let history = |vault: &Vault| -> Vec<String> {
            vault
                .readable(&id)
                .expect("entry")
                .fields
                .iter()
                .filter(|f| f.name == field::PREVIOUS)
                .map(|f| {
                    let text = String::from_utf8(f.value.clone()).expect("utf-8");
                    let mut parts = text.splitn(3, '\n');
                    let (name, when, value) =
                        (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
                    assert!(when.parse::<u64>().is_ok());
                    format!("{name}:{value}")
                })
                .collect()
        };
        save(&mut vault, "first", None);
        assert!(history(&vault).is_empty());
        save(&mut vault, "second", Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(history(&vault), ["password:first"]);
        save(&mut vault, "second", None);
        assert_eq!(history(&vault), ["password:first", "totp:JBSWY3DPEHPK3PXP"]);
        for n in 0..12 {
            save(&mut vault, &format!("p{n}"), None);
        }
        let kept = history(&vault);
        let passwords: Vec<&String> = kept.iter().filter(|h| h.starts_with("password:")).collect();
        assert_eq!(passwords.len(), field::HISTORY_LEN);
        assert_eq!(passwords.last().map(|s| s.as_str()), Some("password:p10"));
        assert!(kept.contains(&"totp:JBSWY3DPEHPK3PXP".to_string()));
    }

    /// Changes kept instead of written over an entry: the copy says whose it is (an empty id
    /// for a new entry), survives a save, and is not a reused password in the audit. A field
    /// of the user's own named so is only a label.
    #[test]
    fn an_unsaved_copy_says_whose_it_is_and_is_not_a_reuse() {
        let field = |name: &str, value: &str, custom: bool| Field {
            name: name.into(),
            value: value.as_bytes().to_vec(),
            concealed: name == field::PASSWORD,
            custom,
        };
        let mut vault = Vault::create(b"pw", KdfParams::MINIMUM).expect("vault");
        let original = vault.add_entry(NewEntry {
            kind: EntryKind::Login,
            title: "site".into(),
            fields: vec![field(field::PASSWORD, "hunter2-long-enough", false)],
        });
        let of = original.iter().map(|b| format!("{b:02x}")).collect::<String>();
        vault.add_entry(NewEntry {
            kind: EntryKind::Login,
            title: "site".into(),
            fields: vec![
                field(field::PASSWORD, "hunter2-long-enough", false),
                field(field::UNSAVED, &of, false),
            ],
        });
        vault.add_entry(NewEntry {
            kind: EntryKind::Note,
            title: "new".into(),
            fields: vec![field(field::UNSAVED, "", false)],
        });
        vault.add_entry(NewEntry {
            kind: EntryKind::Note,
            title: "mine".into(),
            fields: vec![field(field::UNSAVED, "x", true)],
        });

        let reopened = Vault::open(&vault.to_bytes(), b"pw").expect("opens");
        let marks: Vec<Option<String>> = reopened.entries().iter().map(|e| e.unsaved_of.clone()).collect();
        assert_eq!(marks, vec![None, Some(of), Some(String::new()), None]);
        assert!(reopened.audit().iter().all(|item| item.reused.is_none()));
    }
}
