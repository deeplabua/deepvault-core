//! An unlocked vault. Locking is dropping it: the vault key, the subkeys and the entry index
//! are zeroed on drop.

use crate::aead::{self, NONCE_LEN};
use crate::entropy::{Entropy, SystemEntropy};
use crate::entry::{field, Entry, EntryKind, EntrySummary, Field, FieldSummary, NewEntry};
use crate::error::{Result, VaultError};
use crate::format::{self, Block, Header, KdfHeader, SlotHeader, ENTRY_ID_LEN};
use crate::kdf::{self, KdfParams, SALT_LEN};
use crate::keys::{self, SlotKind, Subkeys, VAULT_ID_LEN, WRAPPED_VK_LEN};
use crate::secret::{Key, SecretBytes};
use zeroize::Zeroizing;

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
        let mut entry =
            decrypt(&self.keys, &self.header.vault_id, &self.blocks[block]).ok_or(VaultError::Corrupted)?;
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
        self.add_ssh_entry(title, &key)
    }

    /// An SSH key from its `-----BEGIN OPENSSH PRIVATE KEY-----` text (unencrypted ed25519);
    /// stored re-encoded, so the vault holds one canonical form.
    pub fn import_ssh_key(&mut self, title: &str, private_key: &[u8]) -> Result<[u8; ENTRY_ID_LEN]> {
        let text = std::str::from_utf8(private_key).map_err(|_| VaultError::InvalidSshKey)?;
        let key = crate::ssh::Ed25519Key::from_openssh(text)?;
        Ok(self.add_ssh_entry(title, &key))
    }

    fn add_ssh_entry(&mut self, title: &str, key: &crate::ssh::Ed25519Key) -> [u8; ENTRY_ID_LEN] {
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

    /// The signature of `data` by the SSH key of a live `ssh_key` entry, in the SSH wire format.
    /// The private key is read, used and zeroed here.
    pub fn ssh_sign(&self, id: &[u8; ENTRY_ID_LEN], data: &[u8]) -> Result<Vec<u8>> {
        let entry = self.live(id)?;
        if entry.kind != EntryKind::SshKey {
            return Err(VaultError::NotFound);
        }
        let field = entry.field(field::SSH_PRIVATE_KEY).ok_or(VaultError::NotFound)?;
        let text = std::str::from_utf8(&field.value).map_err(|_| VaultError::InvalidSshKey)?;
        Ok(crate::ssh::Ed25519Key::from_openssh(text)?.sign(data))
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
            used_at: 0,
            favorite: false,
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
            used_at: old.used_at,
            favorite: old.favorite,
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
        let mut entry =
            decrypt(&self.keys, &self.header.vault_id, &self.blocks[block]).ok_or(VaultError::Corrupted)?;
        entry.used_at = self.entropy.now().max(entry.used_at);
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

    /// How strong the field at `index` is (a password): rated here, so it never leaves the core.
    pub fn strength(&self, id: &[u8; ENTRY_ID_LEN], index: usize) -> Result<crate::strength::Strength> {
        let entry = self.live(id)?;
        let field = entry.fields.get(index).ok_or(VaultError::NotFound)?;
        let text = std::str::from_utf8(&field.value).map_err(|_| VaultError::NotFound)?;
        Ok(crate::strength::estimate(text))
    }

    /// Every live entry as a KDBX 4.0 file opened by `key` (ADR-0008): logins as KeePass has
    /// them, other kinds with DeepVault's field names and kind, tags as KeePass tags, files as
    /// binaries. Argon2id and ChaCha20; the caller writes it where the user chose.
    pub fn export_kdbx(&mut self, key: &crate::kdbx::Key) -> Result<Vec<u8>> {
        let mut entries = Vec::with_capacity(self.index.len());
        for summary in &self.index {
            let entry = self.live(&summary.id)?;
            entries.push(crate::kdbx::ExportEntry {
                kind: entry.kind,
                title: entry.title.clone(),
                fields: entry.fields.clone(),
                created: entry.created_at,
                modified: entry.updated_at,
            });
        }
        crate::kdbx::write(&entries, key, self.entropy.as_mut())
    }

    /// The password audit (PRD 05, Pro): every login's and password entry's `password`, how
    /// strong it is and which other entries share it — rated and compared here, so no password
    /// leaves the core. Generated passwords are left out: one in use is also in its login, and
    /// would be «reused» by itself. Entries in index order, fields in entry order.
    pub fn audit(&self) -> Vec<AuditItem> {
        let mut items = Vec::new();
        let mut values: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for summary in &self.index {
            if !matches!(summary.kind, EntryKind::Login | EntryKind::Password) {
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
