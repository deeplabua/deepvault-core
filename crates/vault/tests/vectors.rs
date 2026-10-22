//! Format v1 test vectors (`core/tests/vectors/v1_sample.json`) and the committed sample file
//! (`core/tests/fixtures/v1_sample.dvault`).
//!
//! Every intermediate value is recomputed from the vector's inputs and compared; the whole
//! file is recreated byte for byte; and the committed file must keep opening — the backward
//! compatibility test. Once committed, these files never change: a format change is v2 with
//! vectors of its own.
//!
//! KDF parameters here are `test_only` (8 MiB, 1 pass): the app refuses them.

mod common;

use common::{array, hex, shared, unhex};
use serde_json::{json, Value};
use vault::keys::{self, SlotKind, Subkeys};
use vault::testing::{entry_plaintext, ScriptedEntropy};
use vault::{aead, field, kdf, EntryKind, Field, KdfParams, Key, NewEntry, Vault};

const VECTOR: &str = "vectors/v1_sample.json";
const FIXTURE: &str = "fixtures/v1_sample.dvault";

struct Inputs {
    password: Vec<u8>,
    params: KdfParams,
    salt: [u8; 16],
    vault_id: [u8; 16],
    vk: [u8; 32],
    slot_nonce: [u8; 24],
    now: u64,
    entry_id: [u8; 16],
    entry_nonce: [u8; 24],
    entry: Value,
}

impl Inputs {
    fn from(vector: &Value) -> Self {
        let input = &vector["input"];
        let text = |key: &str| input[key].as_str().expect(key);
        let kdf = &input["kdf"];
        let number = |key: &str| kdf[key].as_u64().expect(key) as u32;
        Self {
            password: text("password").as_bytes().to_vec(),
            params: KdfParams { m_kib: number("m_kib"), t: number("t"), p: number("p") },
            salt: array(kdf["salt"].as_str().unwrap()),
            vault_id: array(text("vault_id")),
            vk: array(text("vault_key")),
            slot_nonce: array(text("slot_nonce")),
            now: input["now"].as_u64().unwrap(),
            entry_id: array(text("entry_id")),
            entry_nonce: array(text("entry_nonce")),
            entry: input["entry"].clone(),
        }
    }

    fn new_entry(&self) -> NewEntry {
        assert_eq!(self.entry["kind"], "login");
        NewEntry {
            kind: EntryKind::Login,
            title: self.entry["title"].as_str().unwrap().into(),
            fields: self.entry["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| Field {
                    name: f["name"].as_str().unwrap().into(),
                    value: f["value"].as_str().unwrap().as_bytes().to_vec(),
                    concealed: f["concealed"].as_bool().unwrap(),
                })
                .collect(),
        }
    }

    /// Randomness in the order the vault draws it: vault id, salt, VK, slot nonce, then the
    /// entry's id and nonce.
    fn entropy(&self) -> ScriptedEntropy {
        let chunks =
            [&self.vault_id[..], &self.salt, &self.vk, &self.slot_nonce, &self.entry_id, &self.entry_nonce];
        ScriptedEntropy::new(chunks.iter().map(|c| c.to_vec()).collect(), self.now)
    }

    /// The sample vault, built from the inputs.
    fn build(&self) -> Vec<u8> {
        let mut vault = Vault::create_with(Box::new(self.entropy()), &self.password, self.params).unwrap();
        vault.add_entry(self.new_entry());
        vault.to_bytes()
    }
}

struct Outputs {
    kek: Vec<u8>,
    wrapped_vk: Vec<u8>,
    header_mac_key: Vec<u8>,
    file_mac_key: Vec<u8>,
    entries_key: Vec<u8>,
    entry_plaintext: Vec<u8>,
    entry_ciphertext: Vec<u8>,
}

fn compute(inputs: &Inputs) -> Outputs {
    let kek = kdf::derive_kek(&inputs.password, &inputs.salt, inputs.params).unwrap();
    let vk = Key::from_slice(&inputs.vk).unwrap();
    let wrapped_vk = keys::wrap_vk(&kek, &vk, &inputs.slot_nonce, SlotKind::Password, &inputs.vault_id);
    let subkeys = Subkeys::derive(&vk, &inputs.vault_id);
    let plaintext = entry_plaintext(inputs.new_entry(), inputs.now, inputs.now);
    let aad = keys::aad("entry", &inputs.vault_id, &inputs.entry_id);
    let ciphertext = aead::seal(&subkeys.entries, &inputs.entry_nonce, &plaintext, &aad);
    Outputs {
        kek: kek.expose().to_vec(),
        wrapped_vk,
        header_mac_key: subkeys.header_mac.expose().to_vec(),
        file_mac_key: subkeys.file_mac.expose().to_vec(),
        entries_key: subkeys.entries.expose().to_vec(),
        entry_plaintext: plaintext,
        entry_ciphertext: ciphertext,
    }
}

fn read_vector() -> Value {
    let text = std::fs::read_to_string(shared(VECTOR)).expect("core/tests/vectors/v1_sample.json");
    serde_json::from_str(&text).unwrap()
}

#[test]
fn intermediate_values_match_the_vector() {
    let vector = read_vector();
    assert_eq!(vector["format_version"], 1);
    assert_eq!(vector["test_only"], true);
    let outputs = compute(&Inputs::from(&vector));
    let expected = |key: &str| unhex(vector["expected"][key].as_str().expect(key));
    assert_eq!(outputs.kek, expected("kek"), "Argon2id");
    assert_eq!(outputs.wrapped_vk, expected("wrapped_vault_key"), "password slot");
    assert_eq!(outputs.header_mac_key, expected("header_mac_key"), "HKDF header-mac");
    assert_eq!(outputs.file_mac_key, expected("file_mac_key"), "HKDF file-mac");
    assert_eq!(outputs.entries_key, expected("entries_key"), "HKDF entries");
    assert_eq!(outputs.entry_plaintext, expected("entry_plaintext"), "entry CBOR");
    assert_eq!(outputs.entry_ciphertext, expected("entry_ciphertext"), "entry block");
}

#[test]
fn the_sample_file_is_recreated_byte_for_byte() {
    let vector = read_vector();
    let inputs = Inputs::from(&vector);
    let fixture = std::fs::read(shared(FIXTURE)).expect("core/tests/fixtures/v1_sample.dvault");
    assert_eq!(hex(&inputs.build()), hex(&fixture));
    assert_eq!(vector["expected"]["file_len"].as_u64(), Some(fixture.len() as u64));
}

#[test]
fn the_committed_v1_file_still_opens() {
    let vector = read_vector();
    let inputs = Inputs::from(&vector);
    let fixture = std::fs::read(shared(FIXTURE)).unwrap();
    let vault = Vault::open(&fixture, &inputs.password).unwrap();

    assert_eq!(vault.vault_id(), inputs.vault_id);
    assert_eq!(vault.kdf_params(), inputs.params);
    let entries = vault.entries();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.id, inputs.entry_id);
    assert_eq!(entry.kind, EntryKind::Login);
    assert_eq!(entry.title, "Example");
    assert_eq!(entry.url.as_deref(), Some("https://example.com/login"));
    assert_eq!(entry.username.as_deref(), Some("alice@example.com"));
    assert_eq!(entry.updated_at, inputs.now);
    let password = vault.secret(&entry.id, field::PASSWORD).unwrap();
    assert_eq!(password.expose(), b"hunter2-but-longer");
}

/// Writes the vector and the sample file from the code. Run once when a format version is
/// introduced — `cargo test -p deepvault-vault --test vectors -- --ignored` — and never again
/// for that version: afterwards the files are the reference and the code must match them.
#[test]
#[ignore]
fn write_v1_vectors() {
    let inputs_json = json!({
        "password": "correct horse battery staple",
        "kdf": { "alg": "argon2id", "m_kib": 8192, "t": 1, "p": 1, "salt": "000102030405060708090a0b0c0d0e0f" },
        "vault_id": "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "vault_key": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "slot_nonce": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
        "now": 1_792_540_800u64,
        "entry_id": "e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
        "entry_nonce": "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7",
        "entry": {
            "kind": "login",
            "title": "Example",
            "fields": [
                { "name": "url", "value": "https://example.com/login", "concealed": false },
                { "name": "username", "value": "alice@example.com", "concealed": false },
                { "name": "password", "value": "hunter2-but-longer", "concealed": true },
            ],
        },
    });
    let mut vector = json!({
        "description": "DeepVault .dvault format v1: one vault, one password slot, one login entry. \
            Randomness is drawn in this order: vault_id, kdf.salt, vault_key, slot_nonce, entry_id, entry_nonce. \
            AAD = \"DVLT\" || u16le(1) || purpose || 0x00 || vault_id || extra (slot: kind label; entry: entry_id). \
            Subkeys = HKDF-SHA256(salt = vault_id, ikm = vault_key, info = \"deepvault/v1/<purpose>\").",
        "format_version": 1,
        "test_only": true,
        "input": inputs_json,
    });
    let inputs = Inputs::from(&vector);
    let outputs = compute(&inputs);
    let file = inputs.build();
    vector["expected"] = json!({
        "kek": hex(&outputs.kek),
        "wrapped_vault_key": hex(&outputs.wrapped_vk),
        "header_mac_key": hex(&outputs.header_mac_key),
        "file_mac_key": hex(&outputs.file_mac_key),
        "entries_key": hex(&outputs.entries_key),
        "entry_plaintext": hex(&outputs.entry_plaintext),
        "entry_ciphertext": hex(&outputs.entry_ciphertext),
        "file_len": file.len(),
    });
    std::fs::write(shared(VECTOR), serde_json::to_string_pretty(&vector).unwrap() + "\n").unwrap();
    std::fs::write(shared(FIXTURE), file).unwrap();
}
