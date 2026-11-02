//! Format v2 test vectors (ADR-0014): one file of an entry (`core/tests/vectors/file_v1.json`),
//! and a vault package — the vault file and two files, one ending on a chunk boundary
//! (`core/tests/vectors/v2_sample.json`, `core/tests/vectors/v2_sample.dvault/`).
//!
//! As for v1: every value is recomputed from the inputs, the files are recreated byte for byte,
//! and the committed package must keep opening. Chunks are 64 bytes here (the app's are 1 MiB):
//! the reader takes the size from the file's header. KDF parameters are `test_only`.

mod common;

use common::{array, hex, shared, unhex};
use serde_json::{json, Value};
use vault::file::{FileRef, FileWriter};
use vault::keys::{self, SlotKind, Subkeys};
use vault::testing::{entry_plaintext, ScriptedEntropy};
use vault::{aead, field, kdf, EntryKind, Field, KdfParams, Key, NewEntry, Vault};

const FILE_VECTOR: &str = "vectors/file_v1.json";
const VECTOR: &str = "vectors/v2_sample.json";
const PACKAGE: &str = "vectors/v2_sample.dvault";
const CHUNK: usize = 64;

fn read(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(shared(path)).expect(path)).unwrap()
}

fn content(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)).collect()
}

// MARK: - One file

struct FileInputs {
    vault_id: [u8; 16],
    file_id: [u8; 16],
    key: [u8; 32],
    prefix: [u8; 19],
    now: u64,
    name: String,
    content: Vec<u8>,
}

impl FileInputs {
    fn from(input: &Value) -> Self {
        let text = |key: &str| input[key].as_str().expect(key);
        assert_eq!(input["chunk_size"].as_u64(), Some(CHUNK as u64));
        Self {
            vault_id: array(text("vault_id")),
            file_id: array(text("file_id")),
            key: array(text("key")),
            prefix: array(text("nonce_prefix")),
            now: input["now"].as_u64().unwrap(),
            name: text("name").into(),
            content: unhex(text("content")),
        }
    }

    /// The file and its ref; `pieces` are the sizes it is fed in.
    fn seal(&self, pieces: usize) -> (Vec<u8>, FileRef) {
        let chunks = vec![self.file_id.to_vec(), self.key.to_vec(), self.prefix.to_vec()];
        let mut entropy = ScriptedEntropy::new(chunks, self.now);
        let mut writer = FileWriter::new_with(&mut entropy, self.vault_id, &self.name, CHUNK);
        assert!(entropy.is_exhausted());
        let mut out = writer.header();
        for piece in self.content.chunks(pieces) {
            out.extend(writer.update(piece).unwrap());
        }
        let (last, file) = writer.finish().unwrap();
        out.extend(last);
        (out, file)
    }
}

/// Each chunk recomputed with the core's XChaCha20-Poly1305 alone, from the nonce rule.
fn chunks_by_hand(inputs: &FileInputs) -> Vec<Vec<u8>> {
    let key = Key::from_slice(&inputs.key).unwrap();
    let aad = keys::aad_for(2, "file", &inputs.vault_id, &inputs.file_id);
    let parts: Vec<&[u8]> =
        if inputs.content.is_empty() { vec![&[][..]] } else { inputs.content.chunks(CHUNK).collect() };
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let mut nonce = [0u8; 24];
            nonce[..19].copy_from_slice(&inputs.prefix);
            nonce[19..23].copy_from_slice(&(i as u32).to_be_bytes());
            nonce[23] = u8::from(i == parts.len() - 1);
            aead::seal(&key, &nonce, part, &aad)
        })
        .collect()
}

#[test]
fn the_file_vector_matches() {
    let vector = read(FILE_VECTOR);
    assert_eq!(vector["file_version"], 1);
    let inputs = FileInputs::from(&vector["input"]);
    let expected = &vector["expected"];
    let chunks = chunks_by_hand(&inputs);
    let listed: Vec<String> =
        expected["chunks"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().into()).collect();
    assert_eq!(chunks.iter().map(|c| hex(c)).collect::<Vec<_>>(), listed);
    for pieces in [1, 13, 64, 1000] {
        let (file, reference) = inputs.seal(pieces);
        assert_eq!(hex(&file), expected["file"].as_str().unwrap(), "fed {pieces} at a time");
        assert_eq!(hex(&file[..45]), expected["header"].as_str().unwrap());
        assert_eq!(hex(&reference.sha256), expected["sha256"].as_str().unwrap());
        assert_eq!(hex(&reference.to_bytes()), expected["field_value"].as_str().unwrap());
    }
    let reference = FileRef::from_bytes(&unhex(expected["field_value"].as_str().unwrap())).unwrap();
    assert_eq!(
        reference.open(&unhex(expected["file"].as_str().unwrap())).unwrap().expose(),
        &inputs.content[..]
    );
}

// MARK: - The package

struct Inputs {
    password: Vec<u8>,
    params: KdfParams,
    salt: [u8; 16],
    vault_id: [u8; 16],
    vk: [u8; 32],
    slot_nonce: [u8; 24],
    now: u64,
    files: Vec<FileInputs>,
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
            files: input["files"].as_array().unwrap().iter().map(FileInputs::from).collect(),
            entry_id: array(text("entry_id")),
            entry_nonce: array(text("entry_nonce")),
            entry: input["entry"].clone(),
        }
    }

    fn fields(&self, files: &[FileRef]) -> Vec<Field> {
        let mut fields: Vec<Field> = self.entry["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| Field {
                name: f["name"].as_str().unwrap().into(),
                value: f["value"].as_str().unwrap().as_bytes().to_vec(),
                concealed: f["concealed"].as_bool().unwrap(),
                custom: false,
            })
            .collect();
        for file in files {
            fields.push(Field {
                name: field::FILE.into(),
                value: file.to_bytes().to_vec(),
                concealed: true,
                custom: false,
            });
        }
        fields
    }

    /// Randomness: vault id, salt, VK, slot nonce; per file id, key, prefix; entry id, nonce.
    fn build(&self) -> (Vec<u8>, Vec<(FileRef, Vec<u8>)>) {
        let mut chunks =
            vec![self.vault_id.to_vec(), self.salt.to_vec(), self.vk.to_vec(), self.slot_nonce.to_vec()];
        for file in &self.files {
            assert_eq!(file.vault_id, self.vault_id);
            chunks.extend([file.file_id.to_vec(), file.key.to_vec(), file.prefix.to_vec()]);
        }
        chunks.extend([self.entry_id.to_vec(), self.entry_nonce.to_vec()]);
        let mut vault =
            Vault::create_with(Box::new(ScriptedEntropy::new(chunks, self.now)), &self.password, self.params)
                .unwrap();
        let mut files = Vec::new();
        for file in &self.files {
            let mut writer = vault.file_writer_chunked(&file.name, CHUNK);
            let mut bytes = writer.header();
            bytes.extend(writer.update(&file.content).unwrap());
            let (last, reference) = writer.finish().unwrap();
            bytes.extend(last);
            files.push((reference, bytes));
        }
        let refs: Vec<FileRef> =
            files.iter().map(|(r, _)| FileRef::from_bytes(&r.to_bytes()).unwrap()).collect();
        assert_eq!(self.entry["kind"], "login");
        vault.add_entry(NewEntry {
            kind: EntryKind::Login,
            title: self.entry["title"].as_str().unwrap().into(),
            fields: self.fields(&refs),
        });
        (vault.to_bytes(), files)
    }
}

#[test]
fn the_v2_vector_matches_and_the_package_is_recreated_byte_for_byte() {
    let vector = read(VECTOR);
    assert_eq!(vector["format_version"], 2);
    assert_eq!(vector["test_only"], true);
    let inputs = Inputs::from(&vector);
    let expected = &vector["expected"];
    let value = |key: &str| unhex(expected[key].as_str().expect(key));

    let kek = kdf::derive_kek(&inputs.password, &inputs.salt, inputs.params).unwrap();
    let vk = Key::from_slice(&inputs.vk).unwrap();
    let wrapped = keys::wrap_vk(&kek, &vk, &inputs.slot_nonce, SlotKind::Password, &inputs.vault_id);
    assert_eq!(wrapped, value("wrapped_vault_key"), "a slot's AAD stays v1");
    let subkeys = Subkeys::derive(&vk, &inputs.vault_id);
    assert_eq!(subkeys.pack_mac.expose().to_vec(), value("pack_mac_key"));

    let (main, files) = inputs.build();
    let refs: Vec<FileRef> = files.iter().map(|(r, _)| FileRef::from_bytes(&r.to_bytes()).unwrap()).collect();
    let plaintext = entry_plaintext(
        NewEntry {
            kind: EntryKind::Login,
            title: inputs.entry["title"].as_str().unwrap().into(),
            fields: inputs.fields(&refs),
        },
        inputs.now,
        inputs.now,
    );
    assert_eq!(plaintext, value("entry_plaintext"));
    let aad = keys::aad_for(2, "entry", &inputs.vault_id, &inputs.entry_id);
    assert_eq!(
        aead::seal(&subkeys.entries, &inputs.entry_nonce, &plaintext, &aad),
        value("entry_ciphertext")
    );

    let package = shared(PACKAGE);
    assert_eq!(hex(&main), hex(&std::fs::read(package.join("vault")).unwrap()));
    let listed = expected["files"].as_array().unwrap();
    assert_eq!(listed.len(), files.len());
    for ((reference, bytes), listed) in files.iter().zip(listed) {
        assert_eq!(hex(&reference.sha256), listed["sha256"].as_str().unwrap());
        assert_eq!(reference.file_name(), listed["name"].as_str().unwrap());
        let on_disk = std::fs::read(package.join("files").join(reference.file_name())).unwrap();
        assert_eq!(hex(bytes), hex(&on_disk));
    }
}

#[test]
fn the_committed_v2_package_still_opens() {
    let vector = read(VECTOR);
    let inputs = Inputs::from(&vector);
    let package = shared(PACKAGE);
    let vault = Vault::open(&std::fs::read(package.join("vault")).unwrap(), &inputs.password).unwrap();
    assert_eq!(vault.version(), 2);
    let entry = &vault.entries()[0];
    assert_eq!(entry.id, inputs.entry_id);
    assert_eq!(vault.secret(&entry.id, field::PASSWORD).unwrap().expose(), b"hunter2-but-longer");
    let files = vault.files(&entry.id).unwrap();
    assert_eq!(files.len(), 2);
    for ((_, file), input) in files.iter().zip(&inputs.files) {
        let bytes = std::fs::read(package.join("files").join(file.file_name())).unwrap();
        assert_eq!(file.name, input.name);
        assert_eq!(file.open(&bytes).unwrap().expose(), &input.content[..]);
    }
}

/// Writes the vectors and the package from the code. Run once for format v2 —
/// `cargo test -p deepvault-vault --test vectors_v2 -- --ignored` — and never again: afterwards
/// the files are the reference and the code must match them.
#[test]
#[ignore]
fn write_v2_vectors() {
    let vault_id = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf";
    let file_input = |id: &str, key: &str, prefix: &str, name: &str, content: &[u8]| {
        json!({
            "vault_id": vault_id, "file_id": id, "key": key, "nonce_prefix": prefix,
            "chunk_size": CHUNK, "now": 1_793_577_600u64, "name": name, "content": hex(content),
        })
    };
    // One file of 150 bytes: chunks of 64, 64 and 22.
    let single = file_input(
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
        "909192939495969798999a9b9c9d9e9fa0a1a2",
        "scan.pdf",
        &content(150, 1),
    );
    let inputs = FileInputs::from(&single);
    let (file, reference) = inputs.seal(CHUNK);
    let file_vector = json!({
        "description": "DeepVault file of an entry, DVLF v1 (ADR-0014): header = \"DVLF\" || u16le(1) || file_id (16) || u32le(chunk_size) || nonce_prefix (19). \
            Chunk i = XChaCha20-Poly1305(key, nonce = nonce_prefix || u32be(i) || last (1 byte), content[i*chunk_size..], \
            AAD = \"DVLT\" || u16le(2) || \"file\" || 0x00 || vault_id || file_id). Every chunk but the last is full; the last has 1..chunk_size bytes (0 only for an empty file). \
            field_value = the entry's `file` field: CBOR map {id, vault, name, size, key, sha256, created}. Randomness: file_id, key, nonce_prefix.",
        "file_version": 1,
        "input": single,
        "expected": {
            "header": hex(&file[..45]),
            "chunks": chunks_by_hand(&inputs).iter().map(|c| hex(c)).collect::<Vec<_>>(),
            "file": hex(&file),
            "sha256": hex(&reference.sha256),
            "field_value": hex(&reference.to_bytes()),
        },
    });
    std::fs::write(shared(FILE_VECTOR), serde_json::to_string_pretty(&file_vector).unwrap() + "\n").unwrap();

    let mut vector = json!({
        "description": "DeepVault vault package, format v2 (ADR-0014): <name>.dvault/vault (as v1, version 2) and files/<file_id hex>. \
            Randomness is drawn in this order: vault_id, kdf.salt, vault_key, slot_nonce, then per file file_id, key, nonce_prefix, then entry_id, entry_nonce. \
            AAD = \"DVLT\" || u16le(version) || purpose || 0x00 || vault_id || extra: a slot says version 1 (so a v1 vault moves without its password), an entry 2, a file's chunks 2. \
            Subkeys as v1 (\"deepvault/v1/<purpose>\"), plus pack_mac = HKDF(info = \"deepvault/v2/pack-mac\") for a vault in one file. \
            The entry has the given fields, then one `file` field per file (concealed). Files are sealed as in file_v1.json, chunks of 64 bytes; the second ends on a chunk boundary.",
        "format_version": 2,
        "test_only": true,
        "input": {
            "password": "correct horse battery staple",
            "kdf": { "alg": "argon2id", "m_kib": 8192, "t": 1, "p": 1, "salt": "000102030405060708090a0b0c0d0e0f" },
            "vault_id": vault_id,
            "vault_key": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            "slot_nonce": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
            "now": 1_793_577_600u64,
            "files": [
                file_input("101112131415161718191a1b1c1d1e1f", "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "505152535455565758595a5b5c5d5e5f606162", "passport.jpg", &content(100, 2)),
                file_input("8081828384858687888980aa8b8c8d8e", "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf", "707172737475767778797a7b7c7d7e7f808182", "boundary.bin", &content(128, 3)),
            ],
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
        },
    });
    let inputs = Inputs::from(&vector);
    let kek = kdf::derive_kek(&inputs.password, &inputs.salt, inputs.params).unwrap();
    let vk = Key::from_slice(&inputs.vk).unwrap();
    let subkeys = Subkeys::derive(&vk, &inputs.vault_id);
    let (main, files) = inputs.build();
    let refs: Vec<FileRef> = files.iter().map(|(r, _)| FileRef::from_bytes(&r.to_bytes()).unwrap()).collect();
    let plaintext = entry_plaintext(
        NewEntry { kind: EntryKind::Login, title: "Example".into(), fields: inputs.fields(&refs) },
        inputs.now,
        inputs.now,
    );
    let aad = keys::aad_for(2, "entry", &inputs.vault_id, &inputs.entry_id);
    vector["expected"] = json!({
        "kek": hex(kek.expose()),
        "wrapped_vault_key": hex(&keys::wrap_vk(&kek, &vk, &inputs.slot_nonce, SlotKind::Password, &inputs.vault_id)),
        "header_mac_key": hex(subkeys.header_mac.expose()),
        "file_mac_key": hex(subkeys.file_mac.expose()),
        "entries_key": hex(subkeys.entries.expose()),
        "pack_mac_key": hex(subkeys.pack_mac.expose()),
        "entry_plaintext": hex(&plaintext),
        "entry_ciphertext": hex(&aead::seal(&subkeys.entries, &inputs.entry_nonce, &plaintext, &aad)),
        "vault_len": main.len(),
        "files": files.iter().map(|(r, bytes)| json!({
            "name": r.file_name(), "sha256": hex(&r.sha256), "len": bytes.len(), "field_value": hex(&r.to_bytes()),
        })).collect::<Vec<_>>(),
    });
    std::fs::write(shared(VECTOR), serde_json::to_string_pretty(&vector).unwrap() + "\n").unwrap();
    let package = shared(PACKAGE);
    let _ = std::fs::remove_dir_all(&package);
    std::fs::create_dir_all(package.join("files")).unwrap();
    std::fs::write(package.join("vault"), main).unwrap();
    for (reference, bytes) in files {
        std::fs::write(package.join("files").join(reference.file_name()), bytes).unwrap();
    }
}
