//! A vault's life — create, add, save, open, delete — and every way a file can be wrong.
//! Parameters are `TEST_ONLY`; nothing here is a real secret.

use vault::testing::ScriptedEntropy;
use vault::{field, EntryKind, Field, KdfParams, NewEntry, Vault, VaultError};

const PASSWORD: &[u8] = b"correct horse battery staple";
const PARAMS: KdfParams = KdfParams::TEST_ONLY;

fn login(title: &str, password: &str) -> NewEntry {
    NewEntry {
        kind: EntryKind::Login,
        title: title.into(),
        fields: vec![
            Field {
                name: field::URL.into(),
                value: b"https://example.com".to_vec(),
                concealed: false,
                custom: false,
            },
            Field { name: field::USERNAME.into(), value: b"alice".to_vec(), concealed: false, custom: false },
            Field {
                name: field::PASSWORD.into(),
                value: password.as_bytes().to_vec(),
                concealed: true,
                custom: false,
            },
        ],
    }
}

/// A saved vault with one login.
fn sample() -> Vec<u8> {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    vault.add_entry(login("Example", "s3cret"));
    vault.to_bytes()
}

/// Where the parts of a v1 file are: (header, header_mac, blocks, file_mac) as ranges.
fn layout(file: &[u8]) -> [std::ops::Range<usize>; 4] {
    let header_len = u32::from_le_bytes(file[6..10].try_into().unwrap()) as usize;
    let header = 10..10 + header_len;
    let header_mac = header.end..header.end + 32;
    let blocks = header_mac.end..file.len() - 32;
    [header, header_mac, blocks, file.len() - 32..file.len()]
}

fn open(file: &[u8]) -> Result<Vault, VaultError> {
    Vault::open(file, PASSWORD)
}

// MARK: - Life

#[test]
fn entries_survive_saving_and_opening() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let first = vault.add_entry(login("First", "one"));
    let second = vault.add_entry(login("Second", "two"));
    assert_ne!(first, second);

    let reopened = open(&vault.to_bytes()).unwrap();
    let titles: Vec<_> = reopened.entries().iter().map(|e| e.title.as_str()).collect();
    assert_eq!(titles, ["First", "Second"]);
    assert_eq!(reopened.entries()[0].url.as_deref(), Some("https://example.com"));
    assert_eq!(reopened.entries()[0].username.as_deref(), Some("alice"));
    assert_eq!(reopened.secret(&second, field::PASSWORD).unwrap().expose(), b"two");
    assert_eq!(reopened.vault_id(), vault.vault_id());
}

#[test]
fn concealed_fields_stay_out_of_the_index() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let id = vault.add_entry(NewEntry {
        kind: EntryKind::Login,
        title: "Hidden".into(),
        fields: vec![Field {
            name: field::USERNAME.into(),
            value: b"bob".to_vec(),
            concealed: true,
            custom: false,
        }],
    });
    assert_eq!(vault.entries()[0].username, None);
    assert_eq!(vault.secret(&id, field::USERNAME).unwrap().expose(), b"bob");
    assert_eq!(vault.secret(&id, field::NOTES).err(), Some(VaultError::NotFound));
}

#[test]
fn an_updated_entry_keeps_its_id_place_and_creation_date() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let first = vault.add_entry(login("First", "one"));
    vault.add_entry(login("Second", "two"));
    let created = vault.entries()[0].created_at;
    let sealed_before = vault.to_bytes();

    let mut changed = login("First, renamed", "uno");
    changed.fields.retain(|field| field.name != field::URL);
    vault.update_entry(&first, changed).unwrap();

    let reopened = open(&vault.to_bytes()).unwrap();
    let summary = &reopened.entries()[0];
    assert_eq!(summary.id, first);
    assert_eq!(summary.title, "First, renamed");
    assert_eq!(summary.url, None);
    assert_eq!(summary.created_at, created);
    assert!(summary.updated_at >= created);
    assert_eq!(reopened.entries()[1].title, "Second");
    assert_eq!(reopened.secret(&first, field::PASSWORD).unwrap().expose(), b"uno");
    // Sealed again in place: the file changed, the block count did not.
    assert_ne!(vault.to_bytes(), sealed_before);
    assert_eq!(reopened.entries().len(), 2);
}

#[test]
fn only_live_entries_can_be_updated() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let gone = vault.add_entry(login("Gone", "x"));
    vault.delete_entry(&gone).unwrap();
    assert_eq!(vault.update_entry(&gone, login("Back", "y")).err(), Some(VaultError::NotFound));
    assert_eq!(vault.update_entry(&[7; 16], login("Never", "z")).err(), Some(VaultError::NotFound));
    assert!(vault.entries().is_empty());
}

#[test]
fn fields_list_names_in_order_without_concealed_values() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let id = vault.add_entry(login("Example", "s3cret"));
    let fields = vault.fields(&id).unwrap();
    let names: Vec<_> = fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, [field::URL, field::USERNAME, field::PASSWORD]);
    assert_eq!(fields[1].value.as_deref(), Some("alice"));
    assert!(fields[2].concealed);
    assert_eq!(fields[2].value, None);
    vault.delete_entry(&id).unwrap();
    assert_eq!(vault.fields(&id).err(), Some(VaultError::NotFound));
}

#[test]
fn repeated_fields_are_read_by_position_and_codes_never_show_the_secret() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let field = |name: &str, value: &[u8], concealed| Field {
        name: name.into(),
        value: value.to_vec(),
        concealed,
        custom: false,
    };
    let id = vault.add_entry(NewEntry {
        kind: EntryKind::Login,
        title: "Many".into(),
        fields: vec![
            field(field::URL, b"https://one.example", false),
            field(field::URL, b"https://two.example", false),
            field(field::NOTES, b"open note", false),
            field(field::NOTES, b"closed note", true),
            // RFC 6238's SHA1 seed.
            field(field::TOTP, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", true),
            field(field::ICON, &[0x89, b'P', b'N', b'G'], false),
            field(field::TAG, b"work", false),
            field(field::TAG, b"servers", false),
        ],
    });
    let reopened = open(&vault.to_bytes()).unwrap();
    let summary = &reopened.entries()[0];
    assert_eq!(summary.url.as_deref(), Some("https://one.example"));
    assert_eq!(summary.icon.as_deref(), Some(&[0x89, b'P', b'N', b'G'][..]));
    assert!(summary.has_otp);
    assert_eq!(summary.tags, ["work", "servers"]);

    let fields = reopened.fields(&id).unwrap();
    assert_eq!(fields[1].value.as_deref(), Some("https://two.example"));
    assert_eq!(fields[3].value, None);
    assert_eq!(reopened.secret_at(&id, 3).unwrap().expose(), b"closed note");
    assert_eq!(reopened.secret_at(&id, 8).err(), Some(VaultError::NotFound));

    assert_eq!(reopened.strength(&id, 3).unwrap().length, 11);

    let code = reopened.totp(&id, 4, 59).unwrap();
    assert_eq!((code.code.as_str(), code.remaining), ("287082", 1));
    assert_eq!(reopened.totp(&id, 0, 59).err(), Some(VaultError::InvalidOtp));
}

#[test]
fn a_card_shows_only_its_last_four_digits() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let card = vault.add_entry(NewEntry {
        kind: EntryKind::Card,
        title: "Mono".into(),
        fields: vec![
            Field {
                name: field::NUMBER.into(),
                value: b"4111 1111 1111 4417".to_vec(),
                concealed: true,
                custom: false,
            },
            Field { name: field::CVV.into(), value: b"123".to_vec(), concealed: true, custom: false },
        ],
    });
    let summary = vault.entries().iter().find(|e| e.id == card).unwrap();
    assert_eq!(summary.card_last4.as_deref(), Some("4417"));
    assert_eq!(summary.card_network.as_deref(), Some("visa"));
    assert_eq!(summary.kind, EntryKind::Card);
    // A login has none; a short number is not a card number.
    vault.add_entry(login("Site", "x"));
    assert_eq!(vault.entries()[1].card_last4, None);
}

#[test]
fn every_kind_is_stored_by_name_and_survives_reopening() {
    let kinds = [
        (EntryKind::Login, "login"),
        (EntryKind::Password, "password"),
        (EntryKind::Note, "note"),
        (EntryKind::Card, "card"),
        (EntryKind::BankAccount, "bank_account"),
        (EntryKind::SoftwareLicense, "software_license"),
        (EntryKind::Environment, "environment"),
        (EntryKind::SshKey, "ssh_key"),
        (EntryKind::GeneratedPassword, "generated_password"),
    ];
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    for (kind, name) in kinds {
        let mut cbor = Vec::new();
        ciborium::into_writer(&kind, &mut cbor).unwrap();
        assert_eq!(
            ciborium::from_reader::<ciborium::Value, _>(&cbor[..]).unwrap(),
            ciborium::Value::Text(name.into())
        );
        vault.add_entry(NewEntry { kind, title: name.into(), fields: vec![] });
    }
    let reopened = open(&vault.to_bytes()).unwrap();
    let mut stored: Vec<_> = reopened.entries().iter().map(|e| (e.title.clone(), e.kind)).collect();
    stored.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected: Vec<_> = kinds.iter().map(|(kind, name)| (name.to_string(), *kind)).collect();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(stored, expected);
}

#[test]
fn environment_variables_keep_their_names_values_and_shell_marks() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let variable = |name: &str, value: &[u8]| Field {
        name: name.into(),
        value: value.to_vec(),
        concealed: true,
        custom: true,
    };
    let id = vault.add_entry(NewEntry {
        kind: EntryKind::Environment,
        title: "Apple".into(),
        fields: vec![
            variable("APPLE_TEAM_ID", b"ECMW794735"),
            variable("APPLE_APP_PASSWORD", b"abcd-efgh-ijkl-mnop"),
            // Only the team id goes to every new shell; the password asks each time.
            Field {
                name: field::SHELL.into(),
                value: b"APPLE_TEAM_ID".to_vec(),
                concealed: false,
                custom: false,
            },
        ],
    });

    let reopened = open(&vault.to_bytes()).unwrap();
    assert_eq!(reopened.entries()[0].kind, EntryKind::Environment);
    let fields = reopened.fields(&id).unwrap();
    let names: Vec<_> = fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["APPLE_TEAM_ID", "APPLE_APP_PASSWORD", field::SHELL]);
    // Values stay concealed in the list; the mark is a name, readable without decrypting a value.
    assert!(fields[0].value.is_none() && fields[1].value.is_none());
    assert_eq!(fields[2].value.as_deref(), Some("APPLE_TEAM_ID"));
    assert_eq!(reopened.secret_at(&id, 0).unwrap().expose(), b"ECMW794735");
    // A variable named like a known field is still only a label.
    assert_eq!(reopened.secret(&id, field::PASSWORD).err(), Some(VaultError::NotFound));
}

#[test]
fn a_custom_field_is_only_a_label() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let id = vault.add_entry(NewEntry {
        kind: EntryKind::Note,
        title: "GitLab tokens".into(),
        fields: vec![
            Field {
                name: field::PASSWORD.into(),
                value: b"glpat-123".to_vec(),
                concealed: true,
                custom: true,
            },
            Field { name: field::URL.into(), value: b"not a site".to_vec(), concealed: false, custom: true },
            Field { name: field::TAG.into(), value: b"not a tag".to_vec(), concealed: false, custom: true },
        ],
    });
    let reopened = open(&vault.to_bytes()).unwrap();
    let summary = reopened.entries().iter().find(|e| e.id == id).unwrap();
    assert_eq!(summary.url, None);
    assert!(summary.tags.is_empty());
    assert_eq!(reopened.secret(&id, field::PASSWORD).err(), Some(VaultError::NotFound));
    let fields = reopened.fields(&id).unwrap();
    assert!(fields.iter().all(|f| f.custom));
    assert_eq!(reopened.secret_at(&id, 0).unwrap().expose(), b"glpat-123");
}

#[test]
fn a_field_that_is_not_custom_is_stored_as_before() {
    let field = Field { name: "url".into(), value: b"x".to_vec(), concealed: false, custom: false };
    let mut cbor = Vec::new();
    ciborium::into_writer(&field, &mut cbor).unwrap();
    let ciborium::Value::Map(keys) = ciborium::from_reader(&cbor[..]).unwrap() else { panic!("a map") };
    let names: Vec<_> = keys.iter().filter_map(|(key, _)| key.as_text()).collect();
    assert_eq!(names, ["name", "value", "concealed"]);
}

#[test]
fn links_are_in_the_index() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let note =
        vault.add_entry(NewEntry { kind: EntryKind::Note, title: "Recovery codes".into(), fields: vec![] });
    let target = note.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let login = vault.add_entry(NewEntry {
        kind: EntryKind::Login,
        title: "GitLab".into(),
        fields: vec![
            Field {
                name: field::LINK.into(),
                value: target.clone().into_bytes(),
                concealed: false,
                custom: false,
            },
            Field { name: field::LINK.into(), value: b"label only".to_vec(), concealed: false, custom: true },
        ],
    });
    let reopened = open(&vault.to_bytes()).unwrap();
    let summary = reopened.entries().iter().find(|e| e.id == login).unwrap();
    assert_eq!(summary.links, vec![target]);
}

#[test]
fn using_an_entry_is_noted_without_changing_it() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let used = vault.add_entry(login("GitLab", "pw"));
    let other = vault.add_entry(login("Other", "pw2"));
    let updated = vault.entries()[0].updated_at;
    assert_eq!(vault.entries()[0].used_at, 0);

    vault.mark_used(&used).unwrap();
    let reopened = open(&vault.to_bytes()).unwrap();
    let summary = reopened.entries().iter().find(|e| e.id == used).unwrap();
    assert!(summary.used_at >= updated);
    assert_eq!(summary.updated_at, updated);
    assert_eq!(reopened.secret(&used, field::PASSWORD).unwrap().expose(), b"pw");
    assert_eq!(reopened.entries().iter().find(|e| e.id == other).unwrap().used_at, 0);
    assert_eq!(vault.mark_used(&[9; 16]).err(), Some(VaultError::NotFound));
}

#[test]
fn a_favourite_is_kept_without_changing_the_entry() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let starred = vault.add_entry(login("GitLab", "pw"));
    let other = vault.add_entry(login("Other", "pw2"));
    let updated = vault.entries()[0].updated_at;
    assert!(!vault.entries()[0].favorite);

    vault.set_favorite(&starred, true).unwrap();
    let mut reopened = open(&vault.to_bytes()).unwrap();
    let summary = reopened.entries().iter().find(|e| e.id == starred).unwrap();
    assert!(summary.favorite);
    assert_eq!(summary.updated_at, updated);
    assert!(!reopened.entries().iter().find(|e| e.id == other).unwrap().favorite);

    // An edit keeps the star; taking it off stores the entry as before.
    reopened.update_entry(&starred, login("GitLab", "new")).unwrap();
    assert!(reopened.entries().iter().find(|e| e.id == starred).unwrap().favorite);
    reopened.set_favorite(&starred, false).unwrap();
    assert!(!open(&reopened.to_bytes()).unwrap().entries().iter().any(|e| e.favorite));
    assert_eq!(vault.set_favorite(&[9; 16], true).err(), Some(VaultError::NotFound));
}

#[test]
fn a_deleted_entry_leaves_a_tombstone() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let gone = vault.add_entry(login("Gone", "x"));
    vault.add_entry(login("Kept", "y"));
    let before = vault.to_bytes();
    vault.delete_entry(&gone).unwrap();
    assert_eq!(vault.secret(&gone, field::PASSWORD).err(), Some(VaultError::NotFound));
    assert_eq!(vault.delete_entry(&gone), Err(VaultError::NotFound));

    let after = vault.to_bytes();
    let reopened = open(&after).unwrap();
    assert_eq!(reopened.entries().len(), 1);
    assert_eq!(reopened.entries()[0].title, "Kept");
    // Still two blocks: the tombstone keeps its place for a merge.
    assert_eq!(after[layout(&after)[2].start..][..4], before[layout(&before)[2].start..][..4]);
}

#[test]
fn nothing_is_written_in_the_clear() {
    let file = sample();
    let contains = |needle: &[u8]| file.windows(needle.len()).any(|window| window == needle);
    assert!(!contains(b"s3cret"));
    assert!(!contains(b"Example"));
    assert!(!contains(b"example.com"));
    assert!(!contains(b"alice"));
    assert!(!contains(PASSWORD));
}

#[test]
fn every_save_is_a_complete_file() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let empty = vault.to_bytes();
    assert_eq!(open(&empty).unwrap().entries().len(), 0);
    vault.add_entry(login("One", "1"));
    assert_eq!(open(&vault.to_bytes()).unwrap().entries().len(), 1);
}

// MARK: - Keys

#[test]
fn a_wrong_password_is_refused() {
    let file = sample();
    assert_eq!(Vault::open(&file, b"correct horse battery stapler").err(), Some(VaultError::WrongPassword));
    assert_eq!(Vault::open(&file, b"").err(), Some(VaultError::WrongPassword));
}

#[test]
fn a_device_slot_opens_its_own_vault_only() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    vault.add_entry(login("Example", "s3cret"));
    let kek = [0x42; 32];
    let slot = vault.device_slot(&kek).unwrap();
    let file = vault.to_bytes();

    let opened = Vault::open_with_device_key(&file, &slot, &kek).unwrap();
    assert_eq!(opened.entries().len(), 1);
    assert_eq!(Vault::open_with_device_key(&file, &slot, &[0x43; 32]).err(), Some(VaultError::WrongPassword));

    let mut other = Vault::create(PASSWORD, PARAMS).unwrap();
    let other_slot = other.device_slot(&kek).unwrap();
    assert_eq!(Vault::open_with_device_key(&file, &other_slot, &kek).err(), Some(VaultError::WrongPassword));

    assert_eq!(Vault::open_with_device_key(&file, &slot, &[0x42; 31]).err(), Some(VaultError::InvalidKey));
    assert_eq!(Vault::open_with_device_key(&file, &slot[1..], &kek).err(), Some(VaultError::InvalidKey));
    assert_eq!(vault.device_slot(&[1; 16]).err(), Some(VaultError::InvalidKey));
}

#[test]
fn a_new_master_password_opens_the_vault_and_the_old_one_does_not() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let id = vault.add_entry(login("Example", "s3cret"));
    let kek = [0x42; 32];
    let slot = vault.device_slot(&kek).unwrap();
    let before = vault.to_bytes();

    vault.change_password(PASSWORD, b"new master password").unwrap();
    let file = vault.to_bytes();
    assert_eq!(open(&file).err(), Some(VaultError::WrongPassword));
    let opened = Vault::open(&file, b"new master password").unwrap();
    assert_eq!(opened.secret(&id, field::PASSWORD).unwrap().expose(), b"s3cret");
    assert_eq!(opened.vault_id(), vault.vault_id());
    assert_eq!(opened.kdf_params(), PARAMS);
    // The vault key stays: Touch ID keeps working, and a copy made before opens as it did.
    assert_eq!(Vault::open_with_device_key(&file, &slot, &kek).unwrap().entries().len(), 1);
    assert!(open(&before).is_ok());
    // No entry was sealed again.
    assert_eq!(layout(&file)[2].len(), layout(&before)[2].len());
    assert_eq!(&file[layout(&file)[2].clone()], &before[layout(&before)[2].clone()]);
}

#[test]
fn the_master_password_changes_only_with_the_current_one() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    vault.add_entry(login("Example", "s3cret"));
    let before = vault.to_bytes();
    assert_eq!(vault.change_password(b"not it", b"new").err(), Some(VaultError::WrongPassword));
    assert_eq!(vault.to_bytes(), before);
    assert!(open(&vault.to_bytes()).is_ok());
}

#[test]
fn weak_kdf_parameters_are_refused() {
    let weak = KdfParams { m_kib: 1024, t: 1, p: 1 };
    assert_eq!(Vault::create(PASSWORD, weak).err(), Some(VaultError::InvalidKdfParams));
}

// MARK: - Damaged files

#[test]
fn a_changed_header_never_opens() {
    let file = sample();
    let [header, ..] = layout(&file);
    for index in header {
        let mut changed = file.clone();
        changed[index] ^= 0x01;
        // A changed salt, cost or slot gives a key that opens nothing; anything else fails
        // the header MAC or the CBOR.
        let result = open(&changed).err();
        assert!(
            matches!(result, Some(VaultError::WrongPassword | VaultError::Corrupted)),
            "byte {index}: {result:?}"
        );
    }
}

#[test]
fn changed_macs_and_blocks_are_detected() {
    let file = sample();
    let [_, header_mac, blocks, file_mac] = layout(&file);
    // Every byte of a block: id, nonce, length and ciphertext.
    for index in header_mac.chain(blocks).chain(file_mac) {
        let mut changed = file.clone();
        changed[index] ^= 0x80;
        assert_eq!(open(&changed).err(), Some(VaultError::Corrupted), "byte {index}");
    }
}

#[test]
fn a_truncated_or_extended_file_is_corrupted() {
    let file = sample();
    for len in 0..file.len() {
        assert_eq!(open(&file[..len]).err(), Some(VaultError::Corrupted), "length {len}");
    }
    let mut longer = file.clone();
    longer.push(0);
    assert_eq!(open(&longer).err(), Some(VaultError::Corrupted));
}

#[test]
fn an_unknown_version_or_magic_is_named() {
    let file = sample();
    let mut newer = file.clone();
    newer[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(open(&newer).err(), Some(VaultError::UnsupportedVersion(2)));

    let mut not_a_vault = file.clone();
    not_a_vault[..4].copy_from_slice(b"PK\x03\x04");
    assert_eq!(open(&not_a_vault).err(), Some(VaultError::Corrupted));
    assert_eq!(open(b"").err(), Some(VaultError::Corrupted));
}

#[test]
fn a_block_from_another_vault_is_refused() {
    // Same password, same entry layout — but a different vault id and key.
    let ours = sample();
    let theirs = sample();
    let [_, _, our_blocks, _] = layout(&ours);
    let [_, _, their_blocks, _] = layout(&theirs);
    let mut mixed = ours[..our_blocks.start].to_vec();
    mixed.extend_from_slice(&theirs[their_blocks.clone()]);
    mixed.extend_from_slice(&ours[ours.len() - 32..]);
    assert_eq!(open(&mixed).err(), Some(VaultError::Corrupted));
}

#[test]
fn scripted_entropy_is_used_in_order() {
    let chunks = vec![vec![1; 16], vec![2; 16], vec![3; 32], vec![4; 24], vec![5; 16], vec![6; 24]];
    let entropy = ScriptedEntropy::new(chunks, 7);
    let mut vault = Vault::create_with(Box::new(entropy), PASSWORD, PARAMS).unwrap();
    assert_eq!(vault.vault_id(), [1; 16]);
    assert_eq!(vault.add_entry(login("x", "y")), [5; 16]);
    assert_eq!(vault.entries()[0].updated_at, 7);
}

#[test]
fn a_header_that_claims_huge_lengths_is_refused_cheaply() {
    // CBOR map { "vault_id": bytes(2^64 − 1) } and an array of 2^32 − 1 items: lengths the
    // parser must not trust for allocation.
    for header in [&b"\xa1\x68vault_id\x5b\xff\xff\xff\xff\xff\xff\xff\xff"[..], b"\x9a\xff\xff\xff\xff"] {
        let mut file = b"DVLT\x01\x00".to_vec();
        file.extend_from_slice(&(header.len() as u32).to_le_bytes());
        file.extend_from_slice(header);
        file.extend_from_slice(&[0; 32 + 4 + 32]);
        assert_eq!(open(&file).err(), Some(VaultError::Corrupted));
    }
    // A block count far beyond what the file holds.
    let file = sample();
    let [_, header_mac, ..] = layout(&file);
    let mut many = file.clone();
    many[header_mac.end..header_mac.end + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(open(&many).err(), Some(VaultError::Corrupted));
}

fn plain(name: &str, value: &str) -> Field {
    Field { name: name.into(), value: value.as_bytes().to_vec(), concealed: false, custom: false }
}

#[test]
fn importing_again_adds_only_what_is_new_and_keeps_what_the_user_did() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    // The first import, before tags were read.
    let first = vault.import(vec![login("Example", "s3cret"), login("Other", "two")]).unwrap();
    assert_eq!(first, vault::Merged { added: 2, matched: 0, tagged: 0 });
    let example = vault.entries().iter().find(|e| e.title == "Example").unwrap().id;

    // Saved by the app with a picture: its own field order, the site as typed without a slash.
    let mut edited = login("Example", "s3cret");
    edited.fields.reverse();
    edited.fields.push(plain(field::ICON, "png"));
    edited.fields.push(plain(field::TAG, "Work"));
    vault.update_entry(&example, edited).unwrap();

    // The same export again, now with tags, and a note that was missed.
    let mut tagged = login("Example", "s3cret");
    tagged.fields[0].value = b"https://EXAMPLE.com/".to_vec();
    tagged.fields.push(plain(field::TAG, "work"));
    tagged.fields.push(plain(field::TAG, "servers"));
    let changed = login("Other", "changed in the other app");
    let note = NewEntry { kind: EntryKind::Note, title: "gitlab".into(), fields: vec![] };
    let again = vault.import(vec![tagged, changed, note]).unwrap();
    assert_eq!(again, vault::Merged { added: 2, matched: 1, tagged: 1 });

    let titles: Vec<_> = vault.entries().iter().map(|e| e.title.as_str()).collect();
    assert_eq!(titles, ["Example", "Other", "Other", "gitlab"]);
    let kept = vault.entries().iter().find(|e| e.id == example).unwrap();
    assert_eq!(kept.icon.as_deref(), Some(&b"png"[..]));
    assert_eq!(kept.tags, ["Work", "servers"]);

    // Once more: nothing new.
    let third = vault.import(vec![login("Example", "s3cret")]).unwrap();
    assert_eq!(third, vault::Merged { added: 0, matched: 1, tagged: 0 });
}

#[test]
fn a_backup_restores_into_the_vault_in_use_without_doubling() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    vault.add_entry(login("Example", "s3cret"));
    let backup = Vault::open(&vault.to_bytes(), PASSWORD).unwrap();
    // Since the backup: one more entry here, one deleted.
    vault.add_entry(login("New here", "n"));
    let gone = vault.add_entry(login("Deleted here", "d"));
    let mut older = Vault::open(&vault.to_bytes(), PASSWORD).unwrap();
    vault.delete_entry(&gone).unwrap();
    older.delete_entry(&older.entries().iter().find(|e| e.title == "New here").unwrap().id.clone()).unwrap();

    let merged = vault.import(older.export_entries().unwrap()).unwrap();
    assert_eq!(merged, vault::Merged { added: 1, matched: 1, tagged: 0 });
    let titles: Vec<_> = vault.entries().iter().map(|e| e.title.as_str()).collect();
    assert_eq!(titles, ["Example", "New here", "Deleted here"]);
    assert_eq!(backup.export_entries().unwrap().len(), 1);
}

// MARK: - Audit

#[test]
fn the_audit_rates_passwords_and_groups_the_reused_without_giving_them_out() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let a = vault.add_entry(login("A", "same-Password-9!x"));
    let weak = vault.add_entry(login("Weak", "123456"));
    let b = vault.add_entry(login("B", "same-Password-9!x"));
    let unique = vault.add_entry(login("Unique", "Kq7#vR2!mX9@pL4z"));
    // A generated password equal to A's is not counted as reuse.
    let mut generated = login("Generated", "same-Password-9!x");
    generated.kind = EntryKind::GeneratedPassword;
    vault.add_entry(generated);
    // A note is not audited.
    let mut note = login("Note", "123456");
    note.kind = EntryKind::Note;
    vault.add_entry(note);

    let items = vault.audit();
    let of = |id: [u8; 16]| items.iter().find(|item| item.id == id).copied().unwrap();
    assert_eq!(items.len(), 4);
    assert_eq!(of(a).reused, of(b).reused);
    assert!(of(a).reused.is_some());
    assert_eq!(of(weak).reused, None);
    assert_eq!(of(unique).reused, None);
    assert_eq!(of(a).index, 2);
    assert!(of(weak).strength.level < vault::strength::Level::Fair);
    assert!(of(unique).strength.level >= vault::strength::Level::Strong);
}
