//! Format v2 (ADR-0014): files outside the vault file, the move from v1, the vault in one file.

mod common;

use std::collections::HashMap;

use common::shared;
use vault::file::{FileRef, FILE_ID_LEN};
use vault::pack::{self, Kind, PREFIX_LEN};
use vault::{field, EntryKind, Field, KdfParams, NewEntry, SystemEntropy, Vault, VaultError};

const PASSWORD: &[u8] = b"pw";
const PARAMS: KdfParams = KdfParams::TEST_ONLY;

type Disk = HashMap<[u8; FILE_ID_LEN], Vec<u8>>;

fn attachment(name: &str, content: &[u8]) -> Field {
    let mut value = format!("{name}\0").into_bytes();
    value.extend_from_slice(content);
    Field { name: field::ATTACHMENT.into(), value, concealed: true, custom: false }
}

fn text(name: &str, value: &str) -> Field {
    Field { name: name.into(), value: value.as_bytes().to_vec(), concealed: false, custom: false }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

fn write_file(vault: &mut Vault, disk: &mut Disk, name: &str, content: &[u8]) -> FileRef {
    let mut writer = vault.file_writer(name);
    let mut bytes = writer.header();
    // In pieces, as the app reads a file from disk.
    for piece in content.chunks(1000) {
        bytes.extend(writer.update(piece).unwrap());
    }
    let (last, file) = writer.finish().unwrap();
    bytes.extend(last);
    disk.insert(file.id, bytes);
    file
}

/// A v1 vault as DeepVault 0.1.x saved it: a login with two files and a note in Recently
/// Deleted with one.
fn v1_vault_with_files() -> Vault {
    let mut vault = Vault::create_v1_with(Box::new(SystemEntropy), PASSWORD, PARAMS).unwrap();
    vault.add_entry(NewEntry {
        kind: EntryKind::Login,
        title: "Bank".into(),
        fields: vec![
            text(field::URL, "https://bank.example"),
            attachment("scan.pdf", &[1; 3000]),
            text(field::TAG, "money"),
            attachment("no-name-follows", b""),
        ],
    });
    let note = vault.add_entry(NewEntry {
        kind: EntryKind::Note,
        title: "Old".into(),
        fields: vec![attachment("old.txt", b"gone soon")],
    });
    vault.trash_entry(&note).unwrap();
    assert_eq!(vault.version(), 1);
    vault
}

#[test]
fn a_v1_vault_moves_to_v2_with_its_files_outside() {
    let v1 = v1_vault_with_files();
    let mut vault = Vault::open(&v1.to_bytes(), PASSWORD).unwrap();
    assert_eq!(vault.version(), 1);
    let before: Vec<_> = vault.entries().iter().map(|e| (e.id, e.title.clone(), e.updated_at)).collect();

    let mut disk = Disk::new();
    let moved = vault
        .upgrade(&mut |id, bytes| {
            disk.insert(*id, bytes.to_vec());
            Ok(())
        })
        .unwrap();
    assert_eq!(moved, 3);
    assert_eq!(vault.version(), 2);
    assert_eq!(vault.upgrade(&mut |_, _| panic!("nothing to move")).unwrap(), 0);

    let file = vault.to_bytes();
    assert_eq!(&file[4..6], &2u16.to_le_bytes());
    let reopened = Vault::open(&file, PASSWORD).unwrap();
    assert_eq!(reopened.version(), 2);
    let after: Vec<_> = reopened.entries().iter().map(|e| (e.id, e.title.clone(), e.updated_at)).collect();
    assert_eq!(after, before, "ids, titles and dates stay");

    let bank = reopened.entries()[0].id;
    let fields = reopened.fields(&bank).unwrap();
    let names: Vec<_> = fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, [field::URL, field::FILE, field::TAG, field::FILE], "the order of fields stays");
    let files = reopened.files(&bank).unwrap();
    assert_eq!(files.len(), 2);
    let (index, scan) = &files[0];
    assert_eq!(*index, 1);
    assert_eq!(scan.name, "scan.pdf");
    assert_eq!(scan.size, 3000);
    assert_eq!(scan.sha256, sha256(&[1; 3000]));
    assert_eq!(scan.open(&disk[&scan.id]).unwrap().expose(), &[1; 3000]);
    assert_eq!(files[1].1.open(&disk[&files[1].1.id]).unwrap().expose(), b"");

    // Recently Deleted's file moved too, and is still referred to.
    let trashed = reopened.trashed()[0].id;
    let old = &reopened.files(&trashed).unwrap()[0].1;
    assert_eq!(old.open(&disk[&old.id]).unwrap().expose(), b"gone soon");
    let mut referenced = reopened.referenced_files().unwrap();
    referenced.sort();
    let mut on_disk: Vec<_> = disk.keys().copied().collect();
    on_disk.sort();
    assert_eq!(referenced, on_disk);
}

/// The committed v1 sample (no files) moves too; its entry and password stay.
#[test]
fn the_committed_v1_sample_moves_to_v2() {
    let fixture = std::fs::read(shared("fixtures/v1_sample.dvault")).unwrap();
    let mut vault = Vault::open(&fixture, b"correct horse battery staple").unwrap();
    assert_eq!(vault.upgrade(&mut |_, _| panic!("no files")).unwrap(), 0);
    let reopened = Vault::open(&vault.to_bytes(), b"correct horse battery staple").unwrap();
    assert_eq!(reopened.version(), 2);
    let entry = &reopened.entries()[0];
    assert_eq!(entry.title, "Example");
    assert_eq!(reopened.secret(&entry.id, field::PASSWORD).unwrap().expose(), b"hunter2-but-longer");
}

/// A write that fails half way leaves the vault v1 as it was: the same bytes.
#[test]
fn an_upgrade_that_fails_changes_nothing() {
    let mut vault = Vault::open(&v1_vault_with_files().to_bytes(), PASSWORD).unwrap();
    let before = vault.to_bytes();
    let mut writes = 0;
    let result = vault.upgrade(&mut |_, _| {
        writes += 1;
        if writes == 2 {
            Err(VaultError::FileTooLarge)
        } else {
            Ok(())
        }
    });
    assert_eq!(result, Err(VaultError::FileTooLarge));
    assert_eq!(vault.version(), 1);
    assert_eq!(vault.to_bytes(), before);
}

/// The app keeps the v1 bytes and goes back to them when writing the files fails after the move.
#[test]
fn a_move_is_undone_with_the_bytes_from_before() {
    let mut vault = Vault::open(&v1_vault_with_files().to_bytes(), PASSWORD).unwrap();
    let before = vault.to_bytes();
    vault.upgrade(&mut |_, _| Ok(())).unwrap();
    vault.revert_to(&before).unwrap();
    assert_eq!(vault.version(), 1);
    assert_eq!(vault.to_bytes(), before);
}

/// Touch ID's slot in the Keychain was made for the v1 file; it opens the v2 file too.
#[test]
fn a_device_slot_made_before_the_move_still_opens() {
    let mut vault = Vault::open(&v1_vault_with_files().to_bytes(), PASSWORD).unwrap();
    let kek = [9u8; 32];
    let slot = vault.device_slot(&kek).unwrap();
    vault.upgrade(&mut |_, _| Ok(())).unwrap();
    let opened = Vault::open_with_device_key(&vault.to_bytes(), &slot, &kek).unwrap();
    assert_eq!(opened.version(), 2);
}

/// A v2 block put into a v1 file (or the other way round) does not open: its AAD says its version.
#[test]
fn a_file_saying_the_other_version_is_damaged() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    vault.add_entry(NewEntry { kind: EntryKind::Note, title: "n".into(), fields: vec![] });
    let mut file = vault.to_bytes();
    file[4] = 1;
    assert!(Vault::open(&file, PASSWORD).is_err());
    file[4] = 3;
    assert_eq!(Vault::open(&file, PASSWORD).err(), Some(VaultError::UnsupportedVersion(3)));
}

#[test]
fn files_are_added_removed_and_counted_with_trash_and_unsaved_copies() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    assert_eq!(vault.version(), 2);
    let mut disk = Disk::new();
    let a = write_file(&mut vault, &mut disk, "a.png", &[3; 2_500_000]);
    let b = write_file(&mut vault, &mut disk, "b.txt", b"bee");
    let c = write_file(&mut vault, &mut disk, "c.txt", b"sea");
    let left_over = write_file(&mut vault, &mut disk, "never-saved", b"x");

    let live = vault.add_entry(NewEntry { kind: EntryKind::Note, title: "live".into(), fields: vec![] });
    vault.add_file(&live, &a).unwrap();
    vault.add_file(&live, &b).unwrap();
    let trashed = vault.add_entry(NewEntry { kind: EntryKind::Note, title: "trash".into(), fields: vec![] });
    vault.add_file(&trashed, &c).unwrap();
    vault.trash_entry(&trashed).unwrap();
    // Changes kept on a lock, not confirmed: a copy that refers to a file of its own.
    let unsaved = write_file(&mut vault, &mut disk, "draft.txt", b"draft");
    let copy = vault.add_entry(NewEntry {
        kind: EntryKind::Note,
        title: "live".into(),
        fields: vec![text(field::UNSAVED, "")],
    });
    vault.add_file(&copy, &unsaved).unwrap();

    let reopened = Vault::open(&vault.to_bytes(), PASSWORD).unwrap();
    let referenced = reopened.referenced_files().unwrap();
    for file in [&a, &b, &c, &unsaved] {
        assert!(referenced.contains(&file.id), "{}", file.name);
    }
    assert!(!referenced.contains(&left_over.id));
    assert_eq!(reopened.file_at(&live, 0).unwrap().open(&disk[&a.id]).unwrap().expose().len(), 2_500_000);
    assert_eq!(reopened.file_at(&live, 5).err(), Some(VaultError::NotFound));

    vault.remove_file(&live, &b.id).unwrap();
    assert_eq!(vault.remove_file(&live, &b.id), Err(VaultError::NotFound));
    vault.delete_entry(&trashed).unwrap();
    let referenced = vault.referenced_files().unwrap();
    assert!(!referenced.contains(&b.id) && !referenced.contains(&c.id));
    assert!(referenced.contains(&a.id));

    // A v1 vault does not take files outside.
    let mut v1 = Vault::create_v1_with(Box::new(SystemEntropy), PASSWORD, PARAMS).unwrap();
    let note = v1.add_entry(NewEntry { kind: EntryKind::Note, title: "n".into(), fields: vec![] });
    assert_eq!(v1.add_file(&note, &a), Err(VaultError::UnsupportedVersion(1)));
}

/// An import's attachments become files of a v2 vault; a v1 vault keeps them in the entry.
#[test]
fn an_import_into_v2_puts_its_attachments_in_files() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let mut entries = vec![NewEntry {
        kind: EntryKind::Login,
        title: "Shop".into(),
        fields: vec![text(field::URL, "https://shop.example"), attachment("receipt.txt", b"paid")],
    }];
    let mut disk = Disk::new();
    let moved = vault
        .externalize(&mut entries, &mut |id, bytes| {
            disk.insert(*id, bytes.to_vec());
            Ok(())
        })
        .unwrap();
    assert_eq!(moved, 1);
    assert_eq!(entries[0].fields[1].name, field::FILE);
    vault.import(entries).unwrap();
    let shop = vault.entries()[0].id;
    let (_, receipt) = &vault.files(&shop).unwrap()[0];
    assert_eq!(receipt.name, "receipt.txt");
    assert_eq!(receipt.open(&disk[&receipt.id]).unwrap().expose(), b"paid");

    let mut v1 = Vault::create_v1_with(Box::new(SystemEntropy), PASSWORD, PARAMS).unwrap();
    let mut entries =
        vec![NewEntry { kind: EntryKind::Note, title: "n".into(), fields: vec![attachment("a", b"b")] }];
    assert_eq!(v1.externalize(&mut entries, &mut |_, _| panic!("v1 keeps it")).unwrap(), 0);
    assert_eq!(entries[0].fields[0].name, field::ATTACHMENT);
}

/// A file copied to another vault as it is opens there: its ref says which vault it was made for.
#[test]
fn a_file_copied_to_another_vault_opens_there() {
    let mut first = Vault::create(PASSWORD, PARAMS).unwrap();
    let mut disk = Disk::new();
    let file = write_file(&mut first, &mut disk, "id.jpg", b"passport");
    let id = first.add_entry(NewEntry { kind: EntryKind::Note, title: "Passport".into(), fields: vec![] });
    first.add_file(&id, &file).unwrap();

    let mut second = Vault::create(PASSWORD, PARAMS).unwrap();
    second.import(first.export_entries().unwrap()).unwrap();
    let copied = second.entries()[0].id;
    let (_, there) = &second.files(&copied).unwrap()[0];
    assert_eq!(there.id, file.id);
    assert_eq!(there.open(&disk[&file.id]).unwrap().expose(), b"passport");
}

/// A pack written piece by piece and read back the same way: the vault opens from its head,
/// each file comes out as it went in, the MAC checks.
fn pack_of(vault: &Vault, disk: &Disk, order: &[[u8; FILE_ID_LEN]]) -> Vec<u8> {
    let table: Vec<_> = order.iter().map(|id| (*id, disk[id].len() as u64)).collect();
    let mut writer = vault.pack_writer(&table).unwrap();
    let mut out = writer.head().to_vec();
    for id in order {
        for piece in disk[id].chunks(777) {
            writer.update(piece);
            out.extend_from_slice(piece);
        }
    }
    out.extend_from_slice(&writer.finish().unwrap());
    out
}

/// What the app does with a pack: read the prefix, the vault file, the table; open; copy the
/// files out; check the MAC.
fn unpack(bytes: &[u8]) -> Result<(Vault, Disk), VaultError> {
    if pack::kind(bytes) != Kind::Pack {
        return Err(VaultError::Corrupted);
    }
    let main_len = pack::main_len(&bytes[..PREFIX_LEN])? as usize;
    let count_at = PREFIX_LEN + main_len;
    let table_len =
        pack::table_len(bytes.get(count_at..count_at + 4).ok_or(VaultError::Corrupted)?)? as usize;
    let head = bytes.get(..count_at + 4 + table_len).ok_or(VaultError::Corrupted)?;
    let vault = Vault::open(pack::main_of(head)?, PASSWORD)?;
    let mut reader = vault.pack_reader(head)?;
    let mut at = head.len();
    let mut disk = Disk::new();
    for (id, len) in reader.files().to_vec() {
        let end = at
            .checked_add(len as usize)
            .filter(|end| *end + 32 <= bytes.len())
            .ok_or(VaultError::Corrupted)?;
        reader.update(&bytes[at..end]);
        disk.insert(id, bytes[at..end].to_vec());
        at = end;
    }
    reader.finish(&bytes[at..])?;
    Ok((vault, disk))
}

#[test]
fn a_vault_in_one_file_comes_back_whole_and_damage_is_refused() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let mut disk = Disk::new();
    let a = write_file(&mut vault, &mut disk, "a.bin", &[5; 70_000]);
    let b = write_file(&mut vault, &mut disk, "b.bin", b"small");
    let id = vault.add_entry(NewEntry { kind: EntryKind::Note, title: "files".into(), fields: vec![] });
    vault.add_file(&id, &a).unwrap();
    vault.add_file(&id, &b).unwrap();

    let bytes = pack_of(&vault, &disk, &[a.id, b.id]);
    let (back, back_disk) = unpack(&bytes).unwrap();
    for (_, file) in back.files(&id).unwrap() {
        let content = file.open(&back_disk[&file.id]).unwrap();
        assert_eq!(sha256(content.expose()), file.sha256);
    }

    // A changed byte anywhere — the head, the vault file, the table, a file, the MAC.
    for index in (0..bytes.len()).step_by(97).chain([bytes.len() - 1, PREFIX_LEN + 3]) {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(unpack(&changed).is_err(), "byte {index}");
    }
    // Cut short; a byte added; the files swapped in the table.
    assert!(unpack(&bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.clone();
    longer.insert(bytes.len() - 32, 0);
    assert!(unpack(&longer).is_err());
    assert!(unpack(&pack_of(&vault, &disk, &[b.id, a.id])).is_ok(), "any order the table says");
    let mut forged = pack_of(&vault, &disk, &[a.id, b.id]);
    let table_at = PREFIX_LEN + pack::main_len(&forged[..PREFIX_LEN]).unwrap() as usize + 4;
    let (first, second) =
        (forged[table_at..table_at + 24].to_vec(), forged[table_at + 24..table_at + 48].to_vec());
    forged[table_at..table_at + 24].copy_from_slice(&second);
    forged[table_at + 24..table_at + 48].copy_from_slice(&first);
    assert!(unpack(&forged).is_err());

    // Another vault's head with this pack's files.
    let other = Vault::create(PASSWORD, PARAMS).unwrap();
    assert!(other.pack_reader(&bytes[..table_at + 48]).is_err());
    // A v1 vault is not packed: it is one file already.
    let v1 = Vault::create_v1_with(Box::new(SystemEntropy), PASSWORD, PARAMS).unwrap();
    assert_eq!(v1.pack_writer(&[]).err(), Some(VaultError::UnsupportedVersion(1)));
    assert_eq!(pack::kind(&v1.to_bytes()), Kind::Vault);
}
