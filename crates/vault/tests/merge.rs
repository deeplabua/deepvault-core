//! Two devices on one vault (ADR-0016): copies of one file changed apart and merged entry by
//! entry. Parameters are `TEST_ONLY`; nothing here is a real secret.

use vault::testing::FixedClock;
use vault::{field, EntryKind, Field, KdfParams, MergeReport, NewEntry, Vault, VaultError};

const PASSWORD: &[u8] = b"correct horse battery staple";
const PARAMS: KdfParams = KdfParams::TEST_ONLY;

fn login(title: &str, password: &str) -> NewEntry {
    NewEntry {
        kind: EntryKind::Login,
        title: title.into(),
        fields: vec![
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

/// The file both devices start from: two logins, written at 1000.
fn base() -> (Vec<u8>, [u8; 16], [u8; 16]) {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    vault.set_entropy(Box::new(FixedClock(1000)));
    let a = vault.add_entry(login("Mail", "mail-0"));
    let b = vault.add_entry(login("Bank", "bank-0"));
    (vault.to_bytes(), a, b)
}

/// A device: the base opened, its clock at `now`.
fn device(file: &[u8], now: u64) -> Vault {
    let mut vault = Vault::open(file, PASSWORD).unwrap();
    vault.set_entropy(Box::new(FixedClock(now)));
    vault
}

fn at(vault: &mut Vault, now: u64) {
    vault.set_entropy(Box::new(FixedClock(now)));
}

/// The password of an entry, live or in Recently Deleted.
fn password(vault: &Vault, id: &[u8; 16]) -> Vec<u8> {
    let at = vault.fields(id).unwrap().iter().position(|f| f.name == field::PASSWORD && !f.custom).unwrap();
    vault.secret_at(id, at).unwrap().expose().to_vec()
}

/// A new password as the app saves one: every other field handed back as it was.
fn change(vault: &mut Vault, id: &[u8; 16], new: &str) {
    let fields = vault.fields(id).unwrap();
    let fields = (0..fields.len())
        .map(|i| Field {
            name: fields[i].name.clone(),
            value: if fields[i].name == field::PASSWORD {
                new.as_bytes().to_vec()
            } else {
                vault.secret_at(id, i).unwrap().expose().to_vec()
            },
            concealed: fields[i].concealed,
            custom: fields[i].custom,
        })
        .collect();
    let title = vault.entries().iter().find(|e| &e.id == id).unwrap().title.clone();
    vault.update_entry(id, NewEntry { kind: EntryKind::Login, title, fields }).unwrap();
}

fn history(vault: &Vault, id: &[u8; 16]) -> Vec<String> {
    let fields = vault.fields(id).unwrap();
    (0..fields.len())
        .filter(|&i| fields[i].name == field::PREVIOUS)
        .map(|i| String::from_utf8(vault.secret_at(id, i).unwrap().expose().to_vec()).unwrap())
        .collect()
}

/// An entry as `contents` compares it: title, changed, trashed, starred, every field's value.
type Contents = (String, u64, u64, bool, Vec<(String, Vec<u8>)>);

/// What a vault holds, comparable across copies (nonces differ): every entry with its fields.
fn contents(vault: &Vault) -> Vec<Contents> {
    let mut all: Vec<_> = vault
        .entries()
        .iter()
        .chain(vault.trashed())
        .map(|e| {
            let fields = vault.fields(&e.id).unwrap();
            let values = (0..fields.len())
                .map(|i| (fields[i].name.clone(), vault.secret_at(&e.id, i).unwrap().expose().to_vec()))
                .collect();
            (e.title.clone(), e.updated_at, e.trashed_at, e.favorite, values)
        })
        .collect();
    all.sort_by(|x, y| x.0.cmp(&y.0));
    all
}

/// Merges both ways and checks they agree; returns the first device's merge.
fn both_ways(mac: &[u8], phone: &[u8], base: Option<&[u8]>) -> (Vault, MergeReport) {
    let mut on_mac = Vault::open(mac, PASSWORD).unwrap();
    let report = on_mac.merge_file(phone, base).unwrap();
    let mut on_phone = Vault::open(phone, PASSWORD).unwrap();
    on_phone.merge_file(mac, base).unwrap();
    assert!(contents(&on_mac) == contents(&on_phone), "the merge depends on the order");
    // Merging the result again changes nothing.
    let again = on_phone.merge_file(&on_mac.to_bytes(), None).unwrap();
    assert_eq!(again, MergeReport::default());
    (on_mac, report)
}

#[test]
fn different_entries_changed_on_two_devices_both_stay() {
    let (file, mail, bank) = base();
    let mut mac = device(&file, 2000);
    mac.update_entry(&mail, login("Mail", "mail-mac")).unwrap();
    let mut phone = device(&file, 2100);
    phone.update_entry(&bank, login("Bank", "bank-phone")).unwrap();
    let added = phone.add_entry(login("New on phone", "n"));

    for base in [Some(&file[..]), None] {
        let (merged, report) = both_ways(&mac.to_bytes(), &phone.to_bytes(), base);
        assert_eq!(password(&merged, &mail), b"mail-mac");
        assert_eq!(password(&merged, &bank), b"bank-phone");
        assert_eq!(password(&merged, &added), b"n");
        assert_eq!((report.added, report.changed, report.removed), (1, 1, 0));
        assert_eq!(report.outgoing, 1, "the Mac's change is not in the phone's file");
    }
}

#[test]
fn one_entry_changed_on_both_the_later_wins_and_the_other_password_is_in_history() {
    let (file, mail, _) = base();
    let mut mac = device(&file, 2000);
    let mut changed = login("Mail (Mac)", "mail-mac");
    changed.fields.push(Field {
        name: field::NOTES.into(),
        value: b"mac".to_vec(),
        concealed: true,
        custom: false,
    });
    mac.update_entry(&mail, changed).unwrap();
    let mut phone = device(&file, 3000);
    phone.update_entry(&mail, login("Mail (phone)", "mail-phone")).unwrap();

    for base in [Some(&file[..]), None] {
        let (merged, report) = both_ways(&mac.to_bytes(), &phone.to_bytes(), base);
        let summary = merged.entries().iter().find(|e| e.id == mail).unwrap();
        assert_eq!(summary.title, "Mail (phone)");
        assert_eq!(password(&merged, &mail), b"mail-phone");
        // The phone's own change kept the base's password; the Mac's goes in beside it.
        assert_eq!(history(&merged, &mail), ["password\n3000\nmail-0", "password\n3000\nmail-mac"]);
        assert_eq!(merged.secret(&mail, field::NOTES).err(), Some(VaultError::NotFound));
        assert_eq!((report.added, report.changed, report.removed), (0, 1, 0));
    }
}

#[test]
fn a_star_or_a_use_on_one_device_and_an_edit_on_the_other_both_stay() {
    let (file, mail, bank) = base();
    let mut mac = device(&file, 2000);
    mac.set_favorite(&mail, true).unwrap();
    mac.mark_used(&bank).unwrap();
    let mut phone = device(&file, 3000);
    phone.update_entry(&bank, login("Bank", "bank-phone")).unwrap();

    let (merged, report) = both_ways(&mac.to_bytes(), &phone.to_bytes(), Some(&file));
    assert!(merged.entries().iter().find(|e| e.id == mail).unwrap().favorite);
    let bank_now = merged.entries().iter().find(|e| e.id == bank).unwrap();
    assert_eq!(bank_now.used_at, 2000);
    assert_eq!(password(&merged, &bank), b"bank-phone");
    assert_eq!((report.added, report.changed, report.removed), (0, 1, 0));

    // A star on the Mac and an edit of the same entry on the phone, in the same second: both.
    let mut mac = device(&file, 3000);
    mac.set_favorite(&bank, true).unwrap();
    let mut phone = device(&file, 3000);
    phone.update_entry(&bank, login("Bank", "bank-phone")).unwrap();
    let (merged, _) = both_ways(&mac.to_bytes(), &phone.to_bytes(), Some(&file));
    let bank_now = merged.entries().iter().find(|e| e.id == bank).unwrap();
    assert!(bank_now.favorite);
    assert_eq!(password(&merged, &bank), b"bank-phone");

    // The star taken off on the phone, the Mac unchanged since: off.
    let starred = merged.to_bytes();
    let mut phone = device(&starred, 4000);
    phone.set_favorite(&mail, false).unwrap();
    let mut mac = device(&starred, 4000);
    mac.merge_file(&phone.to_bytes(), Some(&starred)).unwrap();
    assert!(!mac.entries().iter().find(|e| e.id == mail).unwrap().favorite);
}

#[test]
fn deleted_on_one_device_and_changed_on_the_other() {
    let (file, mail, bank) = base();
    // Moved to Recently Deleted on the Mac, changed later on the phone: live, the change kept.
    let mut mac = device(&file, 2000);
    mac.trash_entry(&mail).unwrap();
    let mut phone = device(&file, 3000);
    phone.update_entry(&mail, login("Mail", "mail-phone")).unwrap();
    let (merged, _) = both_ways(&mac.to_bytes(), &phone.to_bytes(), Some(&file));
    assert!(merged.entries().iter().any(|e| e.id == mail));
    assert_eq!(password(&merged, &mail), b"mail-phone");

    // Deleted for good on the Mac after a change on the phone the Mac never saw: not gone,
    // in Recently Deleted with the phone's change.
    let mut mac = device(&file, 4000);
    mac.delete_entry(&bank).unwrap();
    let mut phone = device(&file, 3000);
    phone.update_entry(&bank, login("Bank", "bank-phone")).unwrap();
    let (merged, report) = both_ways(&mac.to_bytes(), &phone.to_bytes(), Some(&file));
    let trashed = merged.trashed().iter().find(|e| e.id == bank).expect("in Recently Deleted");
    assert_eq!(trashed.trashed_at, 4000);
    assert_eq!(password(&merged, &bank), b"bank-phone");
    // On the Mac it was gone already: nothing new to say, but the phone's file lacks it.
    assert_eq!((report.added, report.removed), (0, 0));
    assert!(report.outgoing >= 1);

    // Deleted for good on one side, unchanged on the other: deleted.
    let mut mac = device(&file, 4000);
    mac.delete_entry(&bank).unwrap();
    let mut phone = device(&file, 3000);
    phone.update_entry(&mail, login("Mail", "mail-phone")).unwrap();
    let (merged, report) = both_ways(&mac.to_bytes(), &phone.to_bytes(), Some(&file));
    assert!(!merged.entries().iter().chain(merged.trashed()).any(|e| e.id == bank));
    assert_eq!((report.added, report.changed, report.removed), (0, 1, 0));
}

#[test]
fn an_entry_taken_out_by_undo_stays_out_unless_changed_elsewhere() {
    let (file, _, _) = base();
    let mut mac = device(&file, 2000);
    let before = mac.to_bytes();
    let imported = mac.add_entry(login("Imported", "x"));
    let with_import = mac.to_bytes();
    // The phone got the import, then the Mac undid it.
    let phone = device(&with_import, 2000);
    mac.revert_to(&before).unwrap();
    let report = mac.merge_file(&phone.to_bytes(), Some(&with_import)).unwrap();
    assert!(!mac.entries().iter().any(|e| e.id == imported));
    assert_eq!(report.added, 0);
    assert_eq!(report.outgoing, 0);
}

#[test]
fn a_password_changed_on_one_device_comes_over_and_on_both_is_refused() {
    let (file, mail, _) = base();
    let mut phone = device(&file, 2000);
    phone.change_password(PASSWORD, b"new password").unwrap();
    let mut mac = device(&file, 2000);
    mac.update_entry(&mail, login("Mail", "mail-mac")).unwrap();
    let report = mac.merge_file(&phone.to_bytes(), Some(&file)).unwrap();
    assert_eq!(report.outgoing, 1);
    let written = mac.to_bytes();
    assert_eq!(Vault::open(&written, PASSWORD).err(), Some(VaultError::WrongPassword));
    assert_eq!(password(&Vault::open(&written, b"new password").unwrap(), &mail), b"mail-mac");

    // Changed on both, or with no base to tell: refused, nothing changes.
    let mut mac = device(&file, 2000);
    mac.change_password(PASSWORD, b"another one").unwrap();
    let before = contents(&mac);
    assert_eq!(mac.merge_file(&phone.to_bytes(), Some(&file)).err(), Some(VaultError::Diverged));
    assert_eq!(mac.merge_file(&phone.to_bytes(), None).err(), Some(VaultError::Diverged));
    assert!(contents(&mac) == before);
}

#[test]
fn another_vault_or_a_damaged_copy_is_refused() {
    let (file, _, _) = base();
    let (other, _, _) = base();
    let mut mac = device(&file, 2000);
    assert_eq!(mac.merge_file(&other, None).err(), Some(VaultError::Corrupted));
    let mut damaged = file.clone();
    let last = damaged.len() - 40;
    damaged[last] ^= 1;
    assert_eq!(mac.merge_file(&damaged, None).err(), Some(VaultError::Corrupted));
    // A damaged base only makes it a merge without one.
    assert_eq!(mac.merge_file(&file, Some(&damaged)).unwrap(), MergeReport::default());
}

#[test]
fn history_stays_ten_of_each_after_a_merge() {
    let (file, mail, _) = base();
    let mut mac = device(&file, 2000);
    let mut phone = device(&file, 2000);
    for step in 0..12 {
        at(&mut mac, 2000 + step);
        change(&mut mac, &mail, &format!("mac-{step}"));
        at(&mut phone, 3000 + step);
        change(&mut phone, &mail, &format!("phone-{step}"));
    }
    let (merged, _) = both_ways(&mac.to_bytes(), &phone.to_bytes(), Some(&file));
    let kept = history(&merged, &mail);
    assert_eq!(kept.len(), field::HISTORY_LEN);
    assert!(kept.iter().any(|h| h.ends_with("\nmac-11")), "the losing current password is kept");
    assert_eq!(password(&merged, &mail), b"phone-11");
}
