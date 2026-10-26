//! KeePass KDBX files (ADR-0008) made by another implementation (`tests/fixtures/kdbx/make.py`:
//! pykeepass, and a KDBX 3.1 writer with pycryptodome) read here; a vault written as KDBX
//! read back. Every secret is made up.

use std::path::PathBuf;

use vault::kdbx::{self, Key};
use vault::{field, EntryKind, Field, KdfParams, NewEntry, Vault, VaultError};

const PASSWORD: &[u8] = b"test-password-4";

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kdbx").join(name);
    std::fs::read(path).unwrap()
}

fn key() -> Key<'static> {
    Key { password: Some(PASSWORD), key_file: None }
}

fn value<'a>(entry: &'a NewEntry, name: &str) -> Option<&'a str> {
    entry.fields.iter().find(|f| f.name == name).map(|f| std::str::from_utf8(&f.value).unwrap())
}

fn values<'a>(entry: &'a NewEntry, name: &str) -> Vec<&'a str> {
    entry
        .fields
        .iter()
        .filter(|f| f.name == name)
        .map(|f| std::str::from_utf8(&f.value).unwrap_or("<bytes>"))
        .collect()
}

fn check_v4(file: &[u8], key: &Key) {
    let imported = kdbx::read(file, key).unwrap();
    // The recycle bin's entry is left out.
    assert_eq!(imported.skipped, 1);
    let titles: Vec<&str> = imported.entries.iter().map(|e| e.title.as_str()).collect();
    assert_eq!(imported.entries.len(), 4, "{titles:?}");
    let github = imported.entries.iter().find(|e| e.title == "GitHub").unwrap();
    assert_eq!(github.kind, EntryKind::Login);
    assert_eq!(value(github, field::USERNAME), Some("alex"));
    // The current password, not the history's.
    assert_eq!(value(github, field::PASSWORD), Some("gh-Secret-2!"));
    assert_eq!(value(github, field::URL), Some("https://github.com/login"));
    assert_eq!(value(github, field::NOTES), Some("Personal account"));
    assert!(value(github, field::TOTP).unwrap().contains("JBSWY3DPEHPK3PXP"));
    let recovery = github.fields.iter().find(|f| f.name == "Recovery code").unwrap();
    assert!(recovery.custom && recovery.concealed);
    assert_eq!(recovery.value, b"rc-1234-5678");
    assert_eq!(value(github, "Plan"), Some("Pro"));
    assert_eq!(values(github, field::TAG), vec!["Work", "dev", "code"]);
    let db = imported.entries.iter().find(|e| e.title == "db-1").unwrap();
    assert_eq!(values(db, field::TAG), vec!["Work/Servers"]);
    assert_eq!(value(db, field::PASSWORD), Some("Db!Root#9"));
    let wifi = imported.entries.iter().find(|e| e.title == "Wi-Fi").unwrap();
    assert_eq!(wifi.kind, EntryKind::Note);
    let passport = imported.entries.iter().find(|e| e.title == "Passport").unwrap();
    let file = passport.fields.iter().find(|f| f.name == "attachment").unwrap();
    assert!(file.value.starts_with(b"passport.pdf\0%PDF-1.4 made-up passport scan"));
}

#[test]
fn reads_kdbx4_with_aes_and_argon2d() {
    check_v4(&fixture("v4-aes-argon2d.kdbx"), &key());
}

#[test]
fn reads_kdbx4_with_chacha20_and_argon2id() {
    check_v4(&fixture("v4-chacha20-argon2id.kdbx"), &key());
}

#[test]
fn reads_kdbx4_with_a_key_file() {
    let key_file = fixture("v4.keyx");
    check_v4(&fixture("v4-keyfile.kdbx"), &Key { password: Some(PASSWORD), key_file: Some(&key_file) });
    // The password alone does not open it.
    assert!(matches!(kdbx::read(&fixture("v4-keyfile.kdbx"), &key()), Err(VaultError::WrongPassword)));
}

#[test]
fn reads_kdbx3_with_aes_kdf_and_salsa20() {
    let imported = kdbx::read(&fixture("v3-aes-kdf.kdbx"), &key()).unwrap();
    assert_eq!(imported.entries.len(), 1);
    let mail = &imported.entries[0];
    assert_eq!(mail.title, "Old Mail");
    assert_eq!(value(mail, field::PASSWORD), Some("mail-Pass-3!"));
    assert_eq!(value(mail, field::USERNAME), Some("alex@example.com"));
    assert_eq!(values(mail, field::TAG), vec!["legacy"]);
}

#[test]
fn a_wrong_password_or_another_file_is_said_so() {
    let wrong = Key { password: Some(b"nope"), key_file: None };
    assert!(matches!(kdbx::read(&fixture("v4-aes-argon2d.kdbx"), &wrong), Err(VaultError::WrongPassword)));
    assert!(matches!(kdbx::read(&fixture("v3-aes-kdf.kdbx"), &wrong), Err(VaultError::WrongPassword)));
    assert!(matches!(kdbx::read(b"title,password\n", &key()), Err(VaultError::InvalidImport)));
    let mut damaged = fixture("v4-chacha20-argon2id.kdbx");
    let last = damaged.len() - 40;
    damaged[last] ^= 1;
    assert!(matches!(kdbx::read(&damaged, &key()), Err(VaultError::Corrupted)));
}

#[test]
fn an_export_comes_back_with_every_kind() {
    let mut vault = Vault::create(b"pw", KdfParams::TEST_ONLY).unwrap();
    let f = |name: &str, value: &str, concealed: bool, custom: bool| Field {
        name: name.into(),
        value: value.as_bytes().to_vec(),
        concealed,
        custom,
    };
    vault.add_entry(NewEntry {
        kind: EntryKind::Login,
        title: "Shop & Co <test>".into(),
        fields: vec![
            f(field::USERNAME, "me", false, false),
            f(field::PASSWORD, "s3cret!", true, false),
            f(field::URL, "https://shop.example.com", false, false),
            f(field::URL, "https://m.shop.example.com", false, false),
            f(field::TOTP, "JBSWY3DPEHPK3PXP", true, false),
            f(field::TAG, "shopping", false, false),
            f("PIN hint", "birthday", true, true),
            Field {
                name: "attachment".into(),
                value: b"receipt.txt\0paid".to_vec(),
                concealed: true,
                custom: false,
            },
        ],
    });
    vault.add_entry(NewEntry {
        kind: EntryKind::Card,
        title: "Visa".into(),
        fields: vec![
            f(field::CARDHOLDER, "ALEX", false, false),
            f(field::NUMBER, "4242424242424242", true, false),
            f(field::CVV, "123", true, false),
        ],
    });
    vault.add_entry(NewEntry {
        kind: EntryKind::Environment,
        title: "Stripe".into(),
        fields: vec![f("STRIPE_KEY", "sk_test_1", true, true), f(field::SHELL, "STRIPE_KEY", false, false)],
    });
    let password: &[u8] = b"export-pass";
    let file = vault.export_kdbx(&Key { password: Some(password), key_file: None }).unwrap();
    let imported = kdbx::read(&file, &Key { password: Some(password), key_file: None }).unwrap();
    assert_eq!(imported.entries.len(), 3);
    let shop = imported.entries.iter().find(|e| e.title == "Shop & Co <test>").unwrap();
    assert_eq!(shop.kind, EntryKind::Login);
    assert_eq!(value(shop, field::PASSWORD), Some("s3cret!"));
    assert_eq!(values(shop, field::URL), vec!["https://shop.example.com", "https://m.shop.example.com"]);
    assert!(value(shop, field::TOTP).unwrap().contains("secret=JBSWY3DPEHPK3PXP"));
    assert_eq!(values(shop, field::TAG), vec!["shopping"]);
    let hint = shop.fields.iter().find(|f| f.name == "PIN hint").unwrap();
    assert!(hint.custom && hint.concealed);
    assert_eq!(shop.fields.iter().find(|f| f.name == "attachment").unwrap().value, b"receipt.txt\0paid");
    let visa = imported.entries.iter().find(|e| e.title == "Visa").unwrap();
    assert_eq!(visa.kind, EntryKind::Card);
    let number = visa.fields.iter().find(|f| f.name == field::NUMBER).unwrap();
    assert!(!number.custom && number.concealed && number.value == b"4242424242424242");
    let stripe = imported.entries.iter().find(|e| e.title == "Stripe").unwrap();
    assert_eq!(stripe.kind, EntryKind::Environment);
    assert!(stripe.fields.iter().any(|f| f.name == "STRIPE_KEY" && f.custom && f.value == b"sk_test_1"));
    assert!(stripe.fields.iter().any(|f| f.name == field::SHELL && !f.custom));
}

/// Writes an export to `$KDBX_OUT` for another implementation to open (`make.py` checks it):
/// `KDBX_OUT=/tmp/out.kdbx cargo test --test kdbx -- --ignored`.
#[test]
#[ignore]
fn writes_an_export_for_keepass() {
    let Ok(path) = std::env::var("KDBX_OUT") else { return };
    let mut vault = Vault::create(b"pw", KdfParams::TEST_ONLY).unwrap();
    vault.add_entry(NewEntry {
        kind: EntryKind::Login,
        title: "GitHub".into(),
        fields: vec![
            Field { name: field::USERNAME.into(), value: b"alex".to_vec(), concealed: false, custom: false },
            Field {
                name: field::PASSWORD.into(),
                value: b"gh-Secret-1!".to_vec(),
                concealed: true,
                custom: false,
            },
            Field {
                name: field::URL.into(),
                value: b"https://github.com".to_vec(),
                concealed: false,
                custom: false,
            },
            Field { name: field::TAG.into(), value: b"dev".to_vec(), concealed: false, custom: false },
            Field {
                name: "attachment".into(),
                value: b"note.txt\0hello".to_vec(),
                concealed: true,
                custom: false,
            },
        ],
    });
    let file = vault.export_kdbx(&Key { password: Some(PASSWORD), key_file: None }).unwrap();
    std::fs::write(path, file).unwrap();
}
