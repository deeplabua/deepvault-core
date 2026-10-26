//! Other password managers' exports (CSV, Secrets' XML), with made-up data in each one's shape.

use vault::field;
use vault::import::{parse, Format, Imported};
use vault::{EntryKind, NewEntry, VaultError};

const SECRET: &str = "JBSWY3DPEHPK3PXP";

fn import(text: &str) -> Imported {
    parse(text.as_bytes()).unwrap()
}

/// `(name, value, concealed, custom)` of each field.
fn fields(entry: &NewEntry) -> Vec<(String, String, bool, bool)> {
    entry
        .fields
        .iter()
        .map(|f| (f.name.clone(), String::from_utf8(f.value.clone()).unwrap(), f.concealed, f.custom))
        .collect()
}

fn known(name: &str, value: &str, concealed: bool) -> (String, String, bool, bool) {
    (name.into(), value.into(), concealed, false)
}

#[test]
fn bitwarden() {
    let csv = format!(
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         Work,1,login,GitLab,\"line one\nline two\",\"Recovery: abc-123\nPIN: 0000\",0,\"https://gitlab.com/users/sign_in,https://gitlab.example.org\",alice,s3cret,{SECRET}\n\
         ,,note,Wi-Fi,network: home,,0,,,,\n\
         ,,card,Visa,,,0,,,,\n"
    );
    let imported = import(&csv);
    assert_eq!(imported.format, Format::Bitwarden);
    assert_eq!(imported.skipped, 1);
    let [gitlab, wifi] = &imported.entries[..] else { panic!("two entries") };
    assert_eq!(gitlab.kind, EntryKind::Login);
    assert_eq!(gitlab.title, "GitLab");
    assert_eq!(
        fields(gitlab),
        vec![
            known(field::USERNAME, "alice", false),
            known(field::PASSWORD, "s3cret", true),
            known(field::TOTP, SECRET, true),
            known(field::URL, "https://gitlab.com/users/sign_in", false),
            known(field::URL, "https://gitlab.example.org", false),
            known(field::NOTES, "line one\nline two", true),
            ("Recovery".into(), "abc-123".into(), true, true),
            ("PIN".into(), "0000".into(), true, true),
            known(field::TAG, "Work", false),
        ]
    );
    assert_eq!(wifi.kind, EntryKind::Note);
    assert_eq!(fields(wifi), vec![known(field::NOTES, "network: home", true)]);
}

#[test]
fn one_password() {
    let csv = format!(
        "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\r\n\
         Stripe,https://dashboard.stripe.com,bob@example.com,\"p,a\"\"ss\",otpauth://totp/Stripe?secret={SECRET},false,false,\"work;billing\",\r\n"
    );
    let imported = import(&csv);
    assert_eq!(imported.format, Format::OnePassword);
    let stripe = &imported.entries[0];
    assert_eq!(
        fields(stripe),
        vec![
            known(field::USERNAME, "bob@example.com", false),
            known(field::PASSWORD, "p,a\"ss", true),
            known(field::TOTP, &format!("otpauth://totp/Stripe?secret={SECRET}"), true),
            known(field::URL, "https://dashboard.stripe.com", false),
            known(field::TAG, "work", false),
            known(field::TAG, "billing", false),
        ]
    );
}

#[test]
fn apple_passwords_with_a_bom() {
    let imported = import("\u{feff}Title,URL,Username,Password,Notes,OTPAuth\napple.com,https://appleid.apple.com/,me@icloud.com,abcd-efgh-ijkl-mnop,App-specific: Thunderbird,not a code\n");
    assert_eq!(imported.format, Format::Apple);
    assert_eq!(
        fields(&imported.entries[0]),
        vec![
            known(field::USERNAME, "me@icloud.com", false),
            known(field::PASSWORD, "abcd-efgh-ijkl-mnop", true),
            // Not a TOTP secret: kept, as the user's own field.
            ("OTP".into(), "not a code".into(), true, true),
            known(field::URL, "https://appleid.apple.com/", false),
            known(field::NOTES, "App-specific: Thunderbird", true),
        ]
    );
}

#[test]
fn chrome_and_firefox_titles_from_the_site() {
    let chrome = import("name,url,username,password,note\n,https://www.github.com/login,carol,pw1,\n");
    assert_eq!(chrome.format, Format::Chrome);
    assert_eq!(chrome.entries[0].title, "github.com");

    let firefox = import(
        "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
         \"https://news.example.org\",\"dave\",\"pw2\",,\"https://news.example.org\",\"{x}\",\"1\",\"1\",\"1\"\n",
    );
    assert_eq!(firefox.format, Format::Firefox);
    assert_eq!(firefox.entries[0].title, "news.example.org");
    assert_eq!(fields(&firefox.entries[0])[1], known(field::PASSWORD, "pw2", true));
}

#[test]
fn rows_without_anything_are_skipped_and_blank_lines_ignored() {
    let imported = import("title,url,username,password\nOnly a title,,,\n\n,,,\nKept,,,pw\n");
    assert_eq!(imported.format, Format::Other);
    assert_eq!(imported.skipped, 1);
    assert_eq!(imported.entries.len(), 1);
    assert_eq!(imported.entries[0].title, "Kept");
}

#[test]
fn not_a_password_export() {
    assert_eq!(parse(b"a,b,c\n1,2,3\n").err(), Some(VaultError::InvalidImport));
    assert_eq!(parse(b"").err(), Some(VaultError::InvalidImport));
    assert_eq!(parse(b"title,password\n\"unterminated,x\n").err(), Some(VaultError::InvalidImport));
}

#[test]
fn secrets_xml() {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<secrets>
  <credentials>
    <credential>
      <creationDate>2026-07-06T14:18:41.183Z</creationDate>
      <favorite>0</favorite>
      <identifier>alice@example.com</identifier>
      <name>reve.com</name>
      <notes>key: sk_test_&amp;123</notes>
      <passkeyEnabled>0</passkeyEnabled>
      <secrets>
        <secret><archived>1</archived><kind>0</kind><secretValue>old-password</secretValue></secret>
        <secret><archived>0</archived><kind>0</kind><secretValue>rR&amp;d7Y&amp;d>9{{</secretValue></secret>
        <secret><archived>0</archived><kind>3</kind><secretValue>{SECRET}</secretValue></secret>
        <secret><archived>0</archived><kind>7</kind><secretValue>1234</secretValue></secret>
      </secrets>
      <services>
        <service><address>https://app.reve.com/</address></service>
        <service><address>https://reve.com</address></service>
      </services>
      <securityQuestion>Pet's name</securityQuestion>
      <tags>
        <tag><creationDate>2026-01-01T00:00:00.000Z</creationDate><name>work</name><uuid>A1</uuid></tag>
        <tag><name> ai </name></tag>
      </tags>
      <trashed>0</trashed>
      <uuid>3ED31704-FA88-426D-95B2-C2ACA1EED02F</uuid>
    </credential>
    <credential>
      <archived>1</archived>
      <identifier>IoT</identifier>
      <name></name>
      <oneTimePassword><algorithm>SHA256</algorithm><digits>8</digits><period>30</period><seed>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=</seed></oneTimePassword>
      <secrets><secret><kind>0</kind><secretValue>wifi-pass</secretValue></secret></secrets>
      <services><service><address>https://router.example.org/admin</address></service></services>
      <trashed>0</trashed>
    </credential>
    <credential>
      <builtinServiceLogo>mail</builtinServiceLogo>
      <name>Mail</name>
      <oneTimePasswords><oneTimePassword><algorithm>SHA1</algorithm><digits>6</digits><period>30</period><seed>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=</seed></oneTimePassword></oneTimePasswords>
      <passkeyEnabled>0</passkeyEnabled>
      <trashed>0</trashed>
    </credential>
    <credential>
      <name></name>
      <services><service><address>https://%3chtml%3e%3chead%3e</address></service></services>
      <trashed>0</trashed>
    </credential>
    <credential>
      <name>Deleted</name>
      <secrets><secret><kind>0</kind><secretValue>gone</secretValue></secret></secrets>
      <trashed>1</trashed>
    </credential>
  </credentials>
  <creditCards>
    <creditCard>
      <brand>visa</brand>
      <cardholder>ALICE EXAMPLE</cardholder>
      <expirationDate>2029-05-31T23:59:59.000Z</expirationDate>
      <name>Monobank</name>
      <notes>limit 1000</notes>
      <pan>4111 1111 1111 1111</pan>
      <securityCode>123</securityCode>
      <trashed>0</trashed>
    </creditCard>
  </creditCards>
  <notes>
    <note>
      <tags><tag><name>servers</name></tag></tags>
      <text>Password: x&lt;y
second line</text>
      <title>gitlab</title>
      <trashed>0</trashed>
    </note>
    <note><title>Empty</title><trashed>0</trashed></note>
    <note><text>gone</text><title>Old</title><trashed>1</trashed></note>
  </notes>
</secrets>"#
    );
    let imported = import(&xml);
    assert_eq!(imported.format, Format::Secrets);
    // The trashed login and note, and the login with only a broken address (no name, no site
    // to name it by).
    assert_eq!(imported.skipped, 3);
    let [reve, router, mail, card, gitlab, empty] = &imported.entries[..] else { panic!("six entries") };
    assert_eq!(reve.title, "reve.com");
    assert_eq!(
        fields(reve),
        vec![
            known(field::USERNAME, "alice@example.com", false),
            known(field::PASSWORD, "rR&d7Y&d>9{", true),
            known(field::TOTP, SECRET, true),
            known(field::URL, "https://app.reve.com/", false),
            known(field::URL, "https://reve.com", false),
            known(field::NOTES, "key: sk_test_&123", true),
            ("Secret".into(), "1234".into(), true, true),
            ("securityQuestion".into(), "Pet's name".into(), true, true),
            known(field::TAG, "work", false),
            known(field::TAG, "ai", false),
        ]
    );
    // No name: the site's host; archived: kept, tagged.
    assert_eq!(router.title, "router.example.org");
    assert_eq!(fields(router).last().unwrap(), &known(field::TAG, "archived", false));
    // The seed is base64 in Secrets, base32 here; unusual settings make an otpauth link.
    const RFC_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    assert!(fields(router).contains(&known(
        field::TOTP,
        &format!("otpauth://totp/?secret={RFC_SEED}&algorithm=SHA256&digits=8&period=30"),
        true
    )));
    // The logo's name and the passkey flag are Secrets' own, not the item's.
    assert_eq!(fields(mail), vec![known(field::TOTP, RFC_SEED, true)]);

    // A card: the number as digits, the expiry as the app writes it; the brand is the number's.
    assert_eq!((card.kind, card.title.as_str()), (EntryKind::Card, "Monobank"));
    assert_eq!(
        fields(card),
        vec![
            known(field::CARDHOLDER, "ALICE EXAMPLE", false),
            known(field::NUMBER, "4111111111111111", true),
            known(field::EXPIRY, "05/29", false),
            known(field::CVV, "123", true),
            known(field::NOTES, "limit 1000", true),
        ]
    );
    // Secure notes, one with only a title.
    assert_eq!((gitlab.kind, gitlab.title.as_str()), (EntryKind::Note, "gitlab"));
    assert_eq!(
        fields(gitlab),
        vec![known(field::NOTES, "Password: x<y\nsecond line", true), known(field::TAG, "servers", false)]
    );
    assert_eq!((empty.kind, empty.title.as_str(), fields(empty).len()), (EntryKind::Note, "Empty", 0));
}

#[test]
fn xml_that_is_not_a_secrets_export() {
    assert_eq!(parse(b"<html><body>hi</body></html>").err(), Some(VaultError::InvalidImport));
    assert_eq!(parse(b"<a><b></a>").err(), Some(VaultError::InvalidImport));
}

/// The new entries of an import get its label as a tag; those the vault had do not.
#[test]
fn an_import_label_tags_only_what_is_new() {
    let mut vault = vault::Vault::create(b"pw", vault::KdfParams::TEST_ONLY).unwrap();
    let login = |title: &str| vault::NewEntry {
        kind: vault::EntryKind::Login,
        title: title.into(),
        fields: vec![vault::Field {
            name: field::USERNAME.into(),
            value: b"alex".to_vec(),
            concealed: false,
            custom: false,
        }],
    };
    vault.import(vec![login("GitHub")]).unwrap();
    let merged = vault
        .import_labelled(vec![login("GitHub"), login("GitLab")], Some("Imported from Passwords"))
        .unwrap();
    assert_eq!((merged.added, merged.matched), (1, 1));
    let tagged: Vec<_> = vault
        .entries()
        .iter()
        .filter(|e| e.tags.iter().any(|t| t == "Imported from Passwords"))
        .map(|e| e.title.clone())
        .collect();
    assert_eq!(tagged, ["GitLab"]);
}
