//! Passkeys (ADR-0010): registration's attestation object and a sign-in's signature, checked
//! against the public key the registration gave — as a site's server checks them.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use vault::{field, KdfParams, Vault, VaultError};

/// The public key out of the attestation object's COSE key: x and y.
fn public_key(attestation: &[u8]) -> (Vec<u8>, VerifyingKey) {
    // authData follows `68 "authData" 58 len` (our encoder) — find it.
    let marker = b"authData";
    let at = attestation.windows(marker.len()).position(|w| w == marker).unwrap() + marker.len();
    let len = attestation[at + 1] as usize;
    let auth = attestation[at + 2..at + 2 + len].to_vec();
    assert_eq!(&auth[..32], Sha256::digest(b"github.com").as_slice());
    assert_eq!(auth[32] & 0x45, 0x45, "UP, UV and AT set");
    let id_len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
    let cose = &auth[55 + id_len..];
    let x = &cose[10..42];
    let y = &cose[45..77];
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    (auth[55..55 + id_len].to_vec(), VerifyingKey::from_sec1_bytes(&sec1).unwrap())
}

#[test]
fn a_passkey_signs_in_and_its_key_stays_inside() {
    let mut vault = Vault::create(b"pw", KdfParams::TEST_ONLY).unwrap();
    let (entry, registration) =
        vault.passkey_register(None, "github.com", b"user-handle-1", "alex", "Alex").unwrap();
    assert!(registration.attestation_object.starts_with(b"\xA3\x63fmt\x64none"));
    let (credential_id, key) = public_key(&registration.attestation_object);
    assert_eq!(credential_id, registration.credential_id);

    // A new login for the site, the passkey concealed in it.
    let summary = vault.entries().iter().find(|e| e.id == entry).unwrap();
    assert_eq!(summary.title, "github.com");
    let fields = vault.fields(&entry).unwrap();
    let passkey = fields.iter().find(|f| f.name == field::PASSKEY).unwrap();
    assert!(passkey.concealed && passkey.value.is_none());

    let listed = vault.passkeys(Some("github.com"));
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].user_name, "alex");
    assert_eq!(listed[0].user_handle, b"user-handle-1");
    assert!(vault.passkeys(Some("example.com")).is_empty());

    let client_data_hash =
        Sha256::digest(br#"{"type":"webauthn.get","challenge":"abc","origin":"https://github.com"}"#);
    let (info, assertion) = vault.passkey_assert("github.com", &credential_id, &client_data_hash).unwrap();
    assert_eq!(info.entry, entry);
    assert_eq!(&assertion.authenticator_data[..32], Sha256::digest(b"github.com").as_slice());
    assert_eq!(assertion.authenticator_data.len(), 37);
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&client_data_hash);
    let signature = DerSignature::try_from(assertion.signature.as_slice()).unwrap();
    key.verify(&signed, &signature).unwrap();

    // Another site or credential: nothing.
    assert!(matches!(
        vault.passkey_assert("evil.com", &credential_id, &client_data_hash),
        Err(VaultError::NotFound)
    ));
    assert!(matches!(
        vault.passkey_assert("github.com", b"other", &client_data_hash),
        Err(VaultError::NotFound)
    ));

    // Survives saving and opening.
    let reopened = Vault::open(&vault.to_bytes(), b"pw").unwrap();
    let (_, again) = reopened.passkey_assert("github.com", &credential_id, &client_data_hash).unwrap();
    let mut signed = again.authenticator_data.clone();
    signed.extend_from_slice(&client_data_hash);
    key.verify(&signed, &DerSignature::try_from(again.signature.as_slice()).unwrap()).unwrap();
}

#[test]
fn a_passkey_joins_an_existing_login() {
    let mut vault = Vault::create(b"pw", KdfParams::TEST_ONLY).unwrap();
    let login = vault.add_entry(vault::NewEntry {
        kind: vault::EntryKind::Login,
        title: "GitHub".into(),
        fields: vec![vault::Field {
            name: field::USERNAME.into(),
            value: b"alex".to_vec(),
            concealed: false,
            custom: false,
        }],
    });
    let (entry, _) = vault.passkey_register(Some(&login), "github.com", b"h", "alex", "Alex").unwrap();
    assert_eq!(entry, login);
    assert_eq!(vault.entries().len(), 1);
    assert_eq!(vault.fields(&login).unwrap().iter().filter(|f| f.name == field::PASSKEY).count(), 1);
}

/// Writes a registration and an assertion to `$PASSKEY_OUT` as hex JSON, for another
/// implementation to check: `PASSKEY_OUT=/tmp/pk.json cargo test --test passkey -- --ignored`.
#[test]
#[ignore]
fn writes_a_passkey_for_another_check() {
    let Ok(path) = std::env::var("PASSKEY_OUT") else { return };
    let mut vault = Vault::create(b"pw", KdfParams::TEST_ONLY).unwrap();
    let (_, registration) = vault.passkey_register(None, "github.com", b"h", "alex", "Alex").unwrap();
    let client_data_hash = Sha256::digest(b"client data");
    let (_, assertion) =
        vault.passkey_assert("github.com", &registration.credential_id, &client_data_hash).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let json = format!(
        r#"{{"attestation":"{}","auth":"{}","sig":"{}","cdh":"{}"}}"#,
        hex(&registration.attestation_object),
        hex(&assertion.authenticator_data),
        hex(&assertion.signature),
        hex(&client_data_hash)
    );
    std::fs::write(path, json).unwrap();
}
