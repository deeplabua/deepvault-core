//! SSH keys (ADR-0006) against keys `ssh-keygen` made (tests/fixtures/ssh): the same public line
//! and fingerprint, signatures the public key verifies, and a key made here that `ssh-keygen`
//! reads back.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use vault::ssh::{self, Ed25519Key, KeyError, PrivateKey};
use vault::{field, EntryKind, KdfParams, SystemEntropy, Vault, VaultError};

const PASSWORD: &[u8] = b"correct horse battery staple";
const PARAMS: KdfParams = KdfParams::TEST_ONLY;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/../../tests/fixtures/ssh/{name}", env!("CARGO_MANIFEST_DIR")))
        .unwrap()
}

/// The signature in an SSH signature blob, checked against the public blob's key.
fn verifies(public_blob: &[u8], data: &[u8], signature_blob: &[u8]) -> bool {
    let key: [u8; 32] = public_blob[public_blob.len() - 32..].try_into().unwrap();
    let signature: [u8; 64] = signature_blob[signature_blob.len() - 64..].try_into().unwrap();
    VerifyingKey::from_bytes(&key).unwrap().verify(data, &Signature::from_bytes(&signature)).is_ok()
}

#[test]
fn a_key_from_ssh_keygen_reads_as_ssh_keygen_sees_it() {
    let key = Ed25519Key::from_openssh(&fixture("ed25519")).unwrap();
    assert_eq!(key.public_line(), fixture("ed25519.pub").trim());
    assert_eq!(key.fingerprint(), fixture("ed25519.fingerprint").trim());
    assert_eq!(key.comment, "fixture@deepvault");
    let signature = key.sign(b"data to sign");
    assert!(signature.starts_with(&[0, 0, 0, 11]) && signature[4..15] == *b"ssh-ed25519");
    assert!(verifies(&key.public_blob(), b"data to sign", &signature));
    assert!(!verifies(&key.public_blob(), b"other data", &signature));
    assert_eq!(ssh::blob_of_line(&key.public_line()).unwrap(), key.public_blob());
}

#[test]
fn a_passphrase_or_another_type_is_said_so() {
    assert_eq!(Ed25519Key::from_openssh(&fixture("ed25519_passphrase")).err(), Some(KeyError::Encrypted));
    assert_eq!(Ed25519Key::from_openssh(&fixture("rsa")).err(), Some(KeyError::Unsupported));
    assert_eq!(Ed25519Key::from_openssh("not a key").err(), Some(KeyError::Invalid));
}

#[test]
fn a_key_made_here_is_read_by_ssh_keygen() {
    let key = Ed25519Key::generate(&mut SystemEntropy, "made@deepvault");
    let text = key.to_openssh(&mut SystemEntropy);
    // Our own reader first, then the real one when it is installed.
    assert_eq!(Ed25519Key::from_openssh(&text).unwrap().public_line(), key.public_line());
    let dir = std::env::temp_dir().join(format!("dv-ssh-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("key");
    std::fs::write(&path, text.as_bytes()).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    if let Ok(out) = std::process::Command::new("ssh-keygen").arg("-y").arg("-f").arg(&path).output() {
        assert!(out.status.success(), "ssh-keygen did not read the key");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), key.public_line());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_vault_signs_with_a_key_it_never_hands_out() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let made = vault.add_ssh_key("GitHub", "alice@mac");
    let imported = vault.import_ssh_key("Fixture", fixture("ed25519").as_bytes()).unwrap();
    assert_eq!(
        vault.import_ssh_key("x", fixture("ed25519_passphrase").as_bytes()).err(),
        Some(VaultError::EncryptedSshKey)
    );

    let reopened = Vault::open(&vault.to_bytes(), PASSWORD).unwrap();
    assert!(reopened.entries().iter().all(|e| e.kind == EntryKind::SshKey));
    let fields = reopened.fields(&imported).unwrap();
    // The private half is concealed; the public line is in the clear for the agent's list.
    assert!(fields.iter().any(|f| f.name == field::SSH_PRIVATE_KEY && f.concealed && f.value.is_none()));
    let public = fields.iter().find(|f| f.name == field::SSH_PUBLIC_KEY).unwrap().value.clone().unwrap();
    assert_eq!(public, fixture("ed25519.pub").trim());

    let signature = reopened.ssh_sign(&imported, b"challenge", 0).unwrap();
    assert!(verifies(&ssh::blob_of_line(&public).unwrap(), b"challenge", &signature));
    let made_public = reopened.secret(&made, field::SSH_PUBLIC_KEY).unwrap();
    let made_line = std::str::from_utf8(made_public.expose()).unwrap().to_string();
    assert!(made_line.starts_with("ssh-ed25519 ") && made_line.ends_with(" alice@mac"));
    assert!(verifies(
        &ssh::blob_of_line(&made_line).unwrap(),
        b"x",
        &reopened.ssh_sign(&made, b"x", 0).unwrap()
    ));
}

/// An RSA signature blob (`string name string sig`) checked against the public blob
/// (`string "ssh-rsa" mpint e mpint n`), with the hash the name says.
fn rsa_verifies(public_blob: &[u8], data: &[u8], signature_blob: &[u8]) -> bool {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    fn strings(mut bytes: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        while bytes.len() >= 4 {
            let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            out.push(&bytes[4..4 + len]);
            bytes = &bytes[4 + len..];
        }
        out
    }
    // An mpint's magnitude, without the sign byte: the key's size is the modulus's.
    let magnitude =
        |mpint: &[u8]| rsa::BoxedUint::from_be_slice_vartime(mpint.strip_prefix(&[0]).unwrap_or(mpint));
    let public = strings(public_blob);
    let key = rsa::RsaPublicKey::new(magnitude(public[2]), magnitude(public[1])).unwrap();
    let signature = strings(signature_blob);
    let Ok(sig) = Signature::try_from(signature[1]) else { return false };
    match signature[0] {
        b"rsa-sha2-256" => VerifyingKey::<sha2::Sha256>::new(key).verify(data, &sig).is_ok(),
        b"rsa-sha2-512" => VerifyingKey::<sha2::Sha512>::new(key).verify(data, &sig).is_ok(),
        _ => false,
    }
}

#[test]
fn an_rsa_key_from_ssh_keygen_signs_sha2_only() {
    let key = PrivateKey::from_openssh(&fixture("rsa3072")).unwrap();
    assert_eq!(key.public_line(), fixture("rsa3072.pub").trim());
    assert_eq!(key.fingerprint(), fixture("rsa3072.fingerprint").trim());
    for (flags, name) in [(ssh::RSA_SHA2_256, "rsa-sha2-256"), (ssh::RSA_SHA2_512, "rsa-sha2-512")] {
        let signature = key.sign(b"data to sign", flags).unwrap();
        assert_eq!(&signature[4..4 + name.len()], name.as_bytes());
        assert!(rsa_verifies(&key.public_blob(), b"data to sign", &signature));
        assert!(!rsa_verifies(&key.public_blob(), b"other data", &signature));
    }
    // Both asked: the stronger.
    let both = key.sign(b"x", ssh::RSA_SHA2_256 | ssh::RSA_SHA2_512).unwrap();
    assert_eq!(&both[4..16], b"rsa-sha2-512");
    // No flag is SHA-1 (`ssh-rsa`): refused.
    assert_eq!(key.sign(b"x", 0).err(), Some(KeyError::Unsupported));
    // 1024 bits: refused at import.
    assert_eq!(PrivateKey::from_openssh(&fixture("rsa")).err(), Some(KeyError::Unsupported));
}

#[test]
fn an_rsa_key_kept_in_the_vault_is_read_by_ssh_keygen() {
    let mut vault = Vault::create(PASSWORD, PARAMS).unwrap();
    let id = vault.import_ssh_key("Old server", fixture("rsa3072").as_bytes()).unwrap();
    let reopened = Vault::open(&vault.to_bytes(), PASSWORD).unwrap();
    let fields = reopened.fields(&id).unwrap();
    let public = fields.iter().find(|f| f.name == field::SSH_PUBLIC_KEY).unwrap().value.clone().unwrap();
    assert_eq!(public, fixture("rsa3072.pub").trim());
    let signature = reopened.ssh_sign(&id, b"challenge", ssh::RSA_SHA2_512).unwrap();
    assert!(rsa_verifies(&ssh::blob_of_line(&public).unwrap(), b"challenge", &signature));

    // What the vault stores is a key ssh-keygen reads back to the same public line.
    let key = PrivateKey::from_openssh(&fixture("rsa3072")).unwrap();
    let text = key.to_openssh(&mut SystemEntropy);
    assert_eq!(PrivateKey::from_openssh(&text).unwrap().public_line(), key.public_line());
    let dir = std::env::temp_dir().join(format!("dv-ssh-rsa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("key");
    std::fs::write(&path, text.as_bytes()).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    if let Ok(out) = std::process::Command::new("ssh-keygen").arg("-y").arg("-f").arg(&path).output() {
        assert!(out.status.success(), "ssh-keygen did not read the key");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), key.public_line());
    }
    std::fs::remove_dir_all(dir).unwrap();
}
