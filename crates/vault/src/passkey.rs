//! Passkeys (ADR-0010): a WebAuthn credential kept in a login as a concealed `passkey` field —
//! its site, its id, the user it is for and its P-256 private key — signed here, so the key
//! never leaves the core. Synced like any value: a passkey in DeepVault is not bound to one Mac.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::entropy::Entropy;
use crate::error::{Result, VaultError};
use crate::format::cbor_bytes;
use crate::ssh::{base64_decode, base64_encode};

/// DeepVault's authenticator id in registrations: sites show «DeepVault» when it is listed in
/// the passkey authenticator AAGUID list. Constant for every passkey DeepVault makes.
pub const AAGUID: [u8; 16] =
    [0xd5, 0x3e, 0x7a, 0x41, 0x8c, 0x2f, 0x4b, 0x6e, 0x9a, 0x07, 0x3c, 0x51, 0xe2, 0x94, 0x6b, 0x1f];

/// Flags in authenticator data: user present, user verified (Touch ID), backup eligible and
/// backed up (it lives in a file that may be synced), attested credential data (registration).
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

/// What a `passkey` field holds, as CBOR. No `Debug`: it holds the private key.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Passkey {
    pub rp_id: String,
    #[serde(with = "cbor_bytes")]
    pub credential_id: Vec<u8>,
    #[serde(with = "cbor_bytes")]
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display: String,
    #[serde(with = "cbor_bytes")]
    key: Vec<u8>,
    #[zeroize(skip)]
    pub created: u64,
}

/// A registration's result for the platform: the new credential's id and the attestation object
/// (fmt `none`) with its public key.
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// An assertion's result: authenticator data and the DER signature over it and the client data hash.
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Passkey {
    /// A new passkey for `rp_id` and the user, its key from `entropy`.
    pub fn new(
        rp_id: &str,
        user_handle: &[u8],
        user_name: &str,
        user_display: &str,
        entropy: &mut dyn Entropy,
    ) -> Self {
        let mut credential_id = vec![0u8; 16];
        entropy.fill(&mut credential_id);
        let mut key = Zeroizing::new([0u8; 32]);
        loop {
            entropy.fill(key.as_mut());
            // Almost every 32 bytes is a valid scalar; zero and values above the order are not.
            if SigningKey::from_slice(key.as_ref()).is_ok() {
                break;
            }
        }
        Passkey {
            rp_id: rp_id.into(),
            credential_id,
            user_handle: user_handle.to_vec(),
            user_name: user_name.into(),
            user_display: user_display.into(),
            key: key.to_vec(),
            created: entropy.now(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|_| VaultError::Corrupted)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).expect("CBOR into a Vec does not fail");
        out
    }

    fn signing_key(&self) -> Result<SigningKey> {
        SigningKey::from_slice(&self.key).map_err(|_| VaultError::Corrupted)
    }

    /// A passkey another manager made (KeePassXC, Apple's Passwords): its key from PKCS#8.
    /// `None` when the key is not a P-256 key.
    pub fn imported(
        rp_id: &str,
        credential_id: &[u8],
        user_handle: &[u8],
        user_name: &str,
        user_display: &str,
        pkcs8: &[u8],
        created: u64,
    ) -> Option<Self> {
        let key = scalar_from_pkcs8(pkcs8)?;
        Some(Passkey {
            rp_id: rp_id.into(),
            credential_id: credential_id.to_vec(),
            user_handle: user_handle.to_vec(),
            user_name: user_name.into(),
            user_display: user_display.into(),
            key: key.to_vec(),
            created,
        })
    }

    /// The private key as PKCS#8 DER (with its public key), for an export that carries
    /// passkeys — KeePassXC's `KPEX_PASSKEY_PRIVATE_KEY_PEM`.
    pub fn pkcs8(&self) -> Result<Zeroizing<Vec<u8>>> {
        let point = self.signing_key()?.verifying_key().to_sec1_point(false);
        let mut out = Zeroizing::new(PKCS8_HEAD.to_vec());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&[0xA1, 0x44, 0x03, 0x42, 0x00]);
        out.extend_from_slice(point.as_bytes());
        Ok(out)
    }

    /// The private key as a PEM `PRIVATE KEY` block.
    pub fn pem(&self) -> Result<Zeroizing<String>> {
        let der = self.pkcs8()?;
        let body = Zeroizing::new(base64_encode(&der));
        let mut out = Zeroizing::new(String::from("-----BEGIN PRIVATE KEY-----\n"));
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        Ok(out)
    }

    /// The public key as COSE_Key (EC2, ES256, P-256).
    pub fn cose_public_key(&self) -> Result<Vec<u8>> {
        let point = self.signing_key()?.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        let (x, y) = (&bytes[1..33], &bytes[33..65]);
        // {1: 2, 3: -7, -1: 1, -2: x, -3: y}, canonical order.
        let mut out = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        out.extend_from_slice(x);
        out.extend_from_slice(&[0x22, 0x58, 0x20]);
        out.extend_from_slice(y);
        Ok(out)
    }

    /// The attestation object of this new credential: `{fmt: "none", attStmt: {}, authData}`.
    pub fn registration(&self) -> Result<Registration> {
        let mut auth = rp_hash_and_flags(&self.rp_id, UP | UV | BE | BS | AT);
        auth.extend_from_slice(&AAGUID);
        auth.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        auth.extend_from_slice(&self.credential_id);
        auth.extend_from_slice(&self.cose_public_key()?);
        // A map of 3: "fmt": "none", "attStmt": {}, "authData": bytes.
        let mut object = vec![0xA3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e'];
        object.extend_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xA0]);
        object.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
        cbor_byte_string(&mut object, &auth);
        Ok(Registration { credential_id: self.credential_id.clone(), attestation_object: object })
    }

    /// A signature for a sign-in: authenticator data (no attested data), and ECDSA over it and
    /// `client_data_hash` — the key stays here.
    pub fn assert(&self, client_data_hash: &[u8]) -> Result<Assertion> {
        let authenticator_data = rp_hash_and_flags(&self.rp_id, UP | UV | BE | BS);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(client_data_hash);
        let signature: Signature = self.signing_key()?.sign(&signed);
        Ok(Assertion { authenticator_data, signature: der(&signature) })
    }
}

/// `SHA-256(rp_id) ‖ flags ‖ sign count 0`: the count stays 0, as for synced passkeys.
fn rp_hash_and_flags(rp_id: &str, flags: u8) -> Vec<u8> {
    let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
    out.push(flags);
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

fn cbor_byte_string(out: &mut Vec<u8>, bytes: &[u8]) {
    match bytes.len() {
        n if n < 24 => out.push(0x40 | n as u8),
        n if n < 256 => out.extend_from_slice(&[0x58, n as u8]),
        n => {
            out.push(0x59);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    out.extend_from_slice(bytes);
}

/// ECDSA (r, s) as ASN.1 DER, as WebAuthn wants it.
fn der(signature: &Signature) -> Vec<u8> {
    let bytes = signature.to_bytes();
    let integer = |half: &[u8]| {
        let mut value: Vec<u8> = half.iter().copied().skip_while(|&b| b == 0).collect();
        if value.is_empty() || value[0] & 0x80 != 0 {
            value.insert(0, 0);
        }
        let mut out = vec![0x02, value.len() as u8];
        out.extend_from_slice(&value);
        out
    };
    let (r, s) = (integer(&bytes[..32]), integer(&bytes[32..]));
    let mut out = vec![0x30, (r.len() + s.len()) as u8];
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// PKCS#8 for a P-256 key up to its 32 bytes: `SEQUENCE { 0, { ecPublicKey, prime256v1 },
/// OCTET STRING { ECPrivateKey: SEQUENCE { 1, OCTET STRING (32) … } } }`.
const PKCS8_HEAD: [u8; 36] = [
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02, 0x01, 0x01,
    0x04, 0x20,
];

/// The P-256 OID, `1.2.840.10045.3.1.7`.
const PRIME256V1: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// The 32-byte scalar out of a P-256 key's PKCS#8 (or a bare SEC1 `ECPrivateKey`): the octet
/// string after the version `1` of the `ECPrivateKey`, checked as a scalar on the curve.
fn scalar_from_pkcs8(der: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if der.first() != Some(&0x30) {
        return None;
    }
    let is_p256 = der.windows(PRIME256V1.len()).any(|w| w == PRIME256V1);
    let at = der.windows(5).position(|w| w == [0x02, 0x01, 0x01, 0x04, 0x20])? + 5;
    let bytes = der.get(at..at + 32)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(bytes);
    (is_p256 && SigningKey::from_slice(key.as_ref()).is_ok()).then_some(key)
}

/// PEM (`-----BEGIN PRIVATE KEY-----` …) to DER.
pub fn pem_to_der(pem: &str) -> Option<Zeroizing<Vec<u8>>> {
    let body: Zeroizing<String> = Zeroizing::new(
        pem.lines().filter(|l| !l.starts_with("-----")).flat_map(|l| l.trim().chars()).collect(),
    );
    base64_decode(&body).map(Zeroizing::new)
}

/// Base64url without padding, as WebAuthn ids are written.
pub fn base64url_encode(bytes: &[u8]) -> String {
    base64_encode(bytes).trim_end_matches('=').replace('+', "-").replace('/', "_")
}

pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    base64_decode(&text.trim().replace('-', "+").replace('_', "/"))
}
