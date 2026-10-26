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
