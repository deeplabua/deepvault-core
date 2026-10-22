//! One-time codes (RFC 6238, TOTP) from a secret kept in an entry. The secret never leaves the
//! core: the app gets the current code and how long it stays valid.
//!
//! A field holds either an `otpauth://totp/…?secret=…` URI (as QR codes carry it) or the bare
//! base32 secret that sites show next to the QR code.

use hmac::{Hmac, KeyInit, Mac};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// What a TOTP field says, secret aside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u32,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self { algorithm: Algorithm::Sha1, digits: 6, period: 30 }
    }
}

/// The code for a moment, and how many seconds it has left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub period: u32,
    pub remaining: u32,
}

/// The secret and parameters of a TOTP field, or `InvalidOtp`.
pub fn parse(text: &[u8]) -> Result<(Zeroizing<Vec<u8>>, TotpParams)> {
    let text = std::str::from_utf8(text).map_err(|_| VaultError::InvalidOtp)?.trim();
    let Some(rest) = strip_prefix_ignore_case(text, "otpauth://") else {
        return Ok((base32(text)?, TotpParams::default()));
    };
    if !rest.get(..5).is_some_and(|kind| kind.eq_ignore_ascii_case("totp/")) {
        // HOTP needs a counter written back on every use: not supported.
        return Err(VaultError::InvalidOtp);
    }
    let query = rest.split_once('?').map(|(_, query)| query).ok_or(VaultError::InvalidOtp)?;
    let mut secret = None;
    let mut params = TotpParams::default();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(base32(&value.replace("%20", ""))?),
            "algorithm" => {
                params.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err(VaultError::InvalidOtp),
                }
            }
            "digits" => params.digits = value.parse().map_err(|_| VaultError::InvalidOtp)?,
            "period" => params.period = value.parse().map_err(|_| VaultError::InvalidOtp)?,
            _ => {} // issuer, image, …: labels, not needed for the code
        }
    }
    if !(6..=8).contains(&params.digits) || !(1..=300).contains(&params.period) {
        return Err(VaultError::InvalidOtp);
    }
    Ok((secret.ok_or(VaultError::InvalidOtp)?, params))
}

/// The code at `unix_time` (seconds).
pub fn code(text: &[u8], unix_time: u64) -> Result<TotpCode> {
    let (secret, params) = parse(text)?;
    let period = u64::from(params.period);
    let counter = (unix_time / period).to_be_bytes();
    let digest: Zeroizing<Vec<u8>> = Zeroizing::new(match params.algorithm {
        Algorithm::Sha1 => hmac::<sha1::Sha1>(&secret, &counter),
        Algorithm::Sha256 => hmac::<sha2::Sha256>(&secret, &counter),
        Algorithm::Sha512 => hmac::<sha2::Sha512>(&secret, &counter),
    });
    // RFC 4226 §5.3, dynamic truncation.
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes(digest[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
    let value = binary % 10u32.pow(params.digits);
    Ok(TotpCode {
        code: format!("{value:0width$}", width = params.digits as usize),
        period: params.period,
        remaining: params.period - (unix_time % period) as u32,
    })
}

fn hmac<D: hmac::EagerHash>(key: &[u8], message: &[u8]) -> Vec<u8>
where
    Hmac<D>: KeyInit + Mac,
{
    let mut mac = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 4648 base32, as authenticator setups show it: any case, spaces and padding ignored.
fn base32(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            b' ' | b'-' | b'=' => continue,
            _ => return Err(VaultError::InvalidOtp),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    buffer.zeroize();
    // Below 80 bits (RFC 4226 asks for 128, sites use 80 and up) it is a typo, not a secret.
    if out.len() < 10 {
        return Err(VaultError::InvalidOtp);
    }
    Ok(out)
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.get(..prefix.len()).filter(|head| head.eq_ignore_ascii_case(prefix)).map(|_| &text[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238, appendix B: the three seeds as base32, 8 digits.
    fn rfc(algorithm: &str, seed: &[u8]) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut encoded = String::new();
        let (mut buffer, mut bits) = (0u32, 0u32);
        for &byte in seed {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                encoded.push(alphabet[((buffer >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            encoded.push(alphabet[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        format!("otpauth://totp/RFC?secret={encoded}&algorithm={algorithm}&digits=8&period=30")
    }

    #[test]
    fn rfc_6238_vectors() {
        let sha1 = rfc("SHA1", b"12345678901234567890");
        let sha256 = rfc("SHA256", b"12345678901234567890123456789012");
        let sha512 = rfc("SHA512", b"1234567890123456789012345678901234567890123456789012345678901234");
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (time, one, two, five) in cases {
            assert_eq!(code(sha1.as_bytes(), time).unwrap().code, one, "SHA1 at {time}");
            assert_eq!(code(sha256.as_bytes(), time).unwrap().code, two, "SHA256 at {time}");
            assert_eq!(code(sha512.as_bytes(), time).unwrap().code, five, "SHA512 at {time}");
        }
    }

    #[test]
    fn a_bare_secret_means_sha1_six_digits_thirty_seconds() {
        // The RFC's SHA1 seed in base32, lowercase and grouped as sites print it.
        let bare = b"gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        let at = code(bare, 59).unwrap();
        assert_eq!(at.code, "287082");
        assert_eq!((at.period, at.remaining), (30, 1));
        assert_eq!(code(bare, 60).unwrap().remaining, 30);
    }

    #[test]
    fn bad_fields_are_refused() {
        for text in [
            &b"not base32 !"[..],
            b"GEZDGNBV", // too short to be a secret
            b"otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1",
            b"otpauth://totp/x?issuer=nobody", // no secret
            b"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=4",
            b"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
            b"\xff\xfe",
        ] {
            assert_eq!(
                parse(text).err(),
                Some(VaultError::InvalidOtp),
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
    }
}
