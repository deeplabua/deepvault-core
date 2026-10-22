use std::fmt;

/// Why an operation on a vault failed. The variants carry no secrets and no file contents:
/// they are safe to log and to show (CLAUDE.md, rule 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// No key slot opens with this password (or this device key). Also what a file whose KDF
    /// parameters were tampered with looks like: the key derived from them opens nothing.
    WrongPassword,
    /// The file is not a vault, is truncated, or failed authentication after the key was
    /// found: a changed header, block or MAC.
    Corrupted,
    /// A vault written by a newer DeepVault.
    UnsupportedVersion(u16),
    /// KDF parameters below the minimum or above the maximum (`KdfParams::check`).
    InvalidKdfParams,
    /// A key handed in from outside (a device key) that is not 32 bytes.
    InvalidKey,
    /// No live entry with this id, or no such field in it.
    NotFound,
    /// A one-time-code field that is neither an `otpauth://totp/` URI nor a base32 secret.
    InvalidOtp,
    /// Generator options out of range: length, word count, a letter as separator.
    InvalidGeneratorOptions,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPassword => f.write_str("wrong password"),
            Self::Corrupted => f.write_str("the vault file is damaged or was modified"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported vault format version {version}"),
            Self::InvalidKdfParams => f.write_str("KDF parameters out of the allowed range"),
            Self::InvalidKey => f.write_str("a key must be 32 bytes"),
            Self::NotFound => f.write_str("no such entry or field"),
            Self::InvalidOtp => f.write_str("not a TOTP secret or otpauth URI"),
            Self::InvalidGeneratorOptions => f.write_str("generator options out of range"),
        }
    }
}

impl std::error::Error for VaultError {}

pub type Result<T> = std::result::Result<T, VaultError>;
