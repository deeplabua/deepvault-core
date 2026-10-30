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
    /// Entries that authenticate but that this core cannot read: written by a newer DeepVault
    /// (a field added since, `Entry` refuses unknown fields), not damage. Update the app.
    NewerEntries,
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
    /// An import file that is neither CSV nor Secrets' XML, or has nothing a password export has.
    InvalidImport,
    /// Not an OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    InvalidSshKey,
    /// An SSH key protected by a passphrase: remove it first (`ssh-keygen -p -N ""`).
    EncryptedSshKey,
    /// An SSH key of a type the agent does not take (RSA, ECDSA from a file).
    UnsupportedSshKey,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPassword => f.write_str("wrong password"),
            Self::Corrupted => f.write_str("the vault file is damaged or was modified"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported vault format version {version}"),
            Self::NewerEntries => f.write_str("entries written by a newer DeepVault"),
            Self::InvalidKdfParams => f.write_str("KDF parameters out of the allowed range"),
            Self::InvalidKey => f.write_str("a key must be 32 bytes"),
            Self::NotFound => f.write_str("no such entry or field"),
            Self::InvalidOtp => f.write_str("not a TOTP secret or otpauth URI"),
            Self::InvalidGeneratorOptions => f.write_str("generator options out of range"),
            Self::InvalidImport => f.write_str("not a password export"),
            Self::InvalidSshKey => f.write_str("not an OpenSSH private key"),
            Self::EncryptedSshKey => f.write_str("the SSH key has a passphrase"),
            Self::UnsupportedSshKey => f.write_str("only ed25519 SSH keys are taken"),
        }
    }
}

impl std::error::Error for VaultError {}

pub type Result<T> = std::result::Result<T, VaultError>;
