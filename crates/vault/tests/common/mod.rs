#![allow(dead_code)]

use std::path::PathBuf;

/// `core/tests/…`: the vectors and fixtures sit at the workspace root, outside any crate, so
/// another implementation can read them without knowing this one.
pub fn shared(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests").join(path)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect()
}

pub fn array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().expect("hex of the wrong length")
}
