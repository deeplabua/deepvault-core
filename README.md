# deepvault-core

The open core of [DeepVault](https://deeplab.tools), a local-only password manager for macOS:
the `.dvault` file format, its key hierarchy and entry encryption, in Rust. The app depends on
the `deepvault-vault` crate at a release tag and exports it to Swift through
[UniFFI](https://mozilla.github.io/uniffi-rs/) on its side.

No network, no file system, no logging: the core takes bytes and returns bytes.

## Crypto in one picture

```text
master password ─Argon2id(salt, m, t, p)─► KEK_pw ─┐
device key (Secure Enclave, Touch ID) ───► KEK_se ─┼─ XChaCha20-Poly1305 wraps VK ("slots")
                                                   ┘
VK (32 random bytes) ─HKDF-SHA256(salt = vault_id)─► K_header_mac, K_file_mac, K_entries

entry ─CBOR─► XChaCha20-Poly1305(K_entries, random 24-byte nonce,
                                 AAD = "DVLT" ‖ version ‖ "entry" ‖ 0 ‖ vault_id ‖ entry_id)
```

- Argon2id defaults: 256 MiB, 3 passes, 4 lanes, calibrated per Mac; never below 64 MiB / 3 passes.
- Each entry is sealed on its own (sync can merge entry by entry); titles and URLs are
  encrypted too.
- The header (KDF parameters, salt, slots) is authenticated by an HMAC; a second HMAC covers the
  whole file, so removing or replaying blocks is detected.

The file layout is documented in [`crates/vault/src/format.rs`](crates/vault/src/format.rs).

## Entries

An entry is a kind (`login`, `password`, `note`, `card`, `bank_account`, `software_license`), a
title and an ordered list of named fields, each visible or concealed. Names the app uses:
`username`, `password`, `totp`, `url`, `notes`, `tag`, `icon`, `link` (another entry's id), a card's, a bank account's and a
licence's (`crates/vault/src/entry.rs`); a name may repeat (several sites, notes, tags). A field
marked `custom` is one the user named: its name is only a label (the flag is left out when false,
so such fields are stored exactly as before). The index kept
in memory while unlocked holds only visible values: title, first site and user name, tags, the
picture, whether there is a one-time code. Concealed values are decrypted one field at a time.

One-time codes (RFC 6238, `crates/vault/src/totp.rs`) are computed in the core from an
`otpauth://totp/…` link or a base32 setup key: the app gets the code, never the secret.

## Generator

Passwords, passphrases and PINs (`crates/vault/src/generator.rs`) from the system CSPRNG, every
choice uniform (rejection sampling, no modulo bias). Passphrases use the
[EFF large word list](https://www.eff.org/dice) (7776 words, 12.9 bits each), CC BY 3.0 — see NOTICE.

## Layout

| Path | What |
|---|---|
| `crates/vault` | The format and keys: `kdf`, `aead`, `keys`, `format`, `entry`, `vault` |
| `tests/vectors` | Test vectors per format version + an independent Python check |
| `tests/fixtures` | Committed vault files that every later version must keep opening |

## Commands

```bash
cargo test                          # unit tests, vectors, backward compatibility
cargo clippy --all-targets -- -D warnings
cargo fmt
./check-deps.sh                     # no network crates linked into the library
python3 tests/vectors/check_v1.py tests/vectors/v1_sample.json tests/fixtures/v1_sample.dvault
```

## Dependencies

RustCrypto `argon2`, `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `sha1` (one-time codes only:
RFC 6238 defaults to HMAC-SHA1); `zeroize`, `getrandom`, `serde` + `ciborium`. Each is justified
in ADR-0001; a new one needs an ADR.

## Using it

```toml
[dependencies]
deepvault-vault = { git = "https://github.com/deeplabua/deepvault-core", tag = "v0.4.0" }
```

## License

MIT OR Apache-2.0, at your option; the EFF word list is CC BY 3.0 ([NOTICE](NOTICE)).
Security reports: [SECURITY.md](SECURITY.md).
