# Security policy — deepvault-core

This crate is the cryptographic core of DeepVault, a local-only password manager for macOS:
the `.dvault` file format, the key hierarchy and entry encryption. Reports about it are the
most valuable ones we get.

## Reporting a vulnerability

- E-mail **hi@deeplab.tools** with the subject `[security] deepvault-core` and the details and, if you can, a proof of concept.
  Please do not open a public issue for an unfixed vulnerability.
- We acknowledge within **3 working days** and send a first assessment within **10 working days**.
- We fix critical issues (anything that reveals vault contents or keys, or lets a modified file
  be accepted) before anything else and publish an advisory with credit, unless you prefer not
  to be named.

## Scope

In scope: this repository — file format parsing, KDF, AEAD use, key slots, subkeys,
zeroisation.

Out of scope here (report to the same address and subject anyway): the UniFFI layer, the macOS app, AutoFill extension and
CLI, which live in a private repository.

## What the core promises

- No network and no file system access: bytes in, bytes out (checked by `check-deps.sh`).
- Secrets are never logged and have no `Debug`/`Display`.
- A file that was changed in any byte does not open (or fails with `WrongPassword` when the
  change hits the KDF parameters or a slot).
- Format versions are frozen by test vectors (`tests/vectors`), checked against an independent
  implementation (`tests/vectors/check_v1.py`).

The threat model and what DeepVault does **not** protect against: PRD 04 of the app
(summarised in README.md).

## Status

Pre-alpha. **Not audited yet.** An external audit is required before DeepVault 1.0.
