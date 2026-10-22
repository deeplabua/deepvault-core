#!/usr/bin/env bash
# Fails when anything that can talk to the network is linked into the core (CLAUDE.md, rule 2;
# PRD 03). Checks what ends up in the library: normal and build dependencies of
# deepvault-vault. The app repo runs the same check over its FFI crate (app/rust/check-deps.sh).
set -euo pipefail
cd "$(dirname "$0")"

FORBIDDEN='^(reqwest|hyper|hyper-util|h2|h3|ureq|curl|isahc|surf|attohttpc|rustls|native-tls|openssl|openssl-sys|tokio|async-std|smol|mio|socket2|tungstenite|quinn|url)$'
deps=$(cargo tree --locked -p deepvault-vault -e normal,build --prefix none --format '{p}' | awk '{print $1}' | sort -u)
hits=$(grep -E "$FORBIDDEN" <<<"$deps" || true)
if [[ -n "$hits" ]]; then
  echo "check-deps: network crates in deepvault-vault:"
  sed 's/^/    /' <<<"$hits"
  exit 1
fi
echo "check-deps: ok ($(wc -l <<<"$deps" | tr -d ' ') crates, none network)"
