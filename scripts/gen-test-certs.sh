#!/usr/bin/env bash
# Regenerate the static mTLS fixtures used by crates/server tests.
#
# This writes test-only server/client private keys and certificates. It does
# NOT copy CA private keys into the repository. Never use these files for
# anything except local tests.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/crates/server/tests/fixtures/mtls"
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    -h|--help)
      printf 'Usage: scripts/gen-test-certs.sh [--force]\n'
      exit 0
      ;;
    *) printf 'error: unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
done

if [[ -d "$FIX" && -n "$(find "$FIX" -mindepth 1 -maxdepth 1 ! -name README.md -print -quit)" && "$FORCE" -eq 0 ]]; then
  printf 'error: %s already contains fixtures; pass --force to regenerate\n' "$FIX" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

bash "$ROOT/scripts/gen-mtls.sh" \
  --out "$TMP/valid" \
  --days 36500 --ca-days 36500 \
  --client "alice:unseal.start,unseal.status,key.read" \
  --holder alice:holder-1 \
  --client "bob:key.read" \
  --client "carol:key.sign,key.read" \
  --client "dave:" \
  --client "eve:0x400" \
  ;

bash "$ROOT/scripts/gen-mtls.sh" \
  --out "$TMP/rogue" \
  --days 36500 --ca-days 36500 \
  --client "rogue:key.read"

mkdir -p "$FIX"
find "$FIX" -mindepth 1 -maxdepth 1 ! -name README.md -delete

cp "$TMP/valid/ca.crt" "$FIX/ca.pem"
cp "$TMP/valid/server.crt" "$FIX/server.pem"
cp "$TMP/valid/server.key" "$FIX/server.key"
openssl x509 -in "$TMP/valid/server.crt" -outform der -out "$FIX/server.der"

for name in alice bob carol dave eve; do
  cp "$TMP/valid/$name.crt" "$FIX/client-$name.pem"
  cp "$TMP/valid/$name.key" "$FIX/client-$name.key"
  cp "$TMP/valid/$name.der" "$FIX/client-$name.der"
done

cp "$TMP/rogue/rogue.crt" "$FIX/client-rogue.pem"
cp "$TMP/rogue/rogue.key" "$FIX/client-rogue.key"
cp "$TMP/rogue/rogue.der" "$FIX/client-rogue.der"
cp "$TMP/rogue/ca.crt" "$FIX/rogue-ca.pem"

chmod 600 "$FIX"/*.key
chmod 644 "$FIX"/*.pem "$FIX"/*.der

if find "$FIX" -name 'ca.key' -o -name 'rogue-ca.key' | grep -q .; then
  printf 'error: CA private key was copied into fixtures\n' >&2
  exit 1
fi

printf 'test fixtures written to %s\n' "$FIX"
printf 'client alice fingerprint: %s\n' "$(openssl x509 -in "$FIX/client-alice.pem" -noout -fingerprint -sha256 | sed 's/^.*=//' | tr -d ':' | tr 'A-F' 'a-f')"
