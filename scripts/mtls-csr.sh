#!/usr/bin/env bash
# CSR-based mTLS issuance using signer-admin (pure Rust rcgen + pkcs8).
#
# The endpoint generates its own private key and CSR in signer-admin. The CA
# signs the CSR with explicitly approved identity and permission values; SANs
# requested by the CSR are ignored. The CA key is encrypted with
# SIGNER_CA_PASSPHRASE and never needs to be present on endpoint hosts.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/mtls-csr.sh <command> [options]

Commands:
  ca-init              Create ca.crt and an encrypted ca.key.enc
  csr                  Generate an endpoint private key and CSR
  sign-csr             Sign a CSR with the CA and approved identity fields

Examples:
  scripts/mtls-csr.sh ca-init --out-dir data/tls

  export SIGNER_TLS_KEY_PASSPHRASE='client-key-passphrase'
  scripts/mtls-csr.sh csr --kind client \
    --principal alice --holder holder-1 \
    --permissions unseal.start,unseal.status,key.read \
    --out-key data/tls/alice.key --out-csr data/tls/alice.csr

  export SIGNER_CA_PASSPHRASE='ca-key-passphrase'
  scripts/mtls-csr.sh sign-csr --kind client \
    --principal alice --holder holder-1 \
    --permissions unseal.start,unseal.status,key.read \
    --csr data/tls/alice.csr --out data/tls/alice.crt

Server certificate:
  scripts/mtls-csr.sh csr --kind server --plaintext-key \
    --server-san DNS:localhost --server-san IP:127.0.0.1 \
    --out-key data/tls/server.key --out-csr data/tls/server.csr
  scripts/mtls-csr.sh sign-csr --kind server \
    --server-san DNS:localhost --server-san IP:127.0.0.1 \
    --csr data/tls/server.csr --out data/tls/server.crt

Environment:
  SIGNER_CA_PASSPHRASE        CA key passphrase (ca-init, sign-csr)
  SIGNER_TLS_KEY_PASSPHRASE   endpoint key passphrase (csr; not needed with
                              --plaintext-key)
  CARGO                       cargo binary (default: cargo)

Use `csr --help` and `sign-csr --help` for all options.
EOF
}

if [[ $# -eq 0 ]]; then
  usage
  exit 1
fi

subcommand="$1"
shift

case "$subcommand" in
  ca-init) admin_command="tls-ca-init" ;;
  csr) admin_command="tls-csr" ;;
  sign-csr) admin_command="tls-sign-csr" ;;
  help|-h|--help)
    usage
    exit 0
    ;;
  *)
    printf 'error: unknown command: %s\n' "$subcommand" >&2
    usage
    exit 1
    ;;
esac

custom_passphrase_env=0
for arg in "$@"; do
  case "$arg" in
    --passphrase-env|--passphrase-env=*) custom_passphrase_env=1 ;;
  esac
done

case "$subcommand" in
  ca-init|sign-csr)
    if [[ "$custom_passphrase_env" -eq 0 && -z "${SIGNER_CA_PASSPHRASE:-}" ]]; then
      printf 'error: set SIGNER_CA_PASSPHRASE before %s\n' "$subcommand" >&2
      exit 1
    fi
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec "${CARGO:-cargo}" run --quiet -p signer-admin -- "$admin_command" "$@"
