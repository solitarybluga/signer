#!/usr/bin/env bash
# Generate a development mTLS CA, server certificate and client certificates.
#
# Client certificates carry:
#   URI:signer://principal/<name>
#   URI:signer://holder/<holder-id>       (zero or more)
#   URI:signer://permissions/0x<16-hex>   (u64 permission mask)
#
# This script is for development and testing. Production CAs must enforce the
# permission bits during issuance; never use the generated CA for production.
# For the CSR workflow (endpoint keys never reach the CA), use mtls-csr.sh.

set -euo pipefail
umask 077

OUT="data/tls"
SERVER_SAN="DNS:localhost,IP:127.0.0.1"
DAYS=825
CA_DAYS=3650
FORCE=0
NEW_CA=0
CLIENT_SPECS=()
HOLDER_SPECS=()

declare -A PERMISSION_BITS=(
  [unseal.start]=0
  [unseal.submit]=1
  [unseal.status]=2
  [unseal.seal]=3
  [key.create]=4
  [key.import]=5
  [key.read]=6
  [key.sign]=7
)

usage() {
  cat <<'EOF'
Usage: scripts/gen-mtls.sh --out DIR --client NAME[:PERM,...] [options]

Options:
  --out DIR             Output directory (default: data/tls)
  --server-san SAN      Server subjectAltName (default: DNS:localhost,IP:127.0.0.1)
  --client NAME[:PERMS] Repeatable. PERMS is a comma-separated list of:
                        unseal.start, unseal.submit, unseal.status, unseal.seal,
                        key.create, key.import, key.read, key.sign.
                        An empty list creates a certificate with no permissions.
                        A raw 0x... mask is accepted as a test hook only.
  --holder NAME:HOLDER  Repeatable. Bind a holder ID to a client certificate.
  --days N              Certificate validity in days (default: 825)
  --ca-days N           CA validity in days (default: 3650)
  --force               Overwrite existing server/client files (CA is reused)
  --new-ca              Regenerate the CA; requires --force if files exist

Environment:
  OPENSSL               Path to the openssl binary (default: openssl)
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

validate_name() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid name: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) [[ $# -ge 2 ]] || die "--out requires a value"; OUT="$2"; shift 2 ;;
    --server-san) [[ $# -ge 2 ]] || die "--server-san requires a value"; SERVER_SAN="$2"; shift 2 ;;
    --client) [[ $# -ge 2 ]] || die "--client requires a value"; CLIENT_SPECS+=("$2"); shift 2 ;;
    --holder) [[ $# -ge 2 ]] || die "--holder requires a value"; HOLDER_SPECS+=("$2"); shift 2 ;;
    --days) [[ $# -ge 2 ]] || die "--days requires a value"; DAYS="$2"; shift 2 ;;
    --ca-days) [[ $# -ge 2 ]] || die "--ca-days requires a value"; CA_DAYS="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --new-ca) NEW_CA=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ ${#CLIENT_SPECS[@]} -gt 0 ]] || die "at least one --client is required"
[[ "$DAYS" =~ ^[0-9]+$ && "$CA_DAYS" =~ ^[0-9]+$ ]] || die "validity must be a number"
[[ "$SERVER_SAN" =~ ^[A-Za-z0-9.:,_=-]+$ ]] || die "invalid --server-san"

declare -A CLIENT_MASKS=()
declare -A CLIENT_HOLDERS=()

for spec in "${CLIENT_SPECS[@]}"; do
  [[ "$spec" == *:* ]] || die "client must be NAME:PERMISSIONS (use NAME: for no permissions)"
  name="${spec%%:*}"
  perms="${spec#*:}"
  validate_name "$name"
  [[ -z "${CLIENT_MASKS[$name]:-}" ]] || die "duplicate client: $name"

  mask=0
  if [[ "$perms" == 0x* || "$perms" == 0X* ]]; then
    # Raw masks are a test hook for exercising reserved-bit rejection.
    hex="${perms:2}"
    [[ "$hex" =~ ^[0-9A-Fa-f]{1,16}$ ]] || die "invalid raw mask for $name"
    mask=$((perms))
  elif [[ -n "$perms" ]]; then
    IFS=',' read -r -a permission_list <<< "$perms"
    for permission in "${permission_list[@]}"; do
      [[ -n "$permission" ]] || die "empty permission in $name:$perms"
      bit="${PERMISSION_BITS[$permission]:-}"
      [[ -n "$bit" ]] || die "unknown permission: $permission"
      mask=$((mask | (1 << bit)))
    done
  fi
  CLIENT_MASKS[$name]="$(printf '0x%016x' "$mask")"
done

for spec in "${HOLDER_SPECS[@]}"; do
  [[ "$spec" == *:* ]] || die "holder must be NAME:HOLDER_ID"
  name="${spec%%:*}"
  holder="${spec#*:}"
  validate_name "$name"
  [[ -n "$holder" ]] || die "empty holder id for $name"
  [[ "$holder" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid holder id: $holder"
  [[ -n "${CLIENT_MASKS[$name]:-}" ]] || die "--holder references unknown client: $name"
  if [[ -n "${CLIENT_HOLDERS[$name]:-}" ]]; then
    CLIENT_HOLDERS[$name]+=",${holder}"
  else
    CLIENT_HOLDERS[$name]="$holder"
  fi
done

OPENSSL="${OPENSSL:-openssl}"
command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl not found"

mkdir -p "$OUT"
chmod 700 "$OUT"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

write_ca_config() {
  cat > "$TMP/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = signer-dev-ca

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
}

write_server_config() {
  cat > "$TMP/server.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = signer-server
EOF
  cat > "$TMP/server.ext" <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${SERVER_SAN}
EOF
}

write_client_config() {
  local name="$1"
  local mask="$2"
  local holders="$3"
  cat > "$TMP/client-$name.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no

[dn]
CN = ${name}
EOF
  local san="URI:signer://principal/${name}"
  if [[ -n "$holders" ]]; then
    IFS=',' read -r -a holder_list <<< "$holders"
    for holder in "${holder_list[@]}"; do
      san+=",URI:signer://holder/${holder}"
    done
  fi
  san+=",URI:signer://permissions/${mask}"
  cat > "$TMP/client-$name.ext" <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = ${san}
EOF
}

sign_cert() {
  local csr="$1" ext="$2" out="$3" days="$4"
  local serial_args=(-CAserial "$OUT/ca.srl")
  if [[ ! -f "$OUT/ca.srl" ]]; then
    serial_args=(-CAcreateserial)
  fi
  "$OPENSSL" x509 -req -in "$csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
    "${serial_args[@]}" -out "$out" -days "$days" -sha256 -extfile "$ext"
}

fingerprint() {
  "$OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 \
    | sed 's/^.*=//' | tr -d ':' | tr 'A-F' 'a-f'
}

# CA: reuse an existing pair unless --new-ca was requested.
if [[ -f "$OUT/ca.crt" && -f "$OUT/ca.key" && "$NEW_CA" -eq 0 ]]; then
  printf 'reusing CA: %s/ca.crt\n' "$OUT"
else
  if [[ "$NEW_CA" -eq 1 && ( -e "$OUT/ca.crt" || -e "$OUT/ca.key" ) && "$FORCE" -eq 0 ]]; then
    die "--new-ca would overwrite the CA; pass --force"
  fi
  write_ca_config
  "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$OUT/ca.key"
  "$OPENSSL" req -x509 -new -key "$OUT/ca.key" -sha256 -days "$CA_DAYS" \
    -config "$TMP/ca.cnf" -out "$OUT/ca.crt"
  rm -f "$OUT/ca.srl"
  chmod 600 "$OUT/ca.key"
  chmod 644 "$OUT/ca.crt"
  printf 'created CA: %s/ca.crt\n' "$OUT"
fi

# Server certificate.
if [[ -e "$OUT/server.crt" && ! -e "$OUT/server.key" ]] || [[ ! -e "$OUT/server.crt" && -e "$OUT/server.key" ]]; then
  die "incomplete server files; remove them or pass --force"
fi
if [[ -f "$OUT/server.crt" && -f "$OUT/server.key" && "$FORCE" -eq 0 ]]; then
  printf 'reusing server certificate: %s/server.crt\n' "$OUT"
else
  write_server_config
  "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT/server.key"
  "$OPENSSL" req -new -key "$OUT/server.key" -config "$TMP/server.cnf" -out "$TMP/server.csr"
  sign_cert "$TMP/server.csr" "$TMP/server.ext" "$OUT/server.crt" "$DAYS"
  chmod 600 "$OUT/server.key"
  chmod 644 "$OUT/server.crt"
  printf 'created server certificate: %s/server.crt\n' "$OUT"
fi

for name in "${!CLIENT_MASKS[@]}"; do
  mask="${CLIENT_MASKS[$name]}"
  holders="${CLIENT_HOLDERS[$name]:-}"
  crt="$OUT/$name.crt"
  key="$OUT/$name.key"
  if [[ -e "$crt" && ! -e "$key" ]] || [[ ! -e "$crt" && -e "$key" ]]; then
    die "incomplete client files for $name; remove them or pass --force"
  fi
  if [[ -f "$crt" && -f "$key" && "$FORCE" -eq 0 ]]; then
    printf 'reusing client certificate: %s\n' "$crt"
    continue
  fi
  write_client_config "$name" "$mask" "$holders"
  "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key"
  "$OPENSSL" req -new -key "$key" -config "$TMP/client-$name.cnf" -out "$TMP/client-$name.csr"
  sign_cert "$TMP/client-$name.csr" "$TMP/client-$name.ext" "$crt" "$DAYS"
  "$OPENSSL" x509 -in "$crt" -outform der -out "$OUT/$name.der"
  chmod 600 "$key"
  chmod 644 "$crt" "$OUT/$name.der"
  printf 'created client %-16s permissions=%s fingerprint=%s\n' "$name" "$mask" "$(fingerprint "$crt")"
done

printf '\nFiles are in %s\n' "$OUT"
printf 'CA private key: %s/ca.key (keep offline; never commit)\n' "$OUT"
printf 'Server: %s/server.crt %s/server.key\n' "$OUT" "$OUT"
printf 'Server SHA-256: %s\n' "$(fingerprint "$OUT/server.crt")"
