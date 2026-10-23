# CSR-based mTLS issuance using signer-admin (pure Rust rcgen + pkcs8).
#
# The endpoint generates its own private key and CSR in signer-admin. The CA
# signs the CSR with explicitly approved identity and permission values; SANs
# requested by the CSR are ignored. The CA key is encrypted with
# $env:SIGNER_CA_PASSPHRASE and never needs to be present on endpoint hosts.

$ErrorActionPreference = "Stop"

function Show-Usage {
    @'
Usage: scripts/mtls-csr.ps1 <command> [options]

Commands:
  ca-init              Create ca.crt and an encrypted ca.key.enc
  csr                  Generate an endpoint private key and CSR
  sign-csr             Sign a CSR with the CA and approved identity fields

Examples:
  .\scripts\mtls-csr.ps1 ca-init --out-dir data/tls

  $env:SIGNER_TLS_KEY_PASSPHRASE = "client-key-passphrase"
  .\scripts\mtls-csr.ps1 csr --kind client `
    --principal alice --holder holder-1 `
    --permissions unseal.start,unseal.status,key.read `
    --out-key data/tls/alice.key --out-csr data/tls/alice.csr

  $env:SIGNER_CA_PASSPHRASE = "ca-key-passphrase"
  .\scripts\mtls-csr.ps1 sign-csr --kind client `
    --principal alice --holder holder-1 `
    --permissions unseal.start,unseal.status,key.read `
    --csr data/tls/alice.csr --out data/tls/alice.crt

Server certificate:
  .\scripts\mtls-csr.ps1 csr --kind server --plaintext-key `
    --server-san DNS:localhost --server-san IP:127.0.0.1 `
    --out-key data/tls/server.key --out-csr data/tls/server.csr
  .\scripts\mtls-csr.ps1 sign-csr --kind server `
    --server-san DNS:localhost --server-san IP:127.0.0.1 `
    --csr data/tls/server.csr --out data/tls/server.crt

Environment:
  SIGNER_CA_PASSPHRASE        CA key passphrase (ca-init, sign-csr)
  SIGNER_TLS_KEY_PASSPHRASE   endpoint key passphrase (csr; not needed with
                              --plaintext-key)

Use `csr --help` and `sign-csr --help` for all options.
'@ | Write-Output
}

if ($args.Count -eq 0) {
    Show-Usage
    exit 1
}

$subcommand = $args[0]
$rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }

switch ($subcommand) {
    "ca-init" { $adminCommand = "tls-ca-init" }
    "csr" { $adminCommand = "tls-csr" }
    "sign-csr" { $adminCommand = "tls-sign-csr" }
    { $_ -in @("help", "-h", "--help") } {
        Show-Usage
        exit 0
    }
    default {
        [Console]::Error.WriteLine("unknown command: $subcommand")
        Show-Usage
        exit 1
    }
}

$customPassphraseEnv = $false
foreach ($arg in $rest) {
    if ($arg -eq "--passphrase-env" -or $arg -like "--passphrase-env=*") {
        $customPassphraseEnv = $true
    }
}

if (($subcommand -eq "ca-init" -or $subcommand -eq "sign-csr") -and
    -not $customPassphraseEnv -and
    [string]::IsNullOrEmpty($env:SIGNER_CA_PASSPHRASE)) {
    [Console]::Error.WriteLine("set SIGNER_CA_PASSPHRASE before $subcommand")
    exit 1
}

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    & cargo run --quiet -p signer-admin -- $adminCommand @rest
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
