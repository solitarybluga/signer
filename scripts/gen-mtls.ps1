# Generate a development mTLS CA, server certificate and client certificates.
#
# Client certificates carry:
#   URI:signer://principal/<name>
#   URI:signer://holder/<holder-id>       (zero or more)
#   URI:signer://permissions/0x<16-hex>   (u64 permission mask)
#
# This script is for development and testing. Production CAs must enforce the
# permission bits during issuance; never use the generated CA for production.
# For the CSR workflow (endpoint keys never reach the CA), use mtls-csr.ps1.

param(
    [string]$Out = "data/tls",
    [string]$ServerSan = "DNS:localhost,IP:127.0.0.1",
    [string[]]$Client = @(),
    [string[]]$Holder = @(),
    [int]$Days = 825,
    [int]$CaDays = 3650,
    [switch]$Force,
    [switch]$NewCa
)

$ErrorActionPreference = "Stop"

$openssl = if ($env:OPENSSL) { $env:OPENSSL } else { "openssl" }

$permissionBits = @{
    "unseal.start"  = 0
    "unseal.submit" = 1
    "unseal.status" = 2
    "unseal.seal"   = 3
    "key.create"    = 4
    "key.import"    = 5
    "key.read"      = 6
    "key.sign"      = 7
}

function Fail([string]$Message) {
    Write-Error "error: $Message"
    exit 1
}

function Test-Name([string]$Value) {
    if ($Value -notmatch '^[A-Za-z0-9._-]+$') {
        Fail "invalid name: $Value"
    }
}

function Invoke-OpenSsl([string[]]$Arguments) {
    & $openssl @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "openssl failed: $($Arguments -join ' ')"
    }
}

function Get-Fingerprint([string]$Path) {
    $line = & $openssl x509 -in $Path -noout -fingerprint -sha256
    if ($LASTEXITCODE -ne 0) { Fail "cannot read certificate: $Path" }
    return ($line -replace '^.*=', '' -replace ':', '').ToLowerInvariant()
}

function Protect-Key([string]$Path) {
    try {
        & icacls $Path /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
    } catch {
        # ACL hardening is best-effort; non-Windows/acl-less environments may skip it.
    }
}

if ($Client.Count -eq 0) { Fail "at least one -Client is required" }
if ($ServerSan -notmatch '^[A-Za-z0-9.:,_=-]+$') { Fail "invalid -ServerSan" }

$clientMasks = @{}
$clientHolders = @{}

foreach ($spec in $Client) {
    $index = $spec.IndexOf(':')
    if ($index -lt 0) { Fail "client must be NAME:PERMISSIONS (use NAME: for no permissions)" }
    $name = $spec.Substring(0, $index)
    $perms = $spec.Substring($index + 1)
    Test-Name $name
    if ($clientMasks.ContainsKey($name)) { Fail "duplicate client: $name" }

    [uint64]$mask = 0
    if ($perms -match '^0[xX][0-9A-Fa-f]{1,16}$') {
        # Raw masks are a test hook for exercising reserved-bit rejection.
        $mask = [Convert]::ToUInt64($perms.Substring(2), 16)
    } elseif ($perms.Length -gt 0) {
        foreach ($permission in $perms.Split(',')) {
            if (-not $permissionBits.ContainsKey($permission)) {
                Fail "unknown permission: $permission"
            }
            $mask = $mask -bor ([uint64]1 -shl $permissionBits[$permission])
        }
    }
    $clientMasks[$name] = ("0x{0:x16}" -f $mask)
}

foreach ($spec in $Holder) {
    $index = $spec.IndexOf(':')
    if ($index -lt 0) { Fail "holder must be NAME:HOLDER_ID" }
    $name = $spec.Substring(0, $index)
    $holder = $spec.Substring($index + 1)
    Test-Name $name
    if ($holder -notmatch '^[A-Za-z0-9._-]+$') { Fail "invalid holder id: $holder" }
    if (-not $clientMasks.ContainsKey($name)) { Fail "-Holder references unknown client: $name" }
    if ($clientHolders.ContainsKey($name)) {
        $clientHolders[$name] = "$($clientHolders[$name]),$holder"
    } else {
        $clientHolders[$name] = $holder
    }
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("signer-mtls-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    $caConfig = @"
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
"@
    $caConfig | Set-Content -Encoding ascii (Join-Path $temp "ca.cnf")

    $caCrt = Join-Path $Out "ca.crt"
    $caKey = Join-Path $Out "ca.key"
    $serial = Join-Path $Out "ca.srl"

    if ((Test-Path $caCrt) -and (Test-Path $caKey) -and -not $NewCa) {
        Write-Host "reusing CA: $caCrt"
    } else {
        if ($NewCa -and ((Test-Path $caCrt) -or (Test-Path $caKey)) -and -not $Force) {
            Fail "-NewCa would overwrite the CA; pass -Force"
        }
        Invoke-OpenSsl @("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", $caKey)
        Invoke-OpenSsl @("req", "-x509", "-new", "-key", $caKey, "-sha256", "-days", "$CaDays", "-config", (Join-Path $temp "ca.cnf"), "-out", $caCrt)
        Remove-Item -Force -ErrorAction SilentlyContinue $serial
        Protect-Key $caKey
        Write-Host "created CA: $caCrt"
    }

    $serverCrt = Join-Path $Out "server.crt"
    $serverKey = Join-Path $Out "server.key"
    if ((Test-Path $serverCrt) -and (Test-Path $serverKey) -and -not $Force) {
        Write-Host "reusing server certificate: $serverCrt"
    } else {
        @"
[req]
distinguished_name = dn
prompt = no

[dn]
CN = signer-server
"@ | Set-Content -Encoding ascii (Join-Path $temp "server.cnf")
        @"
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $ServerSan
"@ | Set-Content -Encoding ascii (Join-Path $temp "server.ext")

        Invoke-OpenSsl @("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", $serverKey)
        Invoke-OpenSsl @("req", "-new", "-key", $serverKey, "-config", (Join-Path $temp "server.cnf"), "-out", (Join-Path $temp "server.csr"))
        $serialArgs = if (Test-Path $serial) { @("-CAserial", $serial) } else { @("-CAcreateserial") }
        Invoke-OpenSsl (@("x509", "-req", "-in", (Join-Path $temp "server.csr"), "-CA", $caCrt, "-CAkey", $caKey) + $serialArgs + @("-out", $serverCrt, "-days", "$Days", "-sha256", "-extfile", (Join-Path $temp "server.ext")))
        Protect-Key $serverKey
        Write-Host "created server certificate: $serverCrt"
    }

    foreach ($name in $clientMasks.Keys) {
        # Do not reuse the [uint64]$mask variable here: its type constraint
        # would coerce "0x..." back to a decimal number.
        [string]$maskText = $clientMasks[$name]
        $holders = if ($clientHolders.ContainsKey($name)) { $clientHolders[$name] } else { "" }
        $crt = Join-Path $Out "$name.crt"
        $key = Join-Path $Out "$name.key"

        if (((Test-Path $crt) -and -not (Test-Path $key)) -or ((Test-Path $key) -and -not (Test-Path $crt))) {
            Fail "incomplete client files for $name; remove them or pass -Force"
        }
        if ((Test-Path $crt) -and (Test-Path $key) -and -not $Force) {
            Write-Host "reusing client certificate: $crt"
            continue
        }

        @"
[req]
distinguished_name = dn
prompt = no

[dn]
CN = $name
"@ | Set-Content -Encoding ascii (Join-Path $temp "client-$name.cnf")

        $san = "URI:signer://principal/$name"
        if ($holders.Length -gt 0) {
            foreach ($holder in $holders.Split(',')) {
                $san += ",URI:signer://holder/$holder"
            }
        }
        $san += ",URI:signer://permissions/$maskText"
        @"
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = $san
"@ | Set-Content -Encoding ascii (Join-Path $temp "client-$name.ext")

        Invoke-OpenSsl @("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", $key)
        Invoke-OpenSsl @("req", "-new", "-key", $key, "-config", (Join-Path $temp "client-$name.cnf"), "-out", (Join-Path $temp "client-$name.csr"))
        $serialArgs = if (Test-Path $serial) { @("-CAserial", $serial) } else { @("-CAcreateserial") }
        Invoke-OpenSsl (@("x509", "-req", "-in", (Join-Path $temp "client-$name.csr"), "-CA", $caCrt, "-CAkey", $caKey) + $serialArgs + @("-out", $crt, "-days", "$Days", "-sha256", "-extfile", (Join-Path $temp "client-$name.ext")))
        Invoke-OpenSsl @("x509", "-in", $crt, "-outform", "der", "-out", (Join-Path $Out "$name.der"))
        Protect-Key $key
        Write-Host ("created client {0,-16} permissions={1} fingerprint={2}" -f $name, $maskText, (Get-Fingerprint $crt))
    }

    Write-Host ""
    Write-Host "Files are in $Out"
    Write-Host "CA private key: $caKey (keep offline; never commit)"
    Write-Host "Server: $serverCrt $serverKey"
    Write-Host "Server SHA-256: $(Get-Fingerprint $serverCrt)"
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $temp
}
