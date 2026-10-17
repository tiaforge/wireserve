# Fetches wireguard.dll for the Windows agent and puts it in the given
# directory. The official wireguard-nt release from download.wireguard.com,
# refused unless the archive is exactly the one pinned here and the DLL is
# signed by WireGuard LLC. Used by CI and the release workflow alike, so the
# DLL that is tested is the DLL that ships.
#
#   pwsh deploy/windows/fetch-wireguard-nt.ps1 <destination> [amd64|arm64]
#
# To move to a newer wireguard-nt: change the version and checksum below,
# and compare its include/wireguard.h with the layouts in
# crates/wireserve-agent/src/wg/nt.rs before anything else.
param(
    [Parameter(Mandatory)] [string] $Destination,
    [ValidateSet("amd64", "arm64")] [string] $Arch = "amd64"
)
$ErrorActionPreference = "Stop"

$version = "1.1"
$sha256 = "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace"

$work = Join-Path ([IO.Path]::GetTempPath()) "wireguard-nt-$version-$PID"
New-Item -ItemType Directory -Force $work | Out-Null
$zip = Join-Path $work "wireguard-nt.zip"
Invoke-WebRequest "https://download.wireguard.com/wireguard-nt/wireguard-nt-$version.zip" -OutFile $zip
$sum = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($sum -ne $sha256) { throw "wireguard-nt $version archive checksum mismatch: $sum" }

Expand-Archive $zip -DestinationPath $work
$dll = Join-Path $work "wireguard-nt\bin\$Arch\wireguard.dll"
$sig = Get-AuthenticodeSignature -LiteralPath $dll
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notlike "CN=WireGuard LLC,*") {
    throw "wireguard.dll is not signed by WireGuard LLC: $($sig.Status) $($sig.SignerCertificate.Subject)"
}

New-Item -ItemType Directory -Force $Destination | Out-Null
Copy-Item $dll $Destination
Remove-Item -Recurse -Force $work
Write-Host "wireguard-nt $version ($Arch) wireguard.dll -> $Destination"
