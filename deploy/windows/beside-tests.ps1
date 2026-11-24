# Copies wireguard.dll beside every test binary of the agent, building them
# first. The agent loads the DLL from its executable's own directory and
# nowhere else, and where cargo puts a test binary depends on its version
# (target\debug\deps, or a directory of its own under target\debug\build),
# so cargo is asked rather than the path assumed.
#
#   pwsh deploy/windows/beside-tests.ps1 <path to wireguard.dll>
param([Parameter(Mandatory)] [string] $Dll)
# Not "Stop": cargo reports its progress on stderr, which Windows PowerShell
# would take for a failure. What can fail is checked below.

$dirs = cargo test -p wireserve-agent --locked --no-run --message-format=json |
    ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
    Where-Object { $_.executable } |
    ForEach-Object { Split-Path $_.executable } |
    Sort-Object -Unique
if ($LASTEXITCODE -ne 0) { throw "building the agent's tests failed" }
if (-not $dirs) { throw "cargo named no test binary" }
foreach ($dir in $dirs) {
    Copy-Item $Dll $dir -ErrorAction Stop
    Write-Host "wireguard.dll -> $dir"
}
