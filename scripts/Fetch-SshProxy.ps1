param(
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $repoRoot "obj\sshproxy\$Arch"
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$previousGoos = $env:GOOS
$previousGoarch = $env:GOARCH
$previousCgo = $env:CGO_ENABLED
Push-Location (Join-Path $repoRoot 'tools\wormhole-sshproxy')
try {
    $env:GOOS = 'windows'
    $env:GOARCH = if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' }
    $env:CGO_ENABLED = '0'
    & go build -trimpath -ldflags '-s -w' -o (Join-Path $destination 'wormhole-sshproxy.exe') .
    if ($LASTEXITCODE -ne 0) { throw "SSH sidecar build failed for $Arch." }
}
finally {
    Pop-Location
    $env:GOOS = $previousGoos
    $env:GOARCH = $previousGoarch
    $env:CGO_ENABLED = $previousCgo
}
