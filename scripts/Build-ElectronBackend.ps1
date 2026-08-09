param(
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64',
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$sourceDir = Join-Path $repoRoot 'tools\wormhole-backend'
$stagingDir = Join-Path $repoRoot 'dist-electron'
$binaryPath = Join-Path $stagingDir "wormhole-backend-$Arch.exe"

function Write-Info([string]$message) {
    if (-not $Quiet) { Write-Host $message }
}

New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

if (Test-Path -LiteralPath $binaryPath) {
    Remove-Item -LiteralPath $binaryPath -Force
}

$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
    throw 'Go is required to build the Electron backend.'
}

$previousGoos = if (Test-Path Env:\GOOS) { $env:GOOS } else { $null }
$previousGoarch = if (Test-Path Env:\GOARCH) { $env:GOARCH } else { $null }
$previousCgoEnabled = if (Test-Path Env:\CGO_ENABLED) { $env:CGO_ENABLED } else { $null }
$env:GOOS = 'windows'
$env:GOARCH = if ($Arch -eq 'arm64') { 'arm64' } else { 'amd64' }
$env:CGO_ENABLED = '0'

try {
    $pushed = $false
    Push-Location $sourceDir
    $pushed = $true
    try {
        Write-Info "BUILD wormhole-backend.exe ($Arch)"
        & go build -trimpath -ldflags '-s -w' -o $binaryPath .
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        if ($pushed) { Pop-Location }
    }
}
finally {
    if ($null -eq $previousGoos) { Remove-Item Env:\GOOS -ErrorAction SilentlyContinue }
    else { $env:GOOS = $previousGoos }
    if ($null -eq $previousGoarch) { Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue }
    else { $env:GOARCH = $previousGoarch }
    if ($null -eq $previousCgoEnabled) { Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue }
    else { $env:CGO_ENABLED = $previousCgoEnabled }
}

if (-not (Test-Path -LiteralPath $binaryPath)) {
    throw "go build completed without producing '$binaryPath'."
}

Write-Info "OK    $binaryPath"
