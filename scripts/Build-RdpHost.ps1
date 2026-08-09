param(
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64',
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$project = Join-Path $repoRoot 'tools\wormhole-rdp-host\Wormhole.RdpHost.csproj'
$stagingDir = Join-Path $repoRoot 'dist-electron'
$publishDir = Join-Path $stagingDir "rdp-host-$Arch"
$binaryPath = Join-Path $stagingDir "wormhole-rdp-host-$Arch.exe"
$rid = if ($Arch -eq 'arm64') { 'win-arm64' } else { 'win-x64' }

function Write-Info([string]$message) {
    if (-not $Quiet) { Write-Host $message }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw '.NET SDK is required to build the Windows ActiveX RDP host.'
}

New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
if (Test-Path -LiteralPath $publishDir) {
    Remove-Item -LiteralPath $publishDir -Recurse -Force
}
if (Test-Path -LiteralPath $binaryPath) {
    Remove-Item -LiteralPath $binaryPath -Force
}

Write-Info "BUILD wormhole-rdp-host.exe ($Arch)"
& dotnet publish $project `
    --configuration Release `
    --runtime $rid `
    -p:Platform=$Arch `
    --self-contained true `
    --output $publishDir `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:PublishTrimmed=false
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE."
}

$publishedBinary = Join-Path $publishDir 'Wormhole.RdpHost.exe'
if (-not (Test-Path -LiteralPath $publishedBinary)) {
    throw "dotnet publish completed without producing '$publishedBinary'."
}
Copy-Item -LiteralPath $publishedBinary -Destination $binaryPath -Force
Write-Info "OK    $binaryPath"
