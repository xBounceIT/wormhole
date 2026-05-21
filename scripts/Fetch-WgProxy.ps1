param(
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [switch]$Force,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Fetches (or builds) the wormhole-wgproxy.exe userspace WireGuard sidecar and writes it
# to obj\wgproxy\<arch>\ so the project file can pick it up as a None item and copy to the
# output directory. Mirrors the pattern in Fetch-WebAssets.ps1.
#
# Resolution order:
#   1. If a SHA256-pinned release URL is configured for $Arch, download and verify.
#   2. Else if Go is on PATH, build from source under tools\wormhole-wgproxy\.
#   3. Else emit a non-fatal warning. Wormhole still builds; the tunnel feature errors at
#      runtime if the user actually opens a connection with a WireGuard tunnel attached.
#
# To pin a release, populate $releases below with { Url, Sha256 } per arch and bump the
# pinned version comment. Until that's set up, the build-from-source path is the default.

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$sourceDir  = Join-Path $repoRoot "tools\wormhole-wgproxy"
$stagingDir = Join-Path $repoRoot "obj\wgproxy\$Arch"
$binaryPath = Join-Path $stagingDir "wormhole-wgproxy.exe"

# Pinned releases. Populate when a tagged release is published. Leave $null to fall through
# to source build.
$releases = @{
    "x64"   = $null   # @{ Url = "https://github.com/.../releases/download/wgproxy-v0.1.0/wormhole-wgproxy-windows-amd64.exe"; Sha256 = "..." }
    "arm64" = $null   # @{ Url = "..."; Sha256 = "..." }
}

function Write-Info($message) {
    if (-not $Quiet) { Write-Host $message }
}

function Get-FileSha256($path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($path)
        try {
            $hash = $sha.ComputeHash($stream)
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $sha.Dispose()
    }
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

if (-not (Test-Path $stagingDir)) {
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
}

# Step 1: if a pinned release is configured for this arch, prefer it.
$release = $releases[$Arch]
if ($release) {
    $haveFile = Test-Path $binaryPath
    if ($haveFile -and -not $Force) {
        $actual = Get-FileSha256 $binaryPath
        if ($actual -eq $release.Sha256) {
            Write-Info "OK    wormhole-wgproxy.exe ($Arch)"
            return
        }
        Write-Info "STALE wormhole-wgproxy.exe ($Arch) - re-downloading"
    }
    Write-Info "FETCH $($release.Url) -> wormhole-wgproxy.exe ($Arch)"
    try {
        Invoke-WebRequest -Uri $release.Url -OutFile $binaryPath -UseBasicParsing
    } catch {
        throw "Failed to download wormhole-wgproxy.exe: $_"
    }
    $hash = Get-FileSha256 $binaryPath
    if ($hash -ne $release.Sha256) {
        Remove-Item $binaryPath -Force
        throw "SHA256 mismatch for wormhole-wgproxy.exe ($Arch). Expected $($release.Sha256), got $hash."
    }
    Write-Info "OK    wormhole-wgproxy.exe ($Arch) (pinned)"
    return
}

# Step 2: try to build from source if Go is installed.
$go = Get-Command go -ErrorAction SilentlyContinue
if ($go) {
    Write-Info "BUILD wormhole-wgproxy.exe ($Arch) from source"
    $env:GOOS = "windows"
    $env:GOARCH = if ($Arch -eq "arm64") { "arm64" } else { "amd64" }
    Push-Location $sourceDir
    try {
        & go build -trimpath -ldflags "-s -w" -o $binaryPath .
        if ($LASTEXITCODE -ne 0) {
            throw "go build exited with code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
        Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
    }
    Write-Info "OK    wormhole-wgproxy.exe ($Arch) (built)"
    return
}

# Step 3: no release pinned and no Go toolchain. Don't fail the build -- the rest of Wormhole
# is fully functional; only WireGuard tunnels will surface a clean runtime error.
Write-Warning "wormhole-wgproxy.exe not built: no pinned release for arch '$Arch' and 'go' is not on PATH. WireGuard tunnels will be unavailable at runtime until this sidecar is provided."
