param(
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [switch]$Force,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Fetches (or builds) the wormhole-fortiproxy.exe userspace Fortinet SSL VPN sidecar and writes
# it to obj\fortiproxy\<arch>\ so the project file can pick it up as a None item and copy to
# the output directory. Mirrors Fetch-WgProxy.ps1 beat-for-beat -- the build is optional and a
# miss must NOT fail the .NET build; FortinetTunnelProvider surfaces a clean runtime error.
#
# Resolution order:
#   1. If a SHA256-pinned release URL is configured for $Arch, download and verify.
#   2. Else if Go is on PATH, build from source under tools\wormhole-fortiproxy\.
#   3. Else emit a non-fatal warning.

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$sourceDir  = Join-Path $repoRoot "tools\wormhole-fortiproxy"
$stagingDir = Join-Path $repoRoot "obj\fortiproxy\$Arch"
$binaryPath = Join-Path $stagingDir "wormhole-fortiproxy.exe"

$releases = @{
    "x64"   = $null
    "arm64" = $null
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

function Remove-StagedBinary {
    if (Test-Path $binaryPath) {
        try {
            Remove-Item -Force $binaryPath
            Write-Info "REMOVE stale $binaryPath"
        }
        catch {
            Write-Warning "Could not remove stale wormhole-fortiproxy.exe at '$binaryPath': $_"
        }
    }
}

$release = $releases[$Arch]
if ($release) {
    $haveFile = Test-Path $binaryPath
    if ($haveFile -and -not $Force) {
        $actual = Get-FileSha256 $binaryPath
        if ($actual -eq $release.Sha256) {
            Write-Info "OK    wormhole-fortiproxy.exe ($Arch)"
            return
        }
        Write-Info "STALE wormhole-fortiproxy.exe ($Arch) - re-downloading"
    }
    Write-Info "FETCH $($release.Url) -> wormhole-fortiproxy.exe ($Arch)"
    try {
        Invoke-WebRequest -Uri $release.Url -OutFile $binaryPath -UseBasicParsing
    } catch {
        throw "Failed to download wormhole-fortiproxy.exe: $_"
    }
    $hash = Get-FileSha256 $binaryPath
    if ($hash -ne $release.Sha256) {
        Remove-Item $binaryPath -Force
        throw "SHA256 mismatch for wormhole-fortiproxy.exe ($Arch). Expected $($release.Sha256), got $hash."
    }
    Write-Info "OK    wormhole-fortiproxy.exe ($Arch) (pinned)"
    return
}

$go = Get-Command go -ErrorAction SilentlyContinue
if ($go) {
    Write-Info "BUILD wormhole-fortiproxy.exe ($Arch) from source"
    $env:GOOS = "windows"
    $env:GOARCH = if ($Arch -eq "arm64") { "arm64" } else { "amd64" }
    $buildOk = $false
    $failureDetail = $null
    Push-Location $sourceDir
    try {
        & go mod download 2>&1 | ForEach-Object { Write-Info $_ }
        if ($LASTEXITCODE -ne 0) {
            $failureDetail = "go mod download exited with code $LASTEXITCODE"
        }
        else {
            & go build -trimpath -ldflags "-s -w" -o $binaryPath . 2>&1 | ForEach-Object { Write-Info $_ }
            if ($LASTEXITCODE -eq 0) {
                $buildOk = $true
            }
            else {
                $failureDetail = "go build exited with code $LASTEXITCODE"
            }
        }
    }
    catch {
        $failureDetail = "unexpected error during go build: $_"
    }
    finally {
        Pop-Location
        Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
    }
    if ($buildOk) {
        Write-Info "OK    wormhole-fortiproxy.exe ($Arch) (built)"
        return
    }
    Remove-StagedBinary
    Write-Warning "wormhole-fortiproxy.exe build failed ($failureDetail). Continuing without the sidecar; Fortinet tunnels will surface a runtime error if used."
    return
}

Remove-StagedBinary
Write-Warning "wormhole-fortiproxy.exe not built: no pinned release for arch '$Arch' and 'go' is not on PATH. Fortinet tunnels will be unavailable at runtime until this sidecar is provided."
