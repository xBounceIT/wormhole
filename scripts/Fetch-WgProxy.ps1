param(
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [switch]$Force,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Merge registry PATH entries into the process PATH so this script finds `go`
# even when MSBuild's Exec spawns a child PowerShell with the env block its
# parent inherited at start time (which never re-reads the registry after a
# fresh choco/scoop install of Go). See Fetch-OvpnProxy.ps1 for the
# longer-form explanation of this trick.
$pathParts = $env:PATH -split ';' | Where-Object { $_ }
$registryPath = (([Environment]::GetEnvironmentVariable("PATH", "Machine"), [Environment]::GetEnvironmentVariable("PATH", "User")) -join ';')
foreach ($p in ($registryPath -split ';' | Where-Object { $_ })) {
    if ($pathParts -notcontains $p) { $pathParts += $p }
}
$env:PATH = $pathParts -join ';'

# Fetches (or builds) the wormhole-wgproxy.exe userspace WireGuard sidecar and writes it
# to obj\wgproxy\<arch>\ so the project file can pick it up as a None item and copy to the
# output directory. This is shared by the Electron development and packaging builds.
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

# Drop any previously-staged binary on a fallback/failure path. The csproj's
# FetchWgProxy target gates its <None Include> on `Exists(...)` of $binaryPath, so a
# stale binary left here from a prior successful build would silently get copied into
# every subsequent output despite the script warning that the sidecar is unavailable --
# protocol drift / wrong-binary behavior at runtime, exactly opposite of what the
# warning advertises. Best-effort delete; if it fails the worst outcome is the staleness
# we wanted to avoid, and the user sees the warning either way.
function Remove-StagedBinary {
    if (Test-Path $binaryPath) {
        try {
            Remove-Item -Force $binaryPath
            Write-Info "REMOVE stale $binaryPath"
        }
        catch {
            Write-Warning "Could not remove stale wormhole-wgproxy.exe at '$binaryPath': $_"
        }
    }
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

# Step 2: try to build from source if Go is installed. Per the WireGuard tunnel PR's
# explicit design, the sidecar is optional and a build miss must NOT fail the .NET build --
# WireGuardTunnelProvider surfaces a clean runtime error if the binary is missing. We
# therefore catch every go-related failure here and downgrade it to a warning.
#
# Note for dep bumps: regenerate tools\wormhole-wgproxy\go.sum with GOOS=windows when
# bumping deps -- the windows-only indirect `golang.zx2c4.com/wintun` is otherwise stripped
# on Linux/macOS tidy passes and the next cross-compile from Windows fails with
# "missing go.sum entry for golang.zx2c4.com/wintun".
$go = Get-Command go -ErrorAction SilentlyContinue
if ($go) {
    Write-Info "BUILD wormhole-wgproxy.exe ($Arch) from source"
    # Snapshot the caller's GOOS/GOARCH so the finally block restores them instead of
    # blindly deleting -- this script is sometimes dot-sourced or run directly from a Go
    # dev's shell that already had these set for another project.
    $priorGoos   = if (Test-Path Env:\GOOS)   { $env:GOOS }   else { $null }
    $priorGoarch = if (Test-Path Env:\GOARCH) { $env:GOARCH } else { $null }
    $env:GOOS = "windows"
    $env:GOARCH = if ($Arch -eq "arm64") { "arm64" } else { "amd64" }
    $buildOk = $false
    $failureDetail = $null
    $pushed = $false
    # Track which stage failed so the catch can report an accurate cause (missing source
    # tree vs. an actual go compile failure) instead of always saying "go build" -- which
    # would mislead a developer staring at a sparse checkout into debugging the toolchain.
    $stage = "pre-build"
    try {
        # Push-Location is inside the try so a missing $sourceDir (sparse checkout, stale
        # branch) becomes a normal $failureDetail instead of a terminating script error
        # that would fail the .NET build, violating the "build miss is a warning, not an
        # error" contract above.
        Push-Location $sourceDir
        $pushed = $true
        $stage = "build"
        # Tee stdout+stderr into a list as it streams so the failure detail can include
        # the real go error even under -Quiet (Write-Info is a no-op there). The local EAP
        # override is required because `2>&1` of native stderr emits ErrorRecord objects
        # into the pipeline, and the script-wide $ErrorActionPreference = "Stop" would
        # otherwise throw on the first stderr line -- losing the line/column of the actual
        # compile error in favor of the (less useful) package-header line.
        #
        # go.sum is committed for this tool so plain `go build` works without a preflight.
        $buildLines = [System.Collections.Generic.List[string]]::new()
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & go build -trimpath -ldflags "-s -w" -o $binaryPath . 2>&1 | ForEach-Object {
                $text = "$_"
                $buildLines.Add($text)
                Write-Info $text
            }
            $buildExit = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $prevEAP
        }
        if ($buildExit -eq 0) {
            $buildOk = $true
        }
        else {
            $tail = ($buildLines | Select-Object -Last 5) -join [Environment]::NewLine
            $failureDetail = "go build exited with code ${buildExit}: ${tail}"
        }
    }
    catch {
        $failureDetail = if ($stage -eq "pre-build") {
            "could not enter source directory '$sourceDir': $_"
        } else {
            "unexpected error during go build: $_"
        }
    }
    finally {
        # Wrap cleanup so a Pop-Location or env-restore failure cannot propagate out of the
        # finally and exit the script non-zero -- which would fail the .NET build, breaking
        # the "build miss is a warning, not an error" contract. Also ensures env vars are
        # always restored even if Pop-Location itself throws (e.g., the prior location was
        # deleted mid-build).
        if ($pushed) {
            try { Pop-Location } catch { Write-Info "Pop-Location failed during cleanup: $_" }
        }
        try {
            if ($null -ne $priorGoos)   { $env:GOOS   = $priorGoos }   else { Remove-Item Env:\GOOS   -ErrorAction SilentlyContinue }
            if ($null -ne $priorGoarch) { $env:GOARCH = $priorGoarch } else { Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue }
        } catch {
            Write-Info "Env restore failed during cleanup: $_"
        }
    }
    if ($buildOk) {
        Write-Info "OK    wormhole-wgproxy.exe ($Arch) (built)"
        return
    }
    Remove-StagedBinary
    Write-Warning "wormhole-wgproxy.exe build failed ($failureDetail). Continuing without the sidecar; WireGuard tunnels will surface a runtime error if used."
    return
}

# Step 3: no release pinned and no Go toolchain. Don't fail the build -- the rest of Wormhole
# is fully functional; only WireGuard tunnels will surface a clean runtime error.
Remove-StagedBinary
Write-Warning "wormhole-wgproxy.exe not built: no pinned release for arch '$Arch' and 'go' is not on PATH. WireGuard tunnels will be unavailable at runtime until this sidecar is provided."
