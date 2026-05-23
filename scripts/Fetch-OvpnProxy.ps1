param(
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [switch]$Force,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Hydrate VCPKG_ROOT and PATH from the User/Machine registry so this script
# can find vcpkg + cmake + gcc + go regardless of how it was invoked. MSBuild's
# Exec task spawns PowerShell with the env block its parent process had at
# process-start time, which on Windows never re-reads the registry. Without
# this hydration, a fresh shell session that just ran `vcpkg/bootstrap` or
# `choco install cmake` then `dotnet build` silently drops to the no-vcpkg /
# no-cmake branch (producing the mock-only sidecar instead of the
# OpenVPN3-linked one) because the registry writes done by those installers
# are invisible to the running process tree.
#
# Read order: process env first (caller may have set it explicitly), then
# User registry, then Machine registry.
if (-not $env:VCPKG_ROOT) {
    $vroot = [Environment]::GetEnvironmentVariable("VCPKG_ROOT", "User")
    if (-not $vroot) {
        $vroot = [Environment]::GetEnvironmentVariable("VCPKG_ROOT", "Machine")
    }
    if ($vroot) { $env:VCPKG_ROOT = $vroot }
}

# Merge registry PATH entries that aren't already in the process PATH. We
# append (not prepend) so caller-specified PATH overrides win. Filter empty
# entries to avoid the pathologically empty-segment that Windows occasionally
# leaves in the registry.
$pathParts = $env:PATH -split ';' | Where-Object { $_ }
$registryPath = (([Environment]::GetEnvironmentVariable("PATH", "Machine"), [Environment]::GetEnvironmentVariable("PATH", "User")) -join ';')
foreach ($p in ($registryPath -split ';' | Where-Object { $_ })) {
    if ($pathParts -notcontains $p) { $pathParts += $p }
}
$env:PATH = $pathParts -join ';'

# Fetches (or builds) the wormhole-ovpnproxy.exe userspace OpenVPN sidecar and writes it
# to obj\ovpnproxy\<arch>\ so the project file can pick it up as a None item and copy to
# the output directory. Mirrors Fetch-WgProxy.ps1.
#
# Resolution order:
#   1. If a SHA256-pinned release URL is configured for $Arch, download and verify.
#   2. Else if Go + CMake + a C++ toolchain are on PATH AND the OpenVPN3 + mbedTLS
#      submodules are populated, build from source with -tags ovpn3 (full OpenVPN3 link).
#   3. Else if Go is on PATH (no submodules / no C++ toolchain), build without the
#      ovpn3 tag -- produces a binary that supports --mock and the SOCKS5 wire protocol
#      but errors on real-mode connect. Useful for CI / managed-side wire tests.
#   4. Else emit a non-fatal warning. Wormhole still builds; OpenVPN tunnels surface a
#      runtime error.

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$sourceDir  = Join-Path $repoRoot "tools\wormhole-ovpnproxy"
$shimDir    = Join-Path $sourceDir "ovpn_shim"
$shimBuild  = Join-Path $shimDir "build"
$openvpn3   = Join-Path $sourceDir "third_party\openvpn3\client\ovpncli.hpp"
$mbedtls    = Join-Path $sourceDir "third_party\mbedtls\include\mbedtls\ssl.h"
$stagingDir = Join-Path $repoRoot "obj\ovpnproxy\$Arch"
$binaryPath = Join-Path $stagingDir "wormhole-ovpnproxy.exe"

# Pinned releases. Populate when a tagged release is published. Leave $null to fall
# through to source build.
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
        try { $hash = $sha.ComputeHash($stream) }
        finally { $stream.Dispose() }
    }
    finally { $sha.Dispose() }
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

if (-not (Test-Path $stagingDir)) {
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
}

# Drop any previously-staged binary on a fallback/failure path so the csproj's
# Exists(...) gate doesn't silently copy a stale binary while the script warns.
function Remove-StagedBinary {
    if (Test-Path $binaryPath) {
        try {
            Remove-Item -Force $binaryPath
            Write-Info "REMOVE stale $binaryPath"
        }
        catch {
            Write-Warning "Could not remove stale wormhole-ovpnproxy.exe at '$binaryPath': $_"
        }
    }
}

# Step 1: pinned release.
$release = $releases[$Arch]
if ($release) {
    $haveFile = Test-Path $binaryPath
    if ($haveFile -and -not $Force) {
        $actual = Get-FileSha256 $binaryPath
        if ($actual -eq $release.Sha256) {
            Write-Info "OK    wormhole-ovpnproxy.exe ($Arch)"
            return
        }
        Write-Info "STALE wormhole-ovpnproxy.exe ($Arch) - re-downloading"
    }
    Write-Info "FETCH $($release.Url) -> wormhole-ovpnproxy.exe ($Arch)"
    try {
        Invoke-WebRequest -Uri $release.Url -OutFile $binaryPath -UseBasicParsing
    } catch {
        throw "Failed to download wormhole-ovpnproxy.exe: $_"
    }
    $hash = Get-FileSha256 $binaryPath
    if ($hash -ne $release.Sha256) {
        Remove-Item $binaryPath -Force
        throw "SHA256 mismatch for wormhole-ovpnproxy.exe ($Arch). Expected $($release.Sha256), got $hash."
    }
    Write-Info "OK    wormhole-ovpnproxy.exe ($Arch) (pinned)"
    return
}

# Step 2 / 3: build from source if Go is on PATH. Detect the full toolchain (Go + CMake
# + C++ + submodules) and pick the build path accordingly.
$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
    Remove-StagedBinary
    Write-Warning "wormhole-ovpnproxy.exe not built: no pinned release for arch '$Arch' and 'go' is not on PATH. OpenVPN tunnels will be unavailable at runtime until this sidecar is provided."
    return
}

# Tag selection: only enable ovpn3 if every prerequisite is present. Mock-only binary is
# strictly better than a build break or a half-linked binary.
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
$haveOvpn3Src = (Test-Path $openvpn3) -and (Test-Path $mbedtls)
$buildTag = ""
if ($cmake -and $haveOvpn3Src) {
    $buildTag = "ovpn3"
    Write-Info "BUILD wormhole-ovpnproxy.exe ($Arch) with -tags ovpn3 (full OpenVPN3)"
} elseif (-not $haveOvpn3Src) {
    Write-Info "BUILD wormhole-ovpnproxy.exe ($Arch) without ovpn3 tag (submodules not populated; mock-only sidecar)"
} else {
    Write-Info "BUILD wormhole-ovpnproxy.exe ($Arch) without ovpn3 tag (cmake not on PATH; mock-only sidecar)"
}

# If we're going to enable ovpn3, build the shim static lib first.
$shimBuilt = $false
if ($buildTag -eq "ovpn3") {
    # Optional: use vcpkg manifest mode if VCPKG_ROOT is set. This pulls asio, jsoncpp,
    # lz4, and xxhash automatically from ovpn_shim/vcpkg.json. Without vcpkg, the user
    # must install those four libraries through whatever package manager they use and
    # ensure CMake's find_package can locate them.
    #
    # Triplet choice: Go CGO on Windows uses gcc (MinGW). MSVC-built .lib files won't
    # link cleanly into Go's CGO output, so we use the mingw-static triplet which makes
    # vcpkg build all transitive deps with the MinGW toolchain that gcc/g++ also use.
    # The `MinGW Makefiles` generator drives mingw32-make. Ninja would be faster if
    # available but isn't a hard requirement.
    $cmakeArgs = @("-B", $shimBuild, "-S", $shimDir, "-G", "MinGW Makefiles")
    if ($env:VCPKG_ROOT -and (Test-Path "$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake")) {
        $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"
        $triplet = if ($Arch -eq "arm64") { "arm64-mingw-static" } else { "x64-mingw-static" }
        $cmakeArgs += "-DVCPKG_TARGET_TRIPLET=$triplet"
        Write-Info "Using vcpkg toolchain at $env:VCPKG_ROOT (triplet $triplet, generator: MinGW Makefiles)"
    }
    else {
        Write-Info "VCPKG_ROOT not set -- relying on system find_package for asio/jsoncpp/lz4/xxhash"
    }

    Push-Location $shimDir
    try {
        if (-not (Test-Path $shimBuild)) {
            New-Item -ItemType Directory -Path $shimBuild -Force | Out-Null
        }
        # CMake emits non-fatal "Deprecation Warning" lines to stderr (e.g. from
        # mbedtls's CMakeLists requiring CMake < 3.10). With $ErrorActionPreference =
        # "Stop", piping stderr-as-stdout through `2>&1 | ForEach-Object` rewraps each
        # stderr line into an ErrorRecord and the next iteration trips the strict
        # preference, failing the build despite cmake itself succeeding ($LASTEXITCODE
        # = 0). The fix: temporarily relax $ErrorActionPreference around the native
        # cmake invocations so stderr is treated as text (matching what the operator
        # sees in a normal shell). Real failures are still caught via $LASTEXITCODE
        # below.
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & $cmake @cmakeArgs 2>&1 | ForEach-Object { Write-Info $_.ToString() }
            $cfgExit = $LASTEXITCODE
            if ($cfgExit -eq 0) {
                & $cmake --build $shimBuild --config Release 2>&1 | ForEach-Object { Write-Info $_.ToString() }
                $shimBuilt = ($LASTEXITCODE -eq 0)
            }
        }
        finally {
            $ErrorActionPreference = $prevPref
        }
    }
    catch {
        Write-Warning "ovpn_shim CMake build failed: $_"
    }
    finally {
        Pop-Location
    }
    if (-not $shimBuilt) {
        Write-Warning "ovpn_shim build failed; falling back to mock-only sidecar (no -tags ovpn3). See tools/wormhole-ovpnproxy/README.md for the full toolchain requirements."
        $buildTag = ""
    }
}

# Go build.
$env:GOOS = "windows"
$env:GOARCH = if ($Arch -eq "arm64") { "arm64" } else { "amd64" }
if ($shimBuilt) {
    $env:CGO_ENABLED = "1"
    $env:CGO_CFLAGS = "-I$shimDir"
    $env:CGO_LDFLAGS = "-L$shimBuild -lovpn_shim"
} else {
    $env:CGO_ENABLED = "0"
}
$buildOk = $false
$failureDetail = $null
Push-Location $sourceDir
# Same StrictMode/stderr-as-ErrorRecord trap as the cmake block above: Go emits
# downloads-progress lines on stderr that the strict preference would treat as
# terminating errors. Relax around the native invocations; rely on $LASTEXITCODE
# for real failure detection.
$prevPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    # `go mod download all` populates the (uncommitted) go.sum from go.mod, fetching the
    # entire build list (including transitive deps). Unlike `go mod tidy`, this does NOT
    # rewrite go.mod -- important because dev/CI environments could otherwise drift go.mod
    # against each other (different toolchain views of indirect deps). Mirrors the same
    # change in Fetch-WgProxy.ps1.
    & go mod download all 2>&1 | ForEach-Object { Write-Info $_.ToString() }
    if ($LASTEXITCODE -ne 0) {
        $failureDetail = "go mod download all exited with code $LASTEXITCODE"
    }
    else {
        $tagArgs = @()
        if ($buildTag) { $tagArgs = @("-tags", $buildTag) }
        & go build -trimpath -ldflags "-s -w" @tagArgs -o $binaryPath . 2>&1 | ForEach-Object { Write-Info $_.ToString() }
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
    $ErrorActionPreference = $prevPref
    Pop-Location
    Remove-Item Env:\GOOS         -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH       -ErrorAction SilentlyContinue
    Remove-Item Env:\CGO_ENABLED  -ErrorAction SilentlyContinue
    Remove-Item Env:\CGO_CFLAGS   -ErrorAction SilentlyContinue
    Remove-Item Env:\CGO_LDFLAGS  -ErrorAction SilentlyContinue
}

if ($buildOk) {
    $tagSuffix = if ($buildTag) { " (built, -tags $buildTag)" } else { " (built, mock-only)" }
    Write-Info "OK    wormhole-ovpnproxy.exe ($Arch)$tagSuffix"
    return
}

Remove-StagedBinary
Write-Warning "wormhole-ovpnproxy.exe build failed ($failureDetail). Continuing without the sidecar; OpenVPN tunnels will surface a runtime error if used."
