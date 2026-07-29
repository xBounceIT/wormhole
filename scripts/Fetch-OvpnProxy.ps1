param(
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [switch]$Force,
    [switch]$Quiet,
    [switch]$RequireReal
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

# Drop MSYS / Git-for-Windows POSIX overlay dirs from PATH. Git hooks (husky's
# pre-commit build runs this script via MSBuild) are ALWAYS spawned from Git's bundled
# sh, which prepends Git\usr\bin, Git\bin, and Git\mingw64\bin. The last one ships its
# own libwinpthread-1.dll; gcc's cc1.exe resolves DLLs by PATH search order, loads
# Git's ABI-incompatible copy, and dies with a silent exit 1 — surfacing here as a
# vcpkg "BUILD_FAILED" on whatever port misses the binary cache (and a poisoned vcpkg
# compiler-ABI hash). Detection is by content, not by name: an entry goes if it is an
# MSYS runtime dir (msys-2.0.dll present) or Git's private mingw64\bin (git.exe AND
# libwinpthread-1.dll side by side — the real toolchain's mingw64\bin carries no
# git.exe, and Git's cmd\ dir carries no DLLs, so `git` itself stays resolvable).
$pathParts = @($pathParts | Where-Object {
    -not ((Test-Path -LiteralPath (Join-Path $_ "msys-2.0.dll") -ErrorAction SilentlyContinue) -or
          ((Test-Path -LiteralPath (Join-Path $_ "git.exe") -ErrorAction SilentlyContinue) -and
           (Test-Path -LiteralPath (Join-Path $_ "libwinpthread-1.dll") -ErrorAction SilentlyContinue)))
})
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
#      but errors on real-mode connect. Useful for development/managed wire tests.
#   4. Else emit a non-fatal warning.
# When -RequireReal is set (the default for Release), paths 3/4 and every failed native
# configure/compile/link step fail closed and remove any stale staged binary.

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$sourceDir  = Join-Path $repoRoot "tools\wormhole-ovpnproxy"
$shimDir    = Join-Path $sourceDir "ovpn_shim"
$shimBuild  = Join-Path $shimDir "build\$Arch"
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

function Assert-RequiredRealBinary {
    if (-not $RequireReal) { return }
    if (-not (Test-Path -LiteralPath $binaryPath)) {
        throw "The required real OpenVPN3 sidecar for '$Arch' was not produced."
    }

    $bytes = [System.IO.File]::ReadAllBytes($binaryPath)
    try {
        if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
            throw "The staged OpenVPN3 sidecar for '$Arch' is not a valid PE executable."
        }
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
        if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length) {
            throw "The staged OpenVPN3 sidecar for '$Arch' has an invalid PE header."
        }
        if ([BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) {
            throw "The staged OpenVPN3 sidecar for '$Arch' has an invalid PE signature."
        }
        $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
        $expectedMachine = if ($Arch -eq "arm64") { 0xaa64 } else { 0x8664 }
        if ($machine -ne $expectedMachine) {
            throw ("The staged OpenVPN3 sidecar has machine type 0x{0:x4}; expected 0x{1:x4} for '$Arch'." -f
                   $machine, $expectedMachine)
        }
        $ascii = [Text.Encoding]::ASCII.GetString($bytes)
        if ($ascii.IndexOf("binding not linked", [StringComparison]::Ordinal) -ge 0) {
            throw "The staged OpenVPN3 sidecar for '$Arch' is the development-only mock stub."
        }
    }
    catch {
        Remove-StagedBinary
        throw
    }
}

# Step 1: pinned release.
$release = $releases[$Arch]
if ($release) {
    $haveFile = Test-Path $binaryPath
    if ($haveFile -and -not $Force) {
        $actual = Get-FileSha256 $binaryPath
        if ($actual -eq $release.Sha256) {
            Assert-RequiredRealBinary
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
    Assert-RequiredRealBinary
    Write-Info "OK    wormhole-ovpnproxy.exe ($Arch) (pinned)"
    return
}

# Step 2 / 3: build from source if Go is on PATH. Detect the full toolchain (Go + CMake
# + C++ + submodules) and pick the build path accordingly.
$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
    Remove-StagedBinary
    if ($RequireReal) {
        throw "A real OpenVPN3 sidecar is required for '$Arch', but 'go' is not on PATH."
    }
    Write-Warning "wormhole-ovpnproxy.exe not built: no pinned release for arch '$Arch' and 'go' is not on PATH. OpenVPN tunnels will be unavailable at runtime until this sidecar is provided."
    return
}

# Tag selection: only enable ovpn3 if every prerequisite is present. Mock-only binary is
# strictly better than a build break or a half-linked binary.
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
$haveOvpn3Src = (Test-Path $openvpn3) -and (Test-Path $mbedtls)
$cCompilerNames = if ($Arch -eq "arm64") {
    # llvm-mingw provides GCC-compatible aliases for clang. Prefer the aliases to
    # preserve existing CMake caches while ovpn_cgo.go links its libc++ explicitly.
    @("aarch64-w64-mingw32-gcc", "aarch64-w64-mingw32-clang")
} else {
    @("gcc")
}
$cppCompilerNames = if ($Arch -eq "arm64") {
    @("aarch64-w64-mingw32-g++", "aarch64-w64-mingw32-clang++")
} else {
    @("g++")
}
$cCompiler = $cCompilerNames |
    ForEach-Object { Get-Command $_ -ErrorAction SilentlyContinue } |
    Select-Object -First 1
$cppCompiler = $cppCompilerNames |
    ForEach-Object { Get-Command $_ -ErrorAction SilentlyContinue } |
    Select-Object -First 1
$arm64CompilerIsLlvm = $true
if ($Arch -eq "arm64" -and $cCompiler -and $cppCompiler) {
    $cCompilerBanner = (& $cCompiler.Source --version 2>&1 | Out-String)
    $cCompilerVersionExitCode = $LASTEXITCODE
    $cppCompilerBanner = (& $cppCompiler.Source --version 2>&1 | Out-String)
    $cppCompilerVersionExitCode = $LASTEXITCODE
    $arm64CompilerIsLlvm =
        $cCompilerVersionExitCode -eq 0 -and
        $cppCompilerVersionExitCode -eq 0 -and
        $cCompilerBanner -match "(?i)clang" -and
        $cppCompilerBanner -match "(?i)clang"
    if (-not $arm64CompilerIsLlvm) {
        # A genuine GCC cross-toolchain uses libstdc++, while the pinned ARM64
        # build links libc++. Prefer explicit clang executables if both toolchains
        # are on PATH; otherwise reject this incompatible compiler pair early.
        $cCompiler = Get-Command "aarch64-w64-mingw32-clang" -ErrorAction SilentlyContinue
        $cppCompiler = Get-Command "aarch64-w64-mingw32-clang++" -ErrorAction SilentlyContinue
        $arm64CompilerIsLlvm = $null -ne $cCompiler -and $null -ne $cppCompiler
    }
}
$haveCompiler =
    $null -ne $cCompiler -and
    $null -ne $cppCompiler -and
    $arm64CompilerIsLlvm
$buildTag = ""
if ($cmake -and $haveOvpn3Src -and $haveCompiler) {
    $buildTag = "ovpn3"
    Write-Info "BUILD wormhole-ovpnproxy.exe ($Arch) with -tags ovpn3 (full OpenVPN3)"
} elseif (-not $haveOvpn3Src) {
    Write-Info "BUILD wormhole-ovpnproxy.exe ($Arch) without ovpn3 tag (submodules not populated; mock-only sidecar)"
} elseif (-not $haveCompiler) {
    Write-Info "BUILD wormhole-ovpnproxy.exe ($Arch) without ovpn3 tag (target C/C++ compiler missing or incompatible; ARM64 requires llvm-mingw)"
} else {
    Write-Info "BUILD wormhole-ovpnproxy.exe ($Arch) without ovpn3 tag (cmake not on PATH; mock-only sidecar)"
}
if ($RequireReal -and $buildTag -ne "ovpn3") {
    Remove-StagedBinary
    throw "A real OpenVPN3 sidecar is required for '$Arch', but its source/toolchain prerequisites are incomplete."
}

# If we're going to enable ovpn3, build the shim static lib first.
$shimBuilt = $false
# Collect every line of cmake output so we can surface it if the build fails. Under
# -Quiet (how the MSBuild FetchOvpnProxy target always invokes this script) Write-Info
# is a no-op, which previously meant a real compiler/linker error was invisible in CI —
# the build just silently fell back to the mock-only stub. We record it here and dump
# the tail on failure regardless of -Quiet (see the fallback block below).
$shimOutput = [System.Collections.Generic.List[string]]::new()
if ($buildTag -eq "ovpn3") {
    # Apply vendored patches to the OpenVPN3 submodule before building. These carry fixes we need
    # ahead of (or instead of) bumping the pinned submodule. Idempotent: skip a patch that already
    # reverse-applies (already in the tree, e.g. a dev working copy). Applied with `git apply` against
    # the submodule worktree. A patch that neither applies nor reverse-applies means the submodule
    # drifted from what the patch targets, or the patch file was mangled (e.g. an EOL mismatch).
    # These patches are LOAD-BEARING for the Stormshield/OpenVPN3 data path (cert verify, CBC PKCS#7
    # padding, dyn-tls-crypt gating); building -tags ovpn3 without one would silently stage a "full"
    # sidecar that's missing a required fix and regress the tunnel. So a failed patch FAILS the build
    # loudly (vs the missing-toolchain case below, which legitimately falls back to the mock sidecar).
    $openvpn3Dir = Join-Path $sourceDir "third_party\openvpn3"
    $patchesDir  = Join-Path $sourceDir "patches"
    if (Test-Path $patchesDir) {
        $prevPrefPatch = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $failedPatches = @()
        foreach ($patch in (Get-ChildItem -Path $patchesDir -Filter '*.patch' | Sort-Object Name)) {
            & git -C $openvpn3Dir apply --reverse --check $patch.FullName 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Info "PATCH already applied: $($patch.Name)"
                continue
            }
            & git -C $openvpn3Dir apply --check $patch.FullName 2>$null
            if ($LASTEXITCODE -eq 0) {
                & git -C $openvpn3Dir apply $patch.FullName 2>&1 | ForEach-Object { Write-Info $_.ToString() }
                Write-Info "PATCH applied: $($patch.Name)"
            }
            else {
                $failedPatches += $patch.Name
            }
        }
        $ErrorActionPreference = $prevPrefPatch
        if ($failedPatches.Count -gt 0) {
            throw ("Required OpenVPN3 patch(es) failed to apply (neither apply nor reverse-apply): " +
                   "$($failedPatches -join ', '). These patches are load-bearing for the Stormshield/" +
                   "OpenVPN3 tunnel; building -tags ovpn3 without them would silently ship a regressed " +
                   "sidecar. Fix the patch (submodule drift or an EOL mismatch on the .patch file) and " +
                   "rebuild. To intentionally build the mock-only sidecar, deinit/empty the openvpn3 + " +
                   "mbedtls submodules so the build takes the no-ovpn3 path instead.")
        }
    }

    # Optional: use vcpkg manifest mode if VCPKG_ROOT is set. This pulls asio, jsoncpp,
    # lz4, and xxhash automatically from ovpn_shim/vcpkg.json. Without vcpkg, the user
    # must install those four libraries through whatever package manager they use and
    # ensure CMake's find_package can locate them.
    #
    # Triplet choice: Go CGO on Windows requires a MinGW-ABI compiler. MSVC-built .lib
    # files won't link cleanly into Go's CGO output, so vcpkg uses mingw-static for all
    # transitive dependencies. x64 uses GCC/libstdc++; ARM64 uses llvm-mingw/libc++.
    # The `MinGW Makefiles` generator drives mingw32-make. Ninja is also supported.
    $generator = if ($env:WORMHOLE_OVPN_CMAKE_GENERATOR) {
        $env:WORMHOLE_OVPN_CMAKE_GENERATOR
    } else {
        "MinGW Makefiles"
    }
    $cmakeArgs = @(
        "-B", $shimBuild,
        "-S", $shimDir,
        "-G", $generator
    )
    if ($Arch -eq "arm64") {
        $cmakeArgs += "-DCMAKE_C_COMPILER=$($cCompiler.Source)"
        $cmakeArgs += "-DCMAKE_CXX_COMPILER=$($cppCompiler.Source)"
    }
    if ($env:VCPKG_ROOT -and (Test-Path "$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake")) {
        $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"
        $triplet = if ($Arch -eq "arm64") { "arm64-mingw-static" } else { "x64-mingw-static" }
        $cmakeArgs += "-DVCPKG_TARGET_TRIPLET=$triplet"
        Write-Info "Using vcpkg toolchain at $env:VCPKG_ROOT (triplet $triplet, generator: $generator)"
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
            & $cmake @cmakeArgs 2>&1 | ForEach-Object { $line = $_.ToString(); $shimOutput.Add($line); Write-Info $line }
            $cfgExit = $LASTEXITCODE
            if ($cfgExit -eq 0) {
                & $cmake --build $shimBuild --config Release 2>&1 | ForEach-Object { $line = $_.ToString(); $shimOutput.Add($line); Write-Info $line }
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
        if ($RequireReal) {
            if ($shimOutput.Count -gt 0) {
                foreach ($line in ($shimOutput | Select-Object -Last 60)) { Write-Host $line }
            }
            Remove-StagedBinary
            throw "ovpn_shim build failed for '$Arch'; refusing to produce a mock-only release sidecar."
        }
        Write-Warning "ovpn_shim build failed; falling back to mock-only sidecar (no -tags ovpn3). See tools/wormhole-ovpnproxy/README.md for the full toolchain requirements."
        # Surface the real cmake/compiler/linker error even under -Quiet so the failure is
        # diagnosable straight from CI logs instead of silently shipping the stub.
        if ($shimOutput.Count -gt 0) {
            Write-Warning "---- last 60 lines of ovpn_shim build output ----"
            foreach ($line in ($shimOutput | Select-Object -Last 60)) { Write-Host $line }
            Write-Warning "---- end ovpn_shim build output ----"
        }
        $buildTag = ""
    }
}

# Go build.
$env:GOOS = "windows"
$env:GOARCH = if ($Arch -eq "arm64") { "arm64" } else { "amd64" }
if ($shimBuilt) {
    $env:CGO_ENABLED = "1"
    $env:CC = $cCompiler.Source
    $env:CXX = $cppCompiler.Source
    $env:CGO_CFLAGS = "-I$shimDir"
    # `go build` keys its cgo link cache on the Go sources + the `#cgo` directive strings, NOT on the
    # *content* of the external static archive (libovpn_shim.a) named via `-lovpn_shim`. So when only
    # the shim / vendored OpenVPN3 / mbedTLS changed (a fresh .a, unchanged .go files), go build would
    # silently relink the PREVIOUS binary. Stamp the archive's hash into a generated (gitignored) Go
    # source so a changed archive changes a source file, which busts the link cache — targeted, unlike
    # `go clean -cache` which would wipe the whole cache and slow every unrelated build. Only rewrite
    # when the hash changed so untouched rebuilds stay fully cached.
    $shimLib = Join-Path $shimBuild "libovpn_shim.a"
    $genFile = Join-Path $sourceDir "shim_buildinfo.go"
    if (Test-Path $shimLib) {
        $shimHash = Get-FileSha256 $shimLib
        $genContent = "// Code generated by Fetch-OvpnProxy.ps1. DO NOT EDIT.`n" +
                      "// Busts go build's cgo link cache when libovpn_shim.a changes (see ovpn_cgo.go).`n`n" +
                      "package main`n`nconst shimArchiveHash = `"$shimHash`"`n"
        $existing = if (Test-Path $genFile) { Get-Content -Raw $genFile } else { "" }
        if ($existing -ne $genContent) {
            Set-Content -Path $genFile -Value $genContent -NoNewline -Encoding ascii
            Write-Info "Stamped shim_buildinfo.go (libovpn_shim.a $($shimHash.Substring(0,12))...)"
        }
    }
    # NB: the full link line (libovpn_shim + mbedTLS + lz4 + the Win32 system libs that
    # OpenVPN3 needs) lives in ovpn_cgo.go's `#cgo windows LDFLAGS` directives so it stays
    # version-controlled with the binding and platform-scoped. Don't set CGO_LDFLAGS here
    # — it would only duplicate -lovpn_shim and obscure where the real link spec lives.
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
    # go.sum is committed for this tool so plain `go build` works without a preflight.
    # Regenerate it via `GOOS=windows go mod tidy` when bumping deps -- the windows-only
    # indirect `golang.zx2c4.com/wintun` is otherwise stripped on Linux/macOS tidy passes.
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
    Assert-RequiredRealBinary
    $tagSuffix = if ($buildTag) { " (built, -tags $buildTag)" } else { " (built, mock-only)" }
    Write-Info "OK    wormhole-ovpnproxy.exe ($Arch)$tagSuffix"
    return
}

Remove-StagedBinary
if ($RequireReal) {
    throw "wormhole-ovpnproxy.exe build failed for '$Arch' ($failureDetail); refusing to continue without the required real OpenVPN3 sidecar."
}
Write-Warning "wormhole-ovpnproxy.exe build failed ($failureDetail). Continuing without the sidecar; OpenVPN tunnels will surface a runtime error if used."
