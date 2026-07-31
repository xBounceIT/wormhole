param(
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",
    [string]$CargoPath = "",
    [string[]]$Packages = @("wormhole-app", "surface-lab"),
    [switch]$SkipSidecars,
    [switch]$DryRun,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Stages release Rust binaries for a future parallel Inno channel.
# Does NOT touch scripts/Build-Installer.ps1 or installer/Wormhole.iss (WinUI remains shipping).
# See docs/migration/18-rust-installer.md and docs/migration/15-cutover.md.

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$rustRoot   = Join-Path $repoRoot "rust"

# Allowlist only - arbitrary -p / path-like package names can escape the stage dir.
$AllowedPackages = @("wormhole-app", "surface-lab")

$targetTriple = switch ($Architecture) {
    "x64"   { "x86_64-pc-windows-msvc" }
    "arm64" { "aarch64-pc-windows-msvc" }
}

# Same sidecar names the .NET csproj copies beside Wormhole.exe (and wormhole-tunnels locate).
$sidecarSpecs = @(
    @{ Name = "wormhole-wgproxy.exe";    ObjDir = "wgproxy";    ToolsDir = "wormhole-wgproxy" }
    @{ Name = "wormhole-ovpnproxy.exe";  ObjDir = "ovpnproxy";  ToolsDir = "wormhole-ovpnproxy" }
    @{ Name = "wormhole-fortiproxy.exe"; ObjDir = "fortiproxy"; ToolsDir = "wormhole-fortiproxy" }
    @{ Name = "wormhole-ciscoproxy.exe"; ObjDir = "ciscoproxy"; ToolsDir = "wormhole-ciscoproxy" }
)

function Test-PathUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Candidate
    )

    $fullRoot = [System.IO.Path]::GetFullPath($Root)
    $fullCandidate = [System.IO.Path]::GetFullPath($Candidate)
    if ($fullCandidate -eq $fullRoot) {
        return $true
    }

    $prefix = if ($fullRoot.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $fullRoot
    }
    else {
        $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    }

    return $fullCandidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-SafePackageName {
    param([Parameter(Mandatory = $true)][string]$Name)

    $trimmed = $Name.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw "Package name must not be empty."
    }
    if ($trimmed -notin $AllowedPackages) {
        throw "Package '$trimmed' is not allowlisted. Allowed: $($AllowedPackages -join ', ')."
    }
    if ($trimmed -match '[\\/]' -or $trimmed.Contains("..")) {
        throw "Package name must be a single path segment without '..': '$trimmed'."
    }
    return $trimmed
}

function Assert-CargoExecutablePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $trimmed = $Path.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw "CargoPath must not be empty."
    }

    $leaf = Split-Path -Leaf $trimmed
    if ($leaf -ine "cargo.exe" -and $leaf -ine "cargo") {
        throw "CargoPath must point to cargo(.exe); got leaf '$leaf'."
    }

    return $trimmed
}

function Resolve-CargoPath {
    param([string]$Explicit)

    if (-not [string]::IsNullOrWhiteSpace($Explicit)) {
        return Assert-CargoExecutablePath -Path $Explicit
    }

    $fromPath = Get-Command cargo -ErrorAction SilentlyContinue
    if ($null -ne $fromPath) {
        return Assert-CargoExecutablePath -Path $fromPath.Source
    }

    $userCargo = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path -LiteralPath $userCargo) {
        return Assert-CargoExecutablePath -Path $userCargo
    }

    throw "cargo not found. Prefix PATH with `%USERPROFILE%\.cargo\bin` or pass -CargoPath."
}

function Get-StagedFilePath {
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    $leaf = Split-Path -Leaf $FileName
    if ($leaf -ne $FileName -or $FileName -match '[\\/]' -or $FileName.Contains("..")) {
        throw "Staged file name must be a single leaf segment: '$FileName'."
    }

    $dest = Join-Path $StageRoot $leaf
    if (-not (Test-PathUnderRoot -Root $StageRoot -Candidate $dest)) {
        throw "Refusing to stage outside rust publish dir ('$StageRoot'): '$dest'."
    }

    return $dest
}

function Find-SidecarSource {
    param(
        [hashtable]$Spec,
        [string]$Arch
    )

    $candidates = @(
        (Join-Path $repoRoot "obj\$($Spec.ObjDir)\$Arch\$($Spec.Name)")
        (Join-Path $repoRoot "tools\$($Spec.ToolsDir)\$($Spec.Name)")
        (Join-Path $repoRoot "bin\$($Spec.Name)")
    )

    foreach ($path in $candidates) {
        # Leaf-only copies - never recurse into tools/obj trees (secrets / configs).
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $leaf = Split-Path -Leaf $path
            if ($leaf -ieq $Spec.Name) {
                return $path
            }
        }
    }

    return $null
}

function Invoke-BuildRustArtifactsSelfTest {
    $failures = New-Object System.Collections.Generic.List[string]

    foreach ($ok in $AllowedPackages) {
        try {
            $null = Assert-SafePackageName -Name $ok
        }
        catch {
            $failures.Add("allowlist accept failed for '$ok': $_")
        }
    }

    foreach ($bad in @("..\win-x64\Wormhole", "evil;calc", "wormhole-app --manifest-path C:\evil", "not-a-crate", "")) {
        try {
            $null = Assert-SafePackageName -Name $bad
            $failures.Add("expected reject for package '$bad'")
        }
        catch {
            # expected
        }
    }

    try {
        $null = Assert-CargoExecutablePath -Path "C:\Windows\System32\notepad.exe"
        $failures.Add("expected CargoPath reject for notepad.exe")
    }
    catch {
        # expected
    }

    try {
        $null = Assert-CargoExecutablePath -Path (Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe")
    }
    catch {
        $failures.Add("cargo.exe path should be accepted: $_")
    }

    $probeStage = Join-Path $repoRoot "artifacts\publish\rust-win-x64"
    try {
        $null = Get-StagedFilePath -StageRoot $probeStage -FileName "..\win-x64\Wormhole.exe"
        $failures.Add("expected stage path reject for ..\win-x64\Wormhole.exe")
    }
    catch {
        # expected
    }

    $safeDest = Get-StagedFilePath -StageRoot $probeStage -FileName "wormhole-app.exe"
    if (-not (Test-PathUnderRoot -Root $probeStage -Candidate $safeDest)) {
        $failures.Add("safe dest not under stage root")
    }

    $winUiRoot = Join-Path $repoRoot "artifacts\publish\win-x64"
    if (Test-PathUnderRoot -Root $probeStage -Candidate (Join-Path $winUiRoot "Wormhole.exe")) {
        $failures.Add("WinUI publish path must not test as under rust stage root")
    }

    if ($failures.Count -gt 0) {
        throw ("SelfTest failed:`n - " + ($failures -join "`n - "))
    }

    Write-Host "SelfTest OK: package allowlist, CargoPath leaf, stage containment."
}

if ($SelfTest) {
    Invoke-BuildRustArtifactsSelfTest
    exit 0
}

$resolvedPackages = @()
foreach ($pkg in $Packages) {
    if ([string]::IsNullOrWhiteSpace($pkg)) { continue }
    $resolvedPackages += Assert-SafePackageName -Name $pkg
}
if ($resolvedPackages.Count -eq 0) {
    throw "At least one package is required (-Packages)."
}

# Stage root is fixed under artifacts/publish/rust-win-{arch} (release channel only).
$stageDir = [System.IO.Path]::GetFullPath((Join-Path $repoRoot "artifacts\publish\rust-win-$Architecture"))
$winUiPublishDir = [System.IO.Path]::GetFullPath((Join-Path $repoRoot "artifacts\publish\win-$Architecture"))
if (Test-PathUnderRoot -Root $stageDir -Candidate $winUiPublishDir) {
    throw "Internal error: rust stage dir must not contain WinUI publish dir."
}

if (-not (Test-Path -LiteralPath $rustRoot)) {
    throw "Rust workspace not found at '$rustRoot'."
}

$packageArgs = @()
foreach ($pkg in $resolvedPackages) {
    $packageArgs += @("-p", $pkg)
}

$cargoArgs = @("build", "--release", "--target", $targetTriple) + $packageArgs
$releaseDir = Join-Path $rustRoot "target\$targetTriple\release"

if ($DryRun) {
    # DryRun must not write and must not require cargo on PATH (CI / agents without Rust).
    $cargoDisplay = $null
    try {
        if ([string]::IsNullOrWhiteSpace($CargoPath)) {
            $cargoDisplay = Resolve-CargoPath -Explicit ""
        }
        else {
            $cargoDisplay = Resolve-CargoPath -Explicit $CargoPath
        }
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($CargoPath)) {
            # Explicit -CargoPath that fails leaf validation is still a caller error.
            throw
        }
        $cargoDisplay = "(cargo not found - DryRun skips invoke)"
    }

    Write-Host "DRY RUN: architecture = $Architecture ($targetTriple)"
    Write-Host "DRY RUN: cargo path = $cargoDisplay"
    Write-Host "DRY RUN: would run: cargo $($cargoArgs -join ' ') (cwd = $rustRoot)"
    Write-Host "DRY RUN: would stage binaries from $releaseDir -> $stageDir"
    foreach ($pkg in $resolvedPackages) {
        $exeName = "$pkg.exe"
        $dest = Get-StagedFilePath -StageRoot $stageDir -FileName $exeName
        Write-Host "DRY RUN:   expect $exeName -> $dest"
    }
    if ($SkipSidecars) {
        Write-Host "DRY RUN: sidecars skipped (-SkipSidecars)"
    }
    else {
        Write-Host "DRY RUN: would stage sidecars if present (leaf copy only; no recursion):"
        foreach ($spec in $sidecarSpecs) {
            $src = Find-SidecarSource -Spec $spec -Arch $Architecture
            $dest = Get-StagedFilePath -StageRoot $stageDir -FileName $spec.Name
            if ($null -ne $src) {
                Write-Host "DRY RUN:   FOUND $($spec.Name) <- $src -> $dest"
            }
            else {
                Write-Host "DRY RUN:   missing $($spec.Name) (non-fatal; runtime locate / Fetch-*.ps1)"
            }
        }
    }
    Write-Host "DRY RUN: WinUI publish dir untouched ($winUiPublishDir)"
    Write-Host "DRY RUN: WinUI installer untouched (scripts/Build-Installer.ps1, installer/Wormhole.iss)"
    exit 0
}

if ([string]::IsNullOrWhiteSpace($CargoPath)) {
    $CargoPath = Resolve-CargoPath -Explicit ""
}
else {
    $CargoPath = Resolve-CargoPath -Explicit $CargoPath
}

if (-not (Test-Path -LiteralPath $CargoPath)) {
    throw "cargo executable not found at '$CargoPath'."
}

Write-Host "Building Rust packages ($Architecture / release) -> $releaseDir"
Push-Location $rustRoot
try {
    & $CargoPath @cargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

Write-Host "Staging artifacts -> $stageDir"
# Create only the rust-win-* stage dir - never Remove-Item WinUI artifacts/publish/win-*.
New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

foreach ($pkg in $resolvedPackages) {
    $exeName = "$pkg.exe"
    $src = Join-Path $releaseDir $exeName
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
        throw "Expected binary missing after build: '$src'."
    }
    $dest = Get-StagedFilePath -StageRoot $stageDir -FileName $exeName
    Copy-Item -LiteralPath $src -Destination $dest -Force
    Write-Host "  staged $exeName"
}

if (-not $SkipSidecars) {
    foreach ($spec in $sidecarSpecs) {
        $src = Find-SidecarSource -Spec $spec -Arch $Architecture
        if ($null -eq $src) {
            Write-Host "  sidecar missing (skip): $($spec.Name)"
            continue
        }
        $dest = Get-StagedFilePath -StageRoot $stageDir -FileName $spec.Name
        Copy-Item -LiteralPath $src -Destination $dest -Force
        Write-Host "  staged sidecar $($spec.Name) <- $src"
    }
}

Write-Host "Rust artifacts ready at $stageDir"
Write-Host "Next (optional): compile a separate Inno script under installer/rust/ - see docs/migration/18-rust-installer.md"
exit 0
