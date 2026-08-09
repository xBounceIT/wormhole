param(
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",
    [string]$IsccPath = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    [string]$AppVersion = "",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$packageJson        = Join-Path $repoRoot "package.json"
$installerScript    = Join-Path $repoRoot "installer\Wormhole.Electron.iss"
$rendererDir        = Join-Path $repoRoot "dist"
$electronDir        = Join-Path $repoRoot "dist-electron"
$electronRuntimeDir = Join-Path $repoRoot "node_modules\electron\dist"
$runtimeDependencyManifest = Join-Path $repoRoot "installer\electron-runtime-dependencies.json"
$assetsDir          = Join-Path $repoRoot "Assets"
$stagingDir         = Join-Path $repoRoot "artifacts\electron-app\$Architecture\Wormhole"
$installerOutputDir = Join-Path $repoRoot "installer\output"

function Get-PackageJsonVersion {
    param([string]$Path)

    $package = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace($package.version)) {
        throw "No 'version' field found in '$Path'."
    }
    return $package.version.Trim()
}

function Assert-PathExists {
    param([string]$Path, [string]$Hint)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing $Hint. Expected at: $Path"
    }
}

if ([string]::IsNullOrWhiteSpace($AppVersion)) {
    $AppVersion = Get-PackageJsonVersion -Path $packageJson
}
else {
    $AppVersion = $AppVersion.Trim()
}

if ($AppVersion -match '\s') {
    throw "AppVersion must not contain whitespace: '$AppVersion'."
}

if ($DryRun) {
    Write-Host "DRY RUN: app version = $AppVersion"
    Write-Host "DRY RUN: would stage the Electron app into $stagingDir"
    Write-Host "DRY RUN: would compile $installerScript with $IsccPath -> $installerOutputDir"
    Write-Host "DRY RUN: would pass /DMyAppVersion=$AppVersion /DAppArchitecture=$Architecture"
    return
}

Assert-PathExists (Join-Path $rendererDir "index.html") "the renderer build (run 'npm run build:renderer')"
Assert-PathExists (Join-Path $electronDir "main.js") "the Electron main build (run 'npm run build:electron')"
Assert-PathExists (Join-Path $electronDir "preload.cjs") "the Electron preload build"
Assert-PathExists (Join-Path $electronDir "wormhole-backend-$Architecture.exe") "the Go backend build for $Architecture (run 'npm run build:backend')"
Assert-PathExists (Join-Path $electronRuntimeDir "electron.exe") "the Electron runtime (run 'node node_modules/electron/install.js')"
Assert-PathExists $runtimeDependencyManifest "the Electron runtime dependency manifest"
Assert-PathExists (Join-Path $assetsDir "Wormhole.ico") "the Wormhole icon"
Assert-PathExists $IsccPath "the Inno Setup 6 compiler"

Write-Host "Staging the Electron app -> $stagingDir"
$appResourcesDir = Join-Path $stagingDir "resources\app"
if (Test-Path -LiteralPath $stagingDir) {
    Remove-Item -LiteralPath $stagingDir -Recurse -Force
}
New-Item -ItemType Directory -Path $appResourcesDir -Force | Out-Null

# Electron runtime (electron.exe renamed to Wormhole.exe + resources\default_app.asar + locales).
Copy-Item -Path (Join-Path $electronRuntimeDir "*") -Destination $stagingDir -Recurse -Force
Move-Item -LiteralPath (Join-Path $stagingDir "electron.exe") -Destination (Join-Path $stagingDir "Wormhole.exe") -Force
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    throw "Node.js is required to patch the Electron executable (resedit)."
}
& node (Join-Path $scriptRoot "patch-electron-exe.mjs") (Join-Path $stagingDir "Wormhole.exe") $AppVersion
if ($LASTEXITCODE -ne 0) { throw "Failed to patch the Electron executable with resedit." }

# The packaged application: package.json (main -> dist-electron/main.js) + renderer + Go backend
# + sidecars + helpers + runtime Node dependencies + static assets. The staged version is pinned
# to the release version so app.getVersion() matches the tag, even if the repo's package.json is behind.
Copy-Item -Path $rendererDir -Destination (Join-Path $appResourcesDir "dist") -Recurse -Force
$appElectronDir = Join-Path $appResourcesDir "dist-electron"
New-Item -ItemType Directory -Path $appElectronDir -Force | Out-Null
# Build-RdpHost.ps1 leaves a publish folder (rdp-host-<arch>) next to the single-file
# wormhole-rdp-host-<arch>.exe it copies to the dist-electron root. Only the root copy is
# needed at runtime; shipping the publish folder would duplicate ~160 MB per architecture.
foreach ($item in Get-ChildItem -LiteralPath $electronDir) {
    if ($item.PSIsContainer -and $item.Name -like 'rdp-host-*') {
        Write-Host "SKIP  $($item.Name) (redundant publish folder)"
        continue
    }
    Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $appElectronDir $item.Name) -Recurse -Force
}
Copy-Item -Path $assetsDir -Destination (Join-Path $appResourcesDir "Assets") -Recurse -Force
& node `
    (Join-Path $scriptRoot "stage-electron-runtime-dependencies.mjs") `
    $runtimeDependencyManifest `
    (Join-Path $repoRoot "node_modules") `
    (Join-Path $appResourcesDir "node_modules")
if ($LASTEXITCODE -ne 0) { throw "Failed to stage Electron runtime dependencies." }
$stagedPackage = [ordered]@{
    name    = "wormhole-electron"
    version = $AppVersion
    private = $true
    main    = "dist-electron/main.js"
    type    = "module"
}
$stagedPackage | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $appResourcesDir "package.json") -Encoding utf8

Write-Host "Compiling installer $installerScript"
New-Item -ItemType Directory -Force -Path $installerOutputDir | Out-Null
& $IsccPath `
    "/DAppArchitecture=$Architecture" `
    "/DPublishDir=$stagingDir" `
    "/DMyAppVersion=$AppVersion" `
    "/O$installerOutputDir" `
    $installerScript
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit $LASTEXITCODE." }

Write-Host "Installer written to $installerOutputDir"
