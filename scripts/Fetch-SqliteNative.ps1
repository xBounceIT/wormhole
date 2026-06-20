param(
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [switch]$Force,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$cacheDir = Join-Path $repoRoot "obj\sqlite-native\cache"
$stagingDir = Join-Path $repoRoot "obj\sqlite-native\$Arch"
$binaryPath = Join-Path $stagingDir "e_sqlite3.dll"

# SQLite 3.53.2 fixes CVE-2026-11824 in FTS5. SQLite publishes SHA3-256 values,
# but this script runs under Windows PowerShell where SHA3 is not consistently
# available, so the official zip payloads are pinned here with SHA256.
$artifacts = @{
    "x64" = [pscustomobject]@{
        Url = "https://sqlite.org/2026/sqlite-dll-win-x64-3530200.zip"
        ZipName = "sqlite-dll-win-x64-3530200.zip"
        ZipSha256 = "5d40de68da94cee0fbb01a7caae96c9226872549fb007e826f63cd7bb464b463"
        DllSha256 = "73b045c910fc19a069bae2e2c7ebb5ea66fe6c85f166535a6e07e09155cd9e6d"
    }
    "arm64" = [pscustomobject]@{
        Url = "https://sqlite.org/2026/sqlite-dll-win-arm64-3530200.zip"
        ZipName = "sqlite-dll-win-arm64-3530200.zip"
        ZipSha256 = "bf295730a2ce364a99a21425ede21c1927d8630fa59133fb47485e229f8b00d8"
        DllSha256 = "797b7aaaa7d3399c1fd92ba995ab935a0f9aaf35b7a65d0f6ba64ede6a815e81"
    }
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

function Test-Hash($path, $expected) {
    (Test-Path $path) -and ((Get-FileSha256 $path) -eq $expected)
}

$artifact = $artifacts[$Arch]
if (-not $artifact) {
    throw "Unsupported SQLite native architecture '$Arch'."
}

if (-not (Test-Path $cacheDir)) {
    New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
}

if (-not (Test-Path $stagingDir)) {
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
}

if ((Test-Hash $binaryPath $artifact.DllSha256) -and -not $Force) {
    Write-Info "OK    e_sqlite3.dll ($Arch)"
    return
}

$zipPath = Join-Path $cacheDir $artifact.ZipName
if (-not (Test-Hash $zipPath $artifact.ZipSha256) -or $Force) {
    Write-Info "FETCH $($artifact.Url) -> $($artifact.ZipName)"
    Invoke-WebRequest -Uri $artifact.Url -OutFile $zipPath -UseBasicParsing

    $zipHash = Get-FileSha256 $zipPath
    if ($zipHash -ne $artifact.ZipSha256) {
        Remove-Item -LiteralPath $zipPath -Force
        throw "SHA256 mismatch for $($artifact.ZipName). Expected $($artifact.ZipSha256), got $zipHash."
    }
}

Write-Info "EXTRACT $($artifact.ZipName) -> e_sqlite3.dll ($Arch)"
Expand-Archive -Path $zipPath -DestinationPath $stagingDir -Force

$sqliteDllPath = Join-Path $stagingDir "sqlite3.dll"
if (-not (Test-Path $sqliteDllPath)) {
    throw "SQLite zip did not contain sqlite3.dll."
}

Copy-Item -LiteralPath $sqliteDllPath -Destination $binaryPath -Force

$dllHash = Get-FileSha256 $binaryPath
if ($dllHash -ne $artifact.DllSha256) {
    Remove-Item -LiteralPath $binaryPath -Force
    throw "SHA256 mismatch for e_sqlite3.dll ($Arch). Expected $($artifact.DllSha256), got $dllHash."
}

Write-Info "OK    e_sqlite3.dll ($Arch) (SQLite 3.53.2)"
