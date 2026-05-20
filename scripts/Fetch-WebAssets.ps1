param(
    [switch]$Force,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$vendorRoot = Join-Path $repoRoot "Assets\web\vendor"
$integrityPath = Join-Path $repoRoot "obj\web-assets-integrity.json"

# Pinned versions. Bump deliberately. The integrity hash for each asset is captured on first
# download into the .integrity.json under the vendor folder; subsequent runs verify against it.
# Delete that file (or pass -Force) to re-pin after a version bump.
$assets = @(
    [pscustomobject]@{
        Url      = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js"
        Relative = "xterm\xterm.js"
    },
    [pscustomobject]@{
        Url      = "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css"
        Relative = "xterm\xterm.css"
    },
    [pscustomobject]@{
        Url      = "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js"
        Relative = "addon-fit\addon-fit.js"
    }
)

function Write-Info($message) {
    if (-not $Quiet) { Write-Host $message }
}

function Get-FileSha256($path) {
    return (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

if (-not (Test-Path $vendorRoot)) {
    New-Item -ItemType Directory -Path $vendorRoot -Force | Out-Null
}

$integrityDir = Split-Path -Parent $integrityPath
if (-not (Test-Path $integrityDir)) {
    New-Item -ItemType Directory -Path $integrityDir -Force | Out-Null
}

$integrity = @{}
if ((Test-Path $integrityPath) -and -not $Force) {
    $raw = Get-Content $integrityPath -Raw
    if ($raw) {
        $parsed = $raw | ConvertFrom-Json
        foreach ($prop in $parsed.PSObject.Properties) {
            $integrity[$prop.Name] = $prop.Value
        }
    }
}

$allOk = $true
foreach ($asset in $assets) {
    $destination = Join-Path $vendorRoot $asset.Relative
    $destDir = Split-Path -Parent $destination
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    $expectedHash = $null
    if ($integrity.ContainsKey($asset.Relative)) { $expectedHash = $integrity[$asset.Relative] }
    $exists = Test-Path $destination

    # Honor existing files even without an integrity manifest entry. This makes the script
    # idempotent across `dotnet clean` (which wipes obj/) and works on offline machines
    # that copied the vendor folder in by hand. Hash is captured into the manifest on
    # first sight so future runs can verify.
    if ($exists -and -not $Force) {
        $actual = Get-FileSha256 $destination
        if ($expectedHash) {
            if ($actual -eq $expectedHash) {
                Write-Info "OK    $($asset.Relative)"
                continue
            }
            Write-Info "STALE $($asset.Relative) - re-downloading"
        }
        else {
            Write-Info "ADOPT $($asset.Relative) (pinning hash from existing file)"
            $integrity[$asset.Relative] = $actual
            continue
        }
    }

    Write-Info "FETCH $($asset.Url) -> $($asset.Relative)"
    try {
        Invoke-WebRequest -Uri $asset.Url -OutFile $destination -UseBasicParsing
    }
    catch {
        Write-Error "Failed to download $($asset.Url): $_"
        $allOk = $false
        continue
    }

    $hash = Get-FileSha256 $destination
    if ($expectedHash -and $hash -ne $expectedHash) {
        Remove-Item $destination -Force
        Write-Error "SHA256 mismatch for $($asset.Relative). Expected $expectedHash, got $hash."
        $allOk = $false
        continue
    }
    $integrity[$asset.Relative] = $hash
}

if (-not $allOk) {
    throw "One or more web assets failed to download. See errors above."
}

$integrity | ConvertTo-Json | Set-Content -Path $integrityPath -Encoding UTF8
Write-Info "Integrity manifest written to $integrityPath"
