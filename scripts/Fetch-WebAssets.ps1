param(
    [switch]$Force,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
}
catch {
    Write-Warning "Could not force TLS 1.2 for web asset downloads: $_"
}
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$vendorRoot = Join-Path $repoRoot "Assets\web\vendor"
$integrityPath = Join-Path $repoRoot "obj\web-assets-integrity.json"

# Pinned versions. Bump deliberately. Hashes are fixed in this script so clean CI
# runners verify the same bytes every time instead of trusting the first CDN response.
$assets = @(
    [pscustomobject]@{
        Urls     = @(
            "https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/lib/xterm.js",
            "https://unpkg.com/@xterm/xterm@6.0.0/lib/xterm.js"
        )
        Relative = "xterm\xterm.js"
        Sha256   = "14903579ff54664cd72f8e8699e6961a6272c21863ec1c3b118cdc8af5d4a972"
    },
    [pscustomobject]@{
        Urls     = @(
            "https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/css/xterm.css",
            "https://unpkg.com/@xterm/xterm@6.0.0/css/xterm.css"
        )
        Relative = "xterm\xterm.css"
        Sha256   = "854a7c0fb70e8b1a083c16797ab827299fb18744f5ad34f227b48337e33293c6"
    },
    [pscustomobject]@{
        Urls     = @(
            "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.11.0/lib/addon-fit.js",
            "https://unpkg.com/@xterm/addon-fit@0.11.0/lib/addon-fit.js"
        )
        Relative = "addon-fit\addon-fit.js"
        Sha256   = "ba3ea256ce0620a0992a197d6c9baea64823fc93d8da07a9e366ca9943c18527"
    }
)

$downloadAttemptsPerUrl = 2
$downloadTimeoutSeconds = 20

$retiredAssets = @(
    [pscustomobject]@{
        Relative       = "addon-webgl"
        ManifestPrefix = "addon-webgl\"
    }
)

function Write-Info($message) {
    if (-not $Quiet) { Write-Host $message }
}

function Get-FileSha256($path) {
    # Compute via System.Security.Cryptography directly. Avoids depending on the
    # Get-FileHash cmdlet, which is unexpectedly missing under MSBuild's invocation
    # of powershell.exe on GitHub-hosted Windows runners.
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

function Remove-IfExists($path) {
    if (Test-Path $path) {
        Remove-Item -LiteralPath $path -Force
    }
}

function Save-VerifiedAsset($asset, $destination) {
    $destDir = Split-Path -Parent $destination
    $fileName = [System.IO.Path]::GetFileName($destination)
    $tempPath = Join-Path $destDir (".$fileName.$([System.Guid]::NewGuid().ToString("N")).tmp")
    $lastError = $null

    foreach ($url in @($asset.Urls)) {
        for ($attempt = 1; $attempt -le $downloadAttemptsPerUrl; $attempt++) {
            Remove-IfExists $tempPath
            Write-Info "FETCH $url -> $($asset.Relative) (attempt $attempt/$downloadAttemptsPerUrl)"

            try {
                Invoke-WebRequest -Uri $url -OutFile $tempPath -UseBasicParsing -TimeoutSec $downloadTimeoutSeconds
                $hash = Get-FileSha256 $tempPath
                if ($hash -ne $asset.Sha256) {
                    throw "SHA256 mismatch for $($asset.Relative). Expected $($asset.Sha256), got $hash."
                }

                Move-Item -LiteralPath $tempPath -Destination $destination -Force
                return
            }
            catch {
                $lastError = $_
                Remove-IfExists $tempPath
                Write-Info "WARN  $($asset.Relative) download failed from ${url}: $_"
                if ($attempt -lt $downloadAttemptsPerUrl) {
                    Start-Sleep -Seconds $attempt
                }
            }
        }
    }

    throw "Failed to download verified $($asset.Relative) from all configured mirrors. Last error: $lastError"
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

foreach ($retired in $retiredAssets) {
    $retiredPath = Join-Path $vendorRoot $retired.Relative
    if (Test-Path $retiredPath) {
        $resolvedVendor = [System.IO.Path]::GetFullPath($vendorRoot).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar)
        $resolvedRetired = [System.IO.Path]::GetFullPath($retiredPath)
        if (-not $resolvedRetired.StartsWith(
                $resolvedVendor + [System.IO.Path]::DirectorySeparatorChar,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove retired web asset outside vendor root: $resolvedRetired"
        }

        Remove-Item -LiteralPath $retiredPath -Recurse -Force
        Write-Info "PRUNE $($retired.Relative)"
    }

    foreach ($key in @($integrity.Keys)) {
        if ($key -eq $retired.Relative -or
            $key.StartsWith($retired.ManifestPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $integrity.Remove($key)
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

    $exists = Test-Path $destination

    if ($exists -and -not $Force) {
        $actual = Get-FileSha256 $destination
        if ($actual -eq $asset.Sha256) {
            Write-Info "OK    $($asset.Relative)"
            $integrity[$asset.Relative] = $asset.Sha256
            continue
        }
        Write-Info "STALE $($asset.Relative) - re-downloading"
    }

    try {
        Save-VerifiedAsset $asset $destination
        $integrity[$asset.Relative] = $asset.Sha256
    }
    catch {
        Write-Warning $_
        $allOk = $false
        continue
    }
}

if (-not $allOk) {
    throw "One or more web assets failed to download. See errors above."
}

$integrity | ConvertTo-Json | Set-Content -Path $integrityPath -Encoding UTF8
Write-Info "Integrity manifest written to $integrityPath"
