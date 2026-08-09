param(
    [ValidateSet('x64', 'arm64')]
    [string]$Arch = 'x64',
    [switch]$RequireRealOvpn
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$destination = Join-Path $repoRoot 'dist-electron'
New-Item -ItemType Directory -Path $destination -Force | Out-Null

& (Join-Path $scriptRoot 'Fetch-WgProxy.ps1') -Arch $Arch -Quiet
& (Join-Path $scriptRoot 'Fetch-FortiProxy.ps1') -Arch $Arch -Quiet
& (Join-Path $scriptRoot 'Fetch-CiscoProxy.ps1') -Arch $Arch -Quiet
if ($RequireRealOvpn) {
    & (Join-Path $scriptRoot 'Fetch-OvpnProxy.ps1') -Arch $Arch -Quiet -RequireReal
} else {
    & (Join-Path $scriptRoot 'Fetch-OvpnProxy.ps1') -Arch $Arch -Quiet
}

$sources = @(
    @{ Directory = "obj\wgproxy\$Arch"; Name = 'wormhole-wgproxy.exe' },
    @{ Directory = "obj\fortiproxy\$Arch"; Name = 'wormhole-fortiproxy.exe' },
    @{ Directory = "obj\ovpnproxy\$Arch"; Name = 'wormhole-ovpnproxy.exe' },
    @{ Directory = "obj\ciscoproxy\$Arch"; Name = 'wormhole-ciscoproxy.exe' }
)

function Test-IsMockOnlyOvpnProxy([string]$Path) {
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $buffer = New-Object byte[] 65536
            $read = 0
            $total = 0
            $text = ''
            while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0 -and $total -lt 4MB) {
                $text += [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                $total += $read
            }
            return $text.IndexOf('binding not linked', [StringComparison]::Ordinal) -ge 0
        }
        finally {
            $stream.Dispose()
        }
    }
    catch {
        return $false
    }
}

foreach ($source in $sources) {
    $path = Join-Path $repoRoot (Join-Path $source.Directory $source.Name)
    if (Test-Path -LiteralPath $path) {
        $target = Join-Path $destination $source.Name
        Copy-Item -LiteralPath $path -Destination $target -Force
        if ($source.Name -eq 'wormhole-ovpnproxy.exe' -and (Test-IsMockOnlyOvpnProxy $target)) {
            if ($RequireRealOvpn) {
                Remove-Item -LiteralPath $target -Force
                throw "$($source.Name) is the development-only mock stub; a real OpenVPN3 sidecar was required."
            }
            Write-Warning "$($source.Name) is the development-only mock stub (no OpenVPN3 engine). OpenVPN, WatchGuard, and Stormshield tunnels will fail at runtime. Build the real sidecar with scripts\Fetch-OvpnProxy.ps1 -Arch $Arch -RequireReal."
        } else {
            Write-Host "OK    $($source.Name)"
        }
    } else {
        Write-Warning "$($source.Name) was not built; the corresponding VPN provider will report an actionable runtime error."
    }
}
