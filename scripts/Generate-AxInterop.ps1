param(
    [string]$AxImpPath = "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\AxImp.exe",
    [string]$OutputDir = "Interop\Rdp\AxMSTSCLib"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Regenerates the AxMSTSCLib interop assembly + wrapper used by Interop/Rdp/RdpHostForm.cs.
# Run once per machine; the produced .dll/.cs files are committed and consumed by the project.
# Reference impl: https://github.com/castorix/WinUI3_ActiveX_MSRDP

if (-not (Test-Path $AxImpPath)) {
    throw "AxImp.exe not found at '$AxImpPath'. Install the Windows SDK 'NET Framework Tools' component and rerun, or pass -AxImpPath."
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$outDir     = Join-Path $repoRoot $OutputDir

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$mstscax = Join-Path $env:windir "System32\mstscax.dll"
if (-not (Test-Path $mstscax)) {
    throw "mstscax.dll not found at '$mstscax'."
}

Push-Location $outDir
try {
    Write-Host "Generating Ax wrappers from $mstscax"
    & $AxImpPath /source $mstscax
    Write-Host "Generated:"
    Get-ChildItem $outDir | Select-Object Name
}
finally {
    Pop-Location
}
