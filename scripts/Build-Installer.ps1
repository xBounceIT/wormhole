param(
    [ValidateSet("x64", "arm64")]
    [string]$Architecture = "x64",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$DotNetPath = "C:\Program Files\dotnet\dotnet.exe",
    [string]$IsccPath  = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptRoot
$projectPath        = Join-Path $repoRoot "Wormhole.csproj"
$installerScript    = Join-Path $repoRoot "installer\Wormhole.iss"
$publishDir         = Join-Path $repoRoot "artifacts\publish\win-$Architecture"
$installerOutputDir = Join-Path $repoRoot "installer\output"

if ($DryRun) {
    Write-Host "DRY RUN: would publish $projectPath ($Configuration / $Architecture) to $publishDir"
    Write-Host "DRY RUN: would compile $installerScript with $IsccPath -> $installerOutputDir"
    Write-Host "DRY RUN: dotnet path = $DotNetPath"
    return
}

if (-not (Test-Path $DotNetPath)) {
    throw "dotnet executable not found at '$DotNetPath'."
}
if (-not (Test-Path $IsccPath)) {
    throw "Inno Setup compiler not found at '$IsccPath'. Install Inno Setup 6 and rerun."
}

Write-Host "Publishing $projectPath -> $publishDir"
# Self-contained so the installed app bundles every runtime it needs — including the ASP.NET Core
# runtime that the in-app MCP server (Kestrel) requires. A framework-dependent publish would make
# the app fail to launch on machines without the ASP.NET Core runtime installed, even with the MCP
# server disabled, because Microsoft.AspNetCore.App is resolved by hostfxr at process startup.
& $DotNetPath publish $projectPath `
    -c $Configuration `
    -r "win-$Architecture" `
    -p:Platform=$Architecture `
    --self-contained true `
    -o $publishDir

Write-Host "Compiling installer $installerScript"
New-Item -ItemType Directory -Force -Path $installerOutputDir | Out-Null
& $IsccPath `
    "/DAppArchitecture=$Architecture" `
    "/DPublishDir=$publishDir" `
    "/O$installerOutputDir" `
    $installerScript

Write-Host "Installer written to $installerOutputDir"
