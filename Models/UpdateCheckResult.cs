using System;

namespace Wormhole.Models;

public sealed record UpdateCheckResult(
    Version CurrentVersion,
    Version? LatestVersion,
    bool IsUpdateAvailable,
    string? ReleaseTag,
    string? ReleaseName,
    string? ReleaseUrl,
    string? ReleaseNotes,
    string? InstallerUrl,
    string? InstallerFileName,
    long? InstallerSize,
    string? InstallerSha256)
{
    public static UpdateCheckResult NoUpdate(Version currentVersion, Version? latest = null) =>
        new(currentVersion, latest, false, null, null, null, null, null, null, null, null);
}
