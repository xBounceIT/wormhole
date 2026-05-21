namespace Wormhole.Models;

public sealed record UpdateCheckResult(
    Version CurrentVersion,
    Version? LatestVersion,
    bool IsUpdateAvailable,
    bool CheckFailed,
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
        new(currentVersion, latest, false, false, null, null, null, null, null, null, null, null);

    public static UpdateCheckResult Failed(Version currentVersion) =>
        new(currentVersion, null, false, true, null, null, null, null, null, null, null, null);
}
