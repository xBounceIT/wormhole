namespace Wormhole.ViewModels.Sessions.Transfer;

/// <summary>
/// Builds the WinSCP-style preset folder list for the local file-transfer pane:
/// well-known user folders, then ready drive roots.
/// </summary>
public static class LocalQuickPaths
{
    /// <summary>Minimal drive descriptor so unit tests can inject fake roots.</summary>
    public readonly record struct DriveRoot(string RootPath, bool IsReady);

    /// <summary>
    /// Resolve special folders / drives / existence via the optional hooks so unit
    /// tests can inject a fake filesystem without touching the real profile.
    /// </summary>
    public static IReadOnlyList<QuickPathItem> Build(
        Func<Environment.SpecialFolder, string>? getFolderPath = null,
        Func<IReadOnlyList<DriveRoot>>? getDrives = null,
        Func<string, bool>? directoryExists = null)
    {
        getFolderPath ??= Environment.GetFolderPath;
        getDrives ??= EnumerateLocalDriveRoots;
        directoryExists ??= Directory.Exists;

        var driveRoots = getDrives();
        var probeSafeDriveLetters = BuildProbeSafeDriveLetters(driveRoots);

        var folders = new List<QuickPathItem>();
        var drives = new List<QuickPathItem>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        bool TryAdd(List<QuickPathItem> target, string? label, string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;

            string full;
            try
            {
                full = Path.GetFullPath(path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // Bad SpecialFolder / injected path must not crash dialog construction.
                return false;
            }

            if (!seen.Add(full)) return false;
            // Redirected known folders can point at UNC paths or mapped network drives.
            // A synchronous Directory.Exists on an offline target can block the UI thread
            // for the network timeout while the File Transfer dialog is opening.
            if (ShouldProbeExists(full, probeSafeDriveLetters) && !directoryExists(full)) return false;
            // Empty label → show the resolved path (drive roots: C:\).
            target.Add(new QuickPathItem(string.IsNullOrEmpty(label) ? full : label, full));
            return true;
        }

        // WinSCP-ish order: common profile folders first, then Home, then drives.
        TryAdd(folders, "Desktop", getFolderPath(Environment.SpecialFolder.Desktop));
        TryAdd(folders, "Documents", getFolderPath(Environment.SpecialFolder.MyDocuments));

        // Downloads is not an Environment.SpecialFolder on .NET; use the conventional
        // profile subfolder and only surface it when it actually exists.
        var profile = getFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(profile))
        {
            TryAdd(folders, "Downloads", Path.Combine(profile, "Downloads"));
        }

        TryAdd(folders, "Pictures", getFolderPath(Environment.SpecialFolder.MyPictures));
        TryAdd(folders, "Music", getFolderPath(Environment.SpecialFolder.MyMusic));
        TryAdd(folders, "Videos", getFolderPath(Environment.SpecialFolder.MyVideos));
        TryAdd(folders, "Home", profile);

        foreach (var drive in driveRoots)
        {
            if (!drive.IsReady) continue;
            // Label as the resolved root (C:\, D:\) — matches WinSCP's drive list.
            TryAdd(drives, label: null, drive.RootPath);
        }

        if (folders.Count > 0 && drives.Count > 0)
        {
            folders.Add(QuickPathItem.Separator);
        }

        folders.AddRange(drives);
        return folders;
    }

    internal static bool ShouldProbeExists(string full, HashSet<char> probeSafeDriveLetters)
    {
        if (IsUncPath(full)) return false;
        if (full.Length >= 2 && full[1] == ':' && char.IsLetter(full[0]))
        {
            return probeSafeDriveLetters.Contains(char.ToUpperInvariant(full[0]));
        }

        return true;
    }

    internal static HashSet<char> BuildProbeSafeDriveLetters(IReadOnlyList<DriveRoot> drives)
    {
        var letters = new HashSet<char>();
        foreach (var drive in drives)
        {
            if (!drive.IsReady) continue;
            if (drive.RootPath.Length >= 2 && drive.RootPath[1] == ':' && char.IsLetter(drive.RootPath[0]))
            {
                letters.Add(char.ToUpperInvariant(drive.RootPath[0]));
            }
        }

        return letters;
    }

    private static bool IsUncPath(string path) =>
        path.StartsWith(@"\\", StringComparison.Ordinal);

    /// <summary>
    /// Best-effort fixed/removable drive roots for the quick-path menu. Bad volumes
    /// must not prevent the File Transfer dialog from opening.
    /// </summary>
    internal static IReadOnlyList<DriveRoot> EnumerateLocalDriveRoots()
    {
        try
        {
            var roots = new List<DriveRoot>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.DriveType is not (DriveType.Fixed or DriveType.Removable)) continue;
                    roots.Add(new DriveRoot(drive.RootDirectory.FullName, drive.IsReady));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Skip volumes Windows cannot describe (bad USB / card reader).
                }
            }

            return roots;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Array.Empty<DriveRoot>();
        }
    }
}
