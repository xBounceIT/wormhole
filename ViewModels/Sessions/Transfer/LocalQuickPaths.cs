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
        // Skip Network/CDRom: DriveInfo.IsReady can stall for seconds on flaky shares
        // or empty optical drives, and that would hitch File Transfer dialog open.
        // Fixed + Removable cover the WinSCP-style local roots users jump to; existence
        // is still gated below via directoryExists.
        getDrives ??= () => DriveInfo.GetDrives()
            .Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable)
            .Select(d => new DriveRoot(d.RootDirectory.FullName, IsReady: true))
            .ToArray();
        directoryExists ??= Directory.Exists;

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

            if (!directoryExists(full) || !seen.Add(full)) return false;
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

        foreach (var drive in getDrives())
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
}
