using Wormhole.Models;

namespace Wormhole.Services.Sftp;

/// <summary>
/// Pure drop-target resolution for the file transfer panes. Kept separate from
/// <c>FilePaneControl</c> so destination rules can be unit-tested without WinUI.
/// </summary>
public static class TransferDropTarget
{
    public static string ResolveDestinationDirectory(string currentPath, string? hoveredFullPath, bool hoveredIsDirectory) =>
        hoveredIsDirectory && !string.IsNullOrEmpty(hoveredFullPath) ? hoveredFullPath : currentPath;

    /// <summary>
    /// True when <paramref name="destination"/> is a local folder being dropped into
    /// itself or one of its descendants. Only meaningful for local destination panes.
    /// </summary>
    public static bool IsInvalidLocalDropDestination(string destination, IReadOnlyList<TransferItem> items)
    {
        string destFull;
        try { destFull = NormalizeLocalDirectory(destination); }
        catch { return false; }

        foreach (var item in items)
        {
            if (RemotePath.IsAbsolute(item.SourcePath)) continue;

            string targetPath;
            try { targetPath = Path.GetFullPath(Path.Combine(destFull, item.Name)); }
            catch { continue; }

            string sourcePath;
            try { sourcePath = Path.GetFullPath(item.SourcePath); }
            catch { continue; }

            if (string.Equals(sourcePath, targetPath, StringComparison.OrdinalIgnoreCase)) return true;

            if (!item.IsDirectory) continue;

            var sourceDir = NormalizeLocalDirectory(item.SourcePath);
            if (IsDescendantLocalDirectory(sourceDir, targetPath)) return true;
            if (IsDescendantLocalDirectory(sourceDir, destFull)) return true;
        }

        return false;
    }

    private static string NormalizeLocalDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static bool IsDescendantLocalDirectory(string ancestor, string candidate)
    {
        var prefix = NormalizeLocalDirectory(ancestor) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(candidate).StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }
}
