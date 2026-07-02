namespace Wormhole.Services.BitwardenBrowser;

internal static class BitwardenBrowserExtensionMarker
{
    private const string MarkerFileName = "wormhole-bitwarden-extension.txt";
    private const string MarkerVersion = "wormhole-bitwarden-extension-v1";

    public static string GetPath(string userDataFolder) => Path.Combine(userDataFolder, MarkerFileName);

    public static bool TryReadInstalledExtensionId(
        string markerPath,
        string expectedExtensionPath,
        out string? extensionId)
    {
        extensionId = null;
        if (!TryReadMarker(markerPath, out var installedExtensionPath, out var installedExtensionId)) return false;
        if (!PathsEqual(installedExtensionPath, expectedExtensionPath)) return false;
        extensionId = installedExtensionId;
        return true;
    }

    public static bool TryReadInstalledExtensionId(string markerPath, out string? extensionId)
    {
        extensionId = null;
        if (!TryReadMarker(markerPath, out _, out var installedExtensionId)) return false;
        extensionId = installedExtensionId;
        return true;
    }

    public static async Task WriteAsync(
        string markerPath,
        string extensionPath,
        string extensionId,
        CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(markerPath)!);
        var lines = new[]
        {
            MarkerVersion,
            NormalizePath(extensionPath),
            extensionId.Trim(),
        };
        await File.WriteAllLinesAsync(markerPath, lines, cancellationToken).ConfigureAwait(false);
    }

    private static bool TryReadMarker(
        string markerPath,
        out string installedExtensionPath,
        out string installedExtensionId)
    {
        installedExtensionPath = string.Empty;
        installedExtensionId = string.Empty;
        try
        {
            if (!File.Exists(markerPath)) return false;
            var lines = File.ReadAllLines(markerPath);
            if (lines.Length < 3 || !string.Equals(lines[0], MarkerVersion, StringComparison.Ordinal)) return false;
            if (string.IsNullOrWhiteSpace(lines[1]) || string.IsNullOrWhiteSpace(lines[2])) return false;
            installedExtensionPath = lines[1].Trim();
            installedExtensionId = lines[2].Trim();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(NormalizePath(left), NormalizePath(right), StringComparison.OrdinalIgnoreCase);

    private static string NormalizePath(string path)
    {
        var trimmed = path.Trim();
        try { return Path.GetFullPath(trimmed); }
        catch { return trimmed; }
    }
}
