using System.Text.Json;

namespace Wormhole.Services.BitwardenBrowser;

internal sealed record BitwardenBrowserExtensionManifest(string Name, string? Version, string? DefaultPopup, string? IconPath)
{
    public static BitwardenBrowserExtensionManifest Read(string extensionFolderPath)
    {
        var manifestPath = Path.Combine(extensionFolderPath, "manifest.json");
        if (!File.Exists(manifestPath))
            throw new BitwardenBrowserExtensionException("The selected Bitwarden extension folder does not contain manifest.json.");

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var root = document.RootElement;
            var name = TryGetString(root, "name");
            if (string.IsNullOrWhiteSpace(name))
                throw new BitwardenBrowserExtensionException("The extension manifest does not define a name.");

            return new BitwardenBrowserExtensionManifest(
                name,
                TryGetString(root, "version"),
                GetDefaultPopup(root),
                ResolveManifestPath(extensionFolderPath, GetDefaultIcon(root)));
        }
        catch (JsonException ex)
        {
            throw new BitwardenBrowserExtensionException("The extension manifest is not valid JSON.", ex);
        }
    }

    private static string? GetDefaultPopup(JsonElement root) =>
        TryGetActionPopup(root, "action") ?? TryGetActionPopup(root, "browser_action");

    private static string? TryGetActionPopup(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var action) || action.ValueKind != JsonValueKind.Object)
            return null;
        return TryGetString(action, "default_popup");
    }

    private static string? GetDefaultIcon(JsonElement root) =>
        TryGetActionIcon(root, "action") ??
        TryGetActionIcon(root, "browser_action") ??
        TryGetIconPath(root, "icons");

    private static string? TryGetActionIcon(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var action) || action.ValueKind != JsonValueKind.Object)
            return null;
        return TryGetIconPath(action, "default_icon");
    }

    private static string? TryGetIconPath(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var icon)) return null;
        if (icon.ValueKind == JsonValueKind.String) return icon.GetString();
        if (icon.ValueKind != JsonValueKind.Object) return null;

        var candidates = new List<(int Size, string Path, int Order)>();
        var order = 0;
        foreach (var property in icon.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String) continue;
            var path = property.Value.GetString();
            if (string.IsNullOrWhiteSpace(path)) continue;
            var size = int.TryParse(property.Name, out var parsed) ? parsed : 0;
            candidates.Add((size, path, order++));
        }

        return candidates
            .OrderBy(candidate => candidate.Size >= 32 ? 0 : 1)
            .ThenBy(candidate => Math.Abs(candidate.Size - 32))
            .ThenBy(candidate => candidate.Order)
            .Select(candidate => candidate.Path)
            .FirstOrDefault();
    }

    private static string? ResolveManifestPath(string extensionFolderPath, string? relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath)) return null;
        var normalized = relativePath.Trim().TrimStart('/', '\\')
            .Replace('/', Path.DirectorySeparatorChar)
            .Replace('\\', Path.DirectorySeparatorChar);
        return string.IsNullOrWhiteSpace(normalized)
            ? null
            : Path.GetFullPath(Path.Combine(extensionFolderPath, normalized));
    }

    private static string? TryGetString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
