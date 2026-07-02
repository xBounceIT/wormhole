using System.Net;
using System.Security.Cryptography;
using System.Text;
using Wormhole.Helpers;

namespace Wormhole.Services.BitwardenBrowser;

internal static class BitwardenBrowserWebViewProfile
{
    private static readonly string[] EphemeralWebDataRelativePaths =
    [
        Path.Combine("Default", "Network", "Cookies"),
        Path.Combine("Default", "Network", "Cookies-journal"),
        Path.Combine("Default", "Cookies"),
        Path.Combine("Default", "Cookies-journal"),
        Path.Combine("Default", "History"),
        Path.Combine("Default", "History-journal"),
        Path.Combine("Default", "Visited Links"),
        Path.Combine("Default", "Local Storage"),
        Path.Combine("Default", "Session Storage"),
        Path.Combine("Default", "Cache"),
        Path.Combine("Default", "Code Cache"),
        Path.Combine("Default", "GPUCache"),
        Path.Combine("Default", "Service Worker", "CacheStorage"),
        Path.Combine("Default", "Service Worker", "ScriptCache"),
    ];

    public static bool IsHttpsTarget(Uri navigateUri, Uri? originalUri) =>
        string.Equals((originalUri ?? navigateUri).Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    public static string BuildBrowserArguments(IPEndPoint? socks5Proxy) =>
        WebViewBrowserArguments.Build(socks5Proxy);

    public static string BuildContextFolderName(string browserArguments, bool ignoreCertificateErrors)
    {
        var material = browserArguments + "\0cert=" + (ignoreCertificateErrors ? "1" : "0");
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)))[..16].ToLowerInvariant();
        return "profile-" + hash;
    }

    public static string GetUserDataFolder(string browserArguments, bool ignoreCertificateErrors) =>
        AppPaths.GetBitwardenBrowserExtensionWebView2UserDataDirectory(
            BuildContextFolderName(browserArguments, ignoreCertificateErrors));

    public static IReadOnlyList<string> GetEphemeralWebDataPaths(string userDataFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        var paths = EphemeralWebDataRelativePaths
            .Select(relativePath => Path.Combine(userDataFolder, relativePath))
            .ToList();
        AddIndexedDbWebDataPaths(userDataFolder, paths);
        return paths;
    }

    private static void AddIndexedDbWebDataPaths(string userDataFolder, List<string> paths)
    {
        var indexedDbRoot = Path.Combine(userDataFolder, "Default", "IndexedDB");
        if (!Directory.Exists(indexedDbRoot))
        {
            paths.Add(indexedDbRoot);
            return;
        }

        foreach (var entry in Directory.EnumerateFileSystemEntries(indexedDbRoot))
        {
            var name = Path.GetFileName(entry);
            if (name.StartsWith("chrome-extension_", StringComparison.OrdinalIgnoreCase)) continue;
            paths.Add(entry);
        }
    }
}

internal sealed class BitwardenWebDataOriginLeaseRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<BitwardenWebDataOriginKey, int> _activeOrigins = new();

    public BitwardenWebDataOriginLease Register(string userDataFolder, IEnumerable<string> origins)
    {
        var lease = new BitwardenWebDataOriginLease(this, NormalizeUserDataFolder(userDataFolder));
        AddOrigins(lease, origins);
        return lease;
    }

    internal void AddOrigins(BitwardenWebDataOriginLease lease, IEnumerable<string> origins)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(origins);

        lock (_gate)
        {
            AddOriginsLocked(lease, origins);
        }
    }

    private void AddOriginsLocked(BitwardenWebDataOriginLease lease, IEnumerable<string> origins)
    {
        if (lease.IsReleased) return;

        foreach (var origin in origins)
        {
            var normalizedOrigin = NormalizeOrigin(origin);
            if (normalizedOrigin is null || !lease.Origins.Add(normalizedOrigin)) continue;

            var key = new BitwardenWebDataOriginKey(lease.UserDataFolder, normalizedOrigin);
            _activeOrigins[key] = _activeOrigins.TryGetValue(key, out var count) ? count + 1 : 1;
        }
    }

    internal IReadOnlyList<string> Release(BitwardenWebDataOriginLease lease, IEnumerable<string>? latestOrigins = null)
    {
        ArgumentNullException.ThrowIfNull(lease);

        lock (_gate)
        {
            if (lease.IsReleased) return Array.Empty<string>();
            if (latestOrigins is not null) AddOriginsLocked(lease, latestOrigins);

            lease.IsReleased = true;
            var clearableOrigins = new List<string>();
            foreach (var origin in lease.Origins)
            {
                var key = new BitwardenWebDataOriginKey(lease.UserDataFolder, origin);
                if (!_activeOrigins.TryGetValue(key, out var count)) continue;

                if (count <= 1)
                {
                    _activeOrigins.Remove(key);
                    clearableOrigins.Add(origin);
                }
                else
                {
                    _activeOrigins[key] = count - 1;
                }
            }

            lease.Origins.Clear();
            return clearableOrigins;
        }
    }

    private static string NormalizeUserDataFolder(string userDataFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        return Path.GetFullPath(userDataFolder)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .ToUpperInvariant();
    }

    private static string? NormalizeOrigin(string? origin) =>
        string.IsNullOrWhiteSpace(origin) ? null : origin.Trim().ToLowerInvariant();

    private readonly record struct BitwardenWebDataOriginKey(string UserDataFolder, string Origin);
}

internal sealed class BitwardenWebDataOriginLease
{
    internal BitwardenWebDataOriginLease(BitwardenWebDataOriginLeaseRegistry registry, string userDataFolder)
    {
        Registry = registry;
        UserDataFolder = userDataFolder;
    }

    internal BitwardenWebDataOriginLeaseRegistry Registry { get; }
    internal string UserDataFolder { get; }
    internal HashSet<string> Origins { get; } = new(StringComparer.OrdinalIgnoreCase);
    internal bool IsReleased { get; set; }

    public void AddOrigins(IEnumerable<string> origins) => Registry.AddOrigins(this, origins);

    public IReadOnlyList<string> Release(IEnumerable<string>? latestOrigins = null) =>
        Registry.Release(this, latestOrigins);
}
