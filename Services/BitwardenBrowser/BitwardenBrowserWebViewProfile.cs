using System.Net;
using System.Security.Cryptography;
using System.Text;
using Wormhole.Helpers;

namespace Wormhole.Services.BitwardenBrowser;

internal static class BitwardenBrowserWebViewProfile
{
    private const string PendingWebDataOriginsFileName = "wormhole-bitwarden-web-origins.txt";
    private static readonly object PendingWebDataOriginsGate = new();

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

    public static IReadOnlyList<string> ReadPendingWebDataOrigins(string userDataFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);

        lock (PendingWebDataOriginsGate)
        {
            return ReadPendingWebDataOriginsLocked(userDataFolder).ToList();
        }
    }

    public static void AddPendingWebDataOrigins(string userDataFolder, IEnumerable<string> origins)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        ArgumentNullException.ThrowIfNull(origins);

        lock (PendingWebDataOriginsGate)
        {
            var normalized = NormalizeOrigins(origins);
            if (normalized.Count == 0) return;

            var existing = ReadPendingWebDataOriginsLocked(userDataFolder);
            var changed = false;
            foreach (var origin in normalized)
            {
                changed |= existing.Add(origin);
            }

            if (!changed) return;

            Directory.CreateDirectory(userDataFolder);
            File.WriteAllLines(GetPendingWebDataOriginsPath(userDataFolder), existing.Order(StringComparer.Ordinal));
        }
    }

    public static void RemovePendingWebDataOrigins(string userDataFolder, IEnumerable<string> origins)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        ArgumentNullException.ThrowIfNull(origins);

        lock (PendingWebDataOriginsGate)
        {
            var normalized = NormalizeOrigins(origins);
            if (normalized.Count == 0) return;

            var existing = ReadPendingWebDataOriginsLocked(userDataFolder);
            if (existing.Count == 0) return;

            existing.ExceptWith(normalized);
            var path = GetPendingWebDataOriginsPath(userDataFolder);
            if (existing.Count == 0)
            {
                if (File.Exists(path)) File.Delete(path);
                return;
            }

            Directory.CreateDirectory(userDataFolder);
            File.WriteAllLines(path, existing.Order(StringComparer.Ordinal));
        }
    }

    private static string GetPendingWebDataOriginsPath(string userDataFolder) =>
        Path.Combine(userDataFolder, PendingWebDataOriginsFileName);

    private static HashSet<string> ReadPendingWebDataOriginsLocked(string userDataFolder)
    {
        var path = GetPendingWebDataOriginsPath(userDataFolder);
        if (!File.Exists(path)) return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            return NormalizeOrigins(File.ReadAllLines(path));
        }
        catch
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static HashSet<string> NormalizeOrigins(IEnumerable<string> origins)
    {
        var normalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var origin in origins)
        {
            if (NormalizeWebOrigin(origin) is { } normalizedOrigin) normalized.Add(normalizedOrigin);
        }

        return normalized;
    }

    internal static string? NormalizeWebOrigin(string? origin)
    {
        if (string.IsNullOrWhiteSpace(origin)) return null;
        if (!Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme is not ("http" or "https")) return null;
        return uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
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

    internal IReadOnlyList<string> GetInactiveOrigins(string userDataFolder, IEnumerable<string> origins)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        ArgumentNullException.ThrowIfNull(origins);

        var normalizedUserDataFolder = NormalizeUserDataFolder(userDataFolder);
        lock (_gate)
        {
            var inactiveOrigins = new List<string>();
            foreach (var origin in origins)
            {
                var normalizedOrigin = NormalizeOrigin(origin);
                if (normalizedOrigin is null) continue;

                var key = new BitwardenWebDataOriginKey(normalizedUserDataFolder, normalizedOrigin);
                if (!_activeOrigins.ContainsKey(key)) inactiveOrigins.Add(normalizedOrigin);
            }

            return inactiveOrigins;
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
        BitwardenBrowserWebViewProfile.NormalizeWebOrigin(origin);

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
