using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Wormhole.Helpers;

namespace Wormhole.Services.BitwardenBrowser;

internal static class BitwardenBrowserWebViewProfile
{
    // Storage.clearDataForOrigin accepts a comma-separated CDP StorageType set. Cookies are
    // deliberately absent: Bitwarden-enabled HTTPS profiles are persistent, so authentication
    // cookies must survive tab teardown, application restarts, and application updates.
    public const string ClearableWebStorageTypes =
        "appcache,file_systems,indexeddb,local_storage,shader_cache,websql,service_workers,cache_storage";

    private const string PendingWebDataOriginsFileName = "wormhole-bitwarden-web-origins.txt";
    private static readonly object PendingWebDataOriginsGate = new();
    private static readonly string[] ExtensionSafeStartupWebDataCleanupRelativePaths =
    [
        Path.Combine("Default", "History"),
        Path.Combine("Default", "History-journal"),
        Path.Combine("Default", "Visited Links"),
        Path.Combine("Default", "Cache"),
        Path.Combine("Default", "Code Cache"),
        Path.Combine("Default", "GPUCache"),
        // DOM storage is site data; Bitwarden state is kept in extension-specific stores copied during profile seeding.
        Path.Combine("Default", "Local Storage"),
        Path.Combine("Default", "Session Storage"),
        Path.Combine("Default", "Service Worker", "CacheStorage"),
        Path.Combine("Default", "Service Worker", "ScriptCache"),
    ];
    private static readonly string[] ExtensionStateRelativePaths =
    [
        Path.Combine("Default", "Extensions"),
        Path.Combine("Default", "Extension Rules"),
        Path.Combine("Default", "Extension Scripts"),
        Path.Combine("Default", "Extension State"),
        Path.Combine("Default", "Local Extension Settings"),
        Path.Combine("Default", "Managed Extension Settings"),
        Path.Combine("Default", "Sync Extension Settings"),
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

    public static string GetUserDataFolder(
        string browserArguments,
        bool ignoreCertificateErrors,
        Uri navigateUri,
        Uri? originalUri)
    {
        ArgumentNullException.ThrowIfNull(navigateUri);

        // Loopback-forwarded targets all navigate to 127.0.0.1/::1, and cookies are not scoped by
        // port. Give each real target a stable profile so one appliance never receives another
        // appliance's cookies when the local forwarder is rebound to a different ephemeral port.
        var contextMaterial = navigateUri.IsLoopback && originalUri is not null
            ? browserArguments + "\0forwarded-target=" + originalUri.GetLeftPart(UriPartial.Authority).ToLowerInvariant()
            : browserArguments;
        return GetUserDataFolder(contextMaterial, ignoreCertificateErrors);
    }

    public static bool TrySeedExtensionStateFromExistingProfile(string userDataFolder) =>
        TrySeedExtensionStateFromExistingProfile(
            userDataFolder,
            AppPaths.GetBitwardenBrowserExtensionWebView2UserDataRoot());

    internal static bool TrySeedExtensionStateFromExistingProfile(string userDataFolder, string profileRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(profileRoot);

        if (HasInstalledExtensionMarker(userDataFolder) || !Directory.Exists(profileRoot)) return false;

        try
        {
            var normalizedDestination = NormalizeUserDataFolder(userDataFolder);
            var source = Directory.EnumerateDirectories(profileRoot)
                .Where(candidate => !string.Equals(
                        NormalizeUserDataFolder(candidate),
                        normalizedDestination,
                        StringComparison.Ordinal)
                    && HasInstalledExtensionMarker(candidate))
                .Select(candidate => new DirectoryInfo(candidate))
                .OrderByDescending(directory => GetLastWriteTimeUtcSafe(directory.FullName))
                .FirstOrDefault()
                ?.FullName;

            if (source is null) return false;

            CopyBitwardenExtensionState(source, userDataFolder);
            return true;
        }
        catch
        {
            return false;
        }
    }

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

    public static IReadOnlyList<string> GetStartupWebDataCleanupPaths(string userDataFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        var paths = ExtensionSafeStartupWebDataCleanupRelativePaths
            .Select(relativePath => Path.Combine(userDataFolder, relativePath))
            .ToList();

        AddNonExtensionIndexedDbPaths(userDataFolder, paths);
        return paths;
    }

    public static IReadOnlyList<string> DiscoverStartupWebDataOrigins(string userDataFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddHistoryOrigins(userDataFolder, origins);
        AddIndexedDbOrigins(userDataFolder, origins);
        return origins.ToList();
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

    private static bool HasInstalledExtensionMarker(string userDataFolder) =>
        BitwardenBrowserExtensionMarker.TryReadInstalledExtensionId(
            BitwardenBrowserExtensionMarker.GetPath(userDataFolder), out _);

    private static DateTime GetLastWriteTimeUtcSafe(string path)
    {
        try { return Directory.GetLastWriteTimeUtc(path); }
        catch { return DateTime.MinValue; }
    }

    private static void CopyBitwardenExtensionState(string sourceUserDataFolder, string destinationUserDataFolder)
    {
        CopyFileIfExists(
            BitwardenBrowserExtensionMarker.GetPath(sourceUserDataFolder),
            BitwardenBrowserExtensionMarker.GetPath(destinationUserDataFolder));

        foreach (var relativePath in ExtensionStateRelativePaths)
        {
            CopyDirectoryIfExists(
                Path.Combine(sourceUserDataFolder, relativePath),
                Path.Combine(destinationUserDataFolder, relativePath));
        }

        CopyExtensionIndexedDbDirectories(sourceUserDataFolder, destinationUserDataFolder);
    }

    private static void CopyExtensionIndexedDbDirectories(string sourceUserDataFolder, string destinationUserDataFolder)
    {
        var sourceIndexedDbRoot = Path.Combine(sourceUserDataFolder, "Default", "IndexedDB");
        if (!Directory.Exists(sourceIndexedDbRoot)) return;

        var destinationIndexedDbRoot = Path.Combine(destinationUserDataFolder, "Default", "IndexedDB");
        foreach (var sourceEntry in Directory.EnumerateDirectories(sourceIndexedDbRoot, "chrome-extension_*"))
        {
            CopyDirectoryIfExists(sourceEntry, Path.Combine(destinationIndexedDbRoot, Path.GetFileName(sourceEntry)));
        }
    }

    private static void CopyDirectoryIfExists(string sourceDirectory, string destinationDirectory)
    {
        if (!Directory.Exists(sourceDirectory)) return;

        foreach (var sourceFile in Directory.EnumerateFiles(sourceDirectory, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(sourceDirectory, sourceFile);
            CopyFileIfExists(sourceFile, Path.Combine(destinationDirectory, relativePath));
        }
    }

    private static void CopyFileIfExists(string sourceFile, string destinationFile)
    {
        try
        {
            if (!File.Exists(sourceFile)) return;
            Directory.CreateDirectory(Path.GetDirectoryName(destinationFile)!);
            File.Copy(sourceFile, destinationFile, overwrite: true);
        }
        catch
        {
            // Extension profile seeding is best-effort; locked files are skipped and rebuilt by WebView2.
        }
    }

    private static void AddNonExtensionIndexedDbPaths(string userDataFolder, List<string> paths)
    {
        var indexedDbRoot = Path.Combine(userDataFolder, "Default", "IndexedDB");
        if (!Directory.Exists(indexedDbRoot)) return;

        foreach (var entry in Directory.EnumerateFileSystemEntries(indexedDbRoot))
        {
            var name = Path.GetFileName(entry);
            if (name.StartsWith("chrome-extension_", StringComparison.OrdinalIgnoreCase)) continue;
            paths.Add(entry);
        }
    }

    private static void AddHistoryOrigins(string userDataFolder, HashSet<string> origins)
    {
        var historyPath = Path.Combine(userDataFolder, "Default", "History");
        if (!File.Exists(historyPath)) return;

        try
        {
            var builder = new SqliteConnectionStringBuilder
            {
                DataSource = historyPath,
                Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
            };
            using var connection = new SqliteConnection(builder.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT url FROM urls";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                if (!reader.IsDBNull(0) && NormalizeWebOrigin(reader.GetString(0)) is { } origin)
                {
                    origins.Add(origin);
                }
            }
        }
        catch
        {
            // Legacy Chromium history is best-effort; it may be absent, locked, or mid-upgrade.
        }
    }

    private static void AddIndexedDbOrigins(string userDataFolder, HashSet<string> origins)
    {
        var indexedDbRoot = Path.Combine(userDataFolder, "Default", "IndexedDB");
        if (!Directory.Exists(indexedDbRoot)) return;

        foreach (var entry in Directory.EnumerateFileSystemEntries(indexedDbRoot))
        {
            var name = Path.GetFileName(entry);
            if (TryParseIndexedDbOrigin(name) is { } origin) origins.Add(origin);
        }
    }

    private static string? TryParseIndexedDbOrigin(string name)
    {
        const string suffix = "_0.indexeddb.leveldb";
        if (!name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return null;

        var material = name[..^suffix.Length];
        var separator = material.IndexOf('_');
        if (separator <= 0 || separator == material.Length - 1) return null;

        var scheme = material[..separator];
        var host = material[(separator + 1)..];
        return NormalizeWebOrigin($"{scheme}://{host}");
    }

    internal static string? NormalizeWebOrigin(string? origin)
    {
        if (string.IsNullOrWhiteSpace(origin)) return null;
        if (!Uri.TryCreate(origin.Trim(), UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme is not ("http" or "https")) return null;
        return uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
    }

    private static string NormalizeUserDataFolder(string userDataFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        return Path.GetFullPath(userDataFolder)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .ToUpperInvariant();
    }

}

internal sealed class BitwardenWebDataOriginLeaseRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<BitwardenWebDataOriginKey, int> _activeOrigins = new();
    private readonly List<BitwardenLiveWebDataOriginRegistration> _liveOrigins = new();

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

    internal void TrackLiveOrigins(
        object owner,
        string userDataFolder,
        IEnumerable<string> origins,
        bool mergeWithExisting = false)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        ArgumentNullException.ThrowIfNull(origins);

        var normalizedUserDataFolder = NormalizeUserDataFolder(userDataFolder);
        var normalizedOrigins = NormalizeOrigins(origins);
        lock (_gate)
        {
            PruneDeadLiveOriginsLocked();
            if (mergeWithExisting && TryMergeLiveOriginsLocked(owner, normalizedUserDataFolder, normalizedOrigins)) return;

            RemoveLiveOriginsLocked(owner);
            if (normalizedOrigins.Count == 0) return;

            _liveOrigins.Add(new BitwardenLiveWebDataOriginRegistration(
                owner,
                normalizedUserDataFolder,
                normalizedOrigins));
        }
    }

    internal void UntrackLiveOrigins(object owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        lock (_gate)
        {
            RemoveLiveOriginsLocked(owner);
        }
    }

    internal IReadOnlyList<string> GetInactiveOrigins(string userDataFolder, IEnumerable<string> origins)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        ArgumentNullException.ThrowIfNull(origins);

        var normalizedUserDataFolder = NormalizeUserDataFolder(userDataFolder);
        lock (_gate)
        {
            PruneDeadLiveOriginsLocked();
            var inactiveOrigins = new List<string>();
            foreach (var origin in origins)
            {
                var normalizedOrigin = NormalizeOrigin(origin);
                if (normalizedOrigin is null) continue;

                var key = new BitwardenWebDataOriginKey(normalizedUserDataFolder, normalizedOrigin);
                if (!IsOriginActiveLocked(key)) inactiveOrigins.Add(normalizedOrigin);
            }

            return inactiveOrigins;
        }
    }

    private static HashSet<string> NormalizeOrigins(IEnumerable<string> origins)
    {
        var normalizedOrigins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var origin in origins)
        {
            if (NormalizeOrigin(origin) is { } normalizedOrigin) normalizedOrigins.Add(normalizedOrigin);
        }

        return normalizedOrigins;
    }

    private void RemoveLiveOriginsLocked(object owner)
    {
        _liveOrigins.RemoveAll(registration =>
            !registration.Owner.TryGetTarget(out var target) || ReferenceEquals(target, owner));
    }

    private void PruneDeadLiveOriginsLocked()
    {
        _liveOrigins.RemoveAll(registration => !registration.Owner.TryGetTarget(out _));
    }

    private bool TryMergeLiveOriginsLocked(
        object owner,
        string normalizedUserDataFolder,
        HashSet<string> normalizedOrigins)
    {
        foreach (var registration in _liveOrigins)
        {
            if (!registration.Owner.TryGetTarget(out var target) || !ReferenceEquals(target, owner)) continue;
            if (!string.Equals(registration.UserDataFolder, normalizedUserDataFolder, StringComparison.Ordinal)) continue;

            registration.Origins.UnionWith(normalizedOrigins);
            return true;
        }

        return false;
    }

    private bool IsOriginActiveLocked(BitwardenWebDataOriginKey key) =>
        _activeOrigins.ContainsKey(key) || HasLiveOriginLocked(key);

    private bool HasLiveOriginLocked(BitwardenWebDataOriginKey key) =>
        _liveOrigins.Any(registration =>
            string.Equals(registration.UserDataFolder, key.UserDataFolder, StringComparison.Ordinal)
            && registration.Origins.Contains(key.Origin));

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
            PruneDeadLiveOriginsLocked();
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
                    if (!HasLiveOriginLocked(key)) clearableOrigins.Add(origin);
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

    private sealed class BitwardenLiveWebDataOriginRegistration
    {
        public BitwardenLiveWebDataOriginRegistration(
            object owner,
            string userDataFolder,
            HashSet<string> origins)
        {
            Owner = new WeakReference<object>(owner);
            UserDataFolder = userDataFolder;
            Origins = origins;
        }

        public WeakReference<object> Owner { get; }
        public string UserDataFolder { get; }
        public HashSet<string> Origins { get; }
    }

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
