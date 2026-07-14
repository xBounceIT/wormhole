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
        "file_systems,indexeddb,local_storage,shader_cache,websql,service_workers,cache_storage";

    private const string PendingWebDataOriginsFileName = "wormhole-bitwarden-web-origins.txt";
    internal const string PersistentRouteKeyFileName = "wormhole-bitwarden-route-key.txt";
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
    private static readonly string[] CookieDatabaseRelativePaths =
    [
        Path.Combine("Default", "Network", "Cookies"),
        Path.Combine("Default", "Cookies"),
    ];
    private static readonly string[] CookieDatabaseStateSuffixes = ["", "-wal", "-journal"];

    public static bool IsHttpsTarget(Uri navigateUri, Uri? originalUri) =>
        string.Equals((originalUri ?? navigateUri).Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    public static string BuildBrowserArguments(IPEndPoint? socks5Proxy) =>
        WebViewBrowserArguments.Build(socks5Proxy);

    public static string? BuildPersistentRouteKey(
        Uri navigateUri,
        Uri? originalUri,
        Guid? tunnelConfigId)
    {
        ArgumentNullException.ThrowIfNull(navigateUri);
        if (tunnelConfigId is not { } configId) return null;

        var routeKind = originalUri is null ? "socks5" : "forwarder";
        var targetOrigin = (originalUri ?? navigateUri)
            .GetLeftPart(UriPartial.Authority)
            .ToLowerInvariant();
        var material = configId.ToString("N") + "\0" + routeKind + "\0" + targetOrigin;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

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
        Uri? originalUri,
        Guid? tunnelConfigId)
    {
        ArgumentNullException.ThrowIfNull(navigateUri);

        var persistentRouteKey = BuildPersistentRouteKey(navigateUri, originalUri, tunnelConfigId);
        string contextMaterial;
        if (persistentRouteKey is not null)
        {
            // Keep the concrete proxy arguments in the runtime profile key: WebView2 rejects one
            // user-data folder opened concurrently with different browser arguments. The stable route
            // key scopes cookie migration between port-specific profiles for the same target/tunnel.
            contextMaterial = browserArguments + "\0route-key=" + persistentRouteKey;
        }
        else
        {
            // Loopback-forwarded targets all navigate to 127.0.0.1/::1, and cookies are not scoped by
            // port. Give each real target a stable profile when no tunnel identity is available.
            contextMaterial = navigateUri.IsLoopback && originalUri is not null
                ? browserArguments + "\0forwarded-target="
                    + originalUri.GetLeftPart(UriPartial.Authority).ToLowerInvariant()
                : browserArguments;
        }

        return GetUserDataFolder(contextMaterial, ignoreCertificateErrors);
    }

    public static bool TrySeedExtensionStateFromExistingProfile(string userDataFolder) =>
        TrySeedProfileStateFromExistingProfile(
            userDataFolder,
            AppPaths.GetBitwardenBrowserExtensionWebView2UserDataRoot(),
            persistentRouteKey: null,
            legacyTargetUri: null);

    internal static bool TrySeedExtensionStateFromExistingProfile(string userDataFolder, string profileRoot)
        => TrySeedProfileStateFromExistingProfile(
            userDataFolder,
            profileRoot,
            persistentRouteKey: null,
            legacyTargetUri: null);

    public static bool TrySeedProfileStateFromExistingProfile(
        string userDataFolder,
        string? persistentRouteKey,
        Uri? legacyTargetUri = null) =>
        TrySeedProfileStateFromExistingProfile(
            userDataFolder,
            AppPaths.GetBitwardenBrowserExtensionWebView2UserDataRoot(),
            persistentRouteKey,
            legacyTargetUri);

    internal static bool TrySeedProfileStateFromExistingProfile(
        string userDataFolder,
        string profileRoot,
        string? persistentRouteKey,
        Uri? legacyTargetUri = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(profileRoot);
        if (persistentRouteKey is not null) ArgumentException.ThrowIfNullOrWhiteSpace(persistentRouteKey);

        if (HasInstalledExtensionMarker(userDataFolder))
        {
            TryWritePersistentRouteKey(userDataFolder, persistentRouteKey);
            return false;
        }

        try
        {
            var normalizedDestination = NormalizeUserDataFolder(userDataFolder);
            var candidates = Directory.Exists(profileRoot)
                ? Directory.EnumerateDirectories(profileRoot)
                .Where(candidate => !string.Equals(
                        NormalizeUserDataFolder(candidate),
                        normalizedDestination,
                        StringComparison.Ordinal)
                    && HasInstalledExtensionMarker(candidate))
                .Select(candidate => new DirectoryInfo(candidate))
                .OrderByDescending(directory => GetLastWriteTimeUtcSafe(directory.FullName))
                .ToList()
                : [];

            var matchingRouteSources = persistentRouteKey is null
                ? []
                : candidates.Where(candidate => string.Equals(
                    ReadPersistentRouteKey(candidate.FullName),
                    persistentRouteKey,
                    StringComparison.Ordinal)).ToList();
            var extensionSource = matchingRouteSources.FirstOrDefault() ?? candidates.FirstOrDefault();
            var copiedState = false;
            if (extensionSource is not null)
            {
                CopyBitwardenExtensionState(extensionSource.FullName, userDataFolder);
                copiedState = true;
            }

            if (!HasCookieDatabase(userDataFolder))
            {
                var cookieSources = matchingRouteSources
                    .Where(source => HasMigratableCookieState(source.FullName))
                    .ToList();
                IReadOnlySet<string>? legacyCookieHosts = null;
                if (cookieSources.Count == 0 && persistentRouteKey is not null && legacyTargetUri is not null)
                {
                    legacyCookieHosts = GetCookieHosts(legacyTargetUri);
                    cookieSources = candidates.Where(source =>
                            ReadPersistentRouteKey(source.FullName) is null
                            && HasMigratableCookieState(source.FullName)
                            && CookieDatabaseContainsAnyHost(source.FullName, legacyCookieHosts))
                        .ToList();
                }

                foreach (var cookieSource in cookieSources
                         .OrderByDescending(source => GetCookieStateLastWriteTimeUtcSafe(source.FullName))
                         .ThenByDescending(source => GetLastWriteTimeUtcSafe(source.FullName)))
                {
                    if (!CopyCookieState(cookieSource.FullName, userDataFolder, legacyCookieHosts)) continue;
                    copiedState = true;
                    break;
                }
            }

            TryWritePersistentRouteKey(userDataFolder, persistentRouteKey);
            return copiedState;
        }
        catch
        {
            TryWritePersistentRouteKey(userDataFolder, persistentRouteKey);
            return false;
        }
    }

    private static string? ReadPersistentRouteKey(string userDataFolder)
    {
        try
        {
            var path = Path.Combine(userDataFolder, PersistentRouteKeyFileName);
            return File.Exists(path) ? File.ReadAllText(path).Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    private static void TryWritePersistentRouteKey(string userDataFolder, string? persistentRouteKey)
    {
        if (persistentRouteKey is null) return;

        try
        {
            Directory.CreateDirectory(userDataFolder);
            File.WriteAllText(Path.Combine(userDataFolder, PersistentRouteKeyFileName), persistentRouteKey);
        }
        catch
        {
            // Best-effort metadata: a later profile can still start, but it will not inherit cookies.
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

    private static bool HasCookieDatabase(string userDataFolder) =>
        CookieDatabaseRelativePaths.Any(relativePath => File.Exists(Path.Combine(userDataFolder, relativePath)));

    private static bool HasMigratableCookieState(string userDataFolder) =>
        File.Exists(Path.Combine(userDataFolder, "Local State")) && HasCookieDatabase(userDataFolder);

    private static DateTime GetCookieStateLastWriteTimeUtcSafe(string userDataFolder)
    {
        var newest = DateTime.MinValue;
        foreach (var relativePath in CookieDatabaseRelativePaths)
        {
            var databasePath = Path.Combine(userDataFolder, relativePath);
            foreach (var suffix in CookieDatabaseStateSuffixes)
            {
                try
                {
                    var path = databasePath + suffix;
                    var lastWriteTimeUtc = File.Exists(path) ? File.GetLastWriteTimeUtc(path) : DateTime.MinValue;
                    if (lastWriteTimeUtc > newest) newest = lastWriteTimeUtc;
                }
                catch
                {
                    // An unreadable timestamp sorts last; the backup itself remains best-effort.
                }
            }
        }

        return newest;
    }

    private static HashSet<string> GetCookieHosts(Uri targetUri)
    {
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalizedHost = targetUri.IdnHost.TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalizedHost)) return hosts;

        hosts.Add(normalizedHost);
        if (IPAddress.TryParse(normalizedHost, out _)) return hosts;

        var dotIndex = normalizedHost.IndexOf('.');
        while (dotIndex > 0 && dotIndex < normalizedHost.Length - 1)
        {
            var parentDomain = normalizedHost[(dotIndex + 1)..];
            if (!parentDomain.Contains('.', StringComparison.Ordinal)) break;
            hosts.Add(parentDomain);
            dotIndex = normalizedHost.IndexOf('.', dotIndex + 1);
        }

        return hosts;
    }

    private static bool CookieDatabaseContainsAnyHost(
        string userDataFolder,
        IReadOnlySet<string> cookieHosts)
    {
        foreach (var relativePath in CookieDatabaseRelativePaths)
        {
            var databasePath = Path.Combine(userDataFolder, relativePath);
            if (!File.Exists(databasePath)) continue;

            try
            {
                var builder = new SqliteConnectionStringBuilder
                {
                    DataSource = databasePath,
                    Mode = SqliteOpenMode.ReadOnly,
                    Cache = SqliteCacheMode.Private,
                    Pooling = false,
                };
                using var connection = new SqliteConnection(builder.ToString());
                connection.Open();
                using var command = connection.CreateCommand();
                var parameterNames = AddCookieHostParameters(command, cookieHosts);
                command.CommandText = $"SELECT 1 FROM cookies WHERE host_key IN ({parameterNames}) LIMIT 1";
                if (command.ExecuteScalar() is not null) return true;
            }
            catch
            {
                // A legacy database may be locked or use an unexpected schema; skip it safely.
            }
        }

        return false;
    }

    private static string AddCookieHostParameters(SqliteCommand command, IReadOnlySet<string> cookieHosts)
    {
        var values = cookieHosts
            .SelectMany(host => new[] { host, "." + host })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var parameterNames = new string[values.Count];
        for (var index = 0; index < values.Count; index++)
        {
            var parameterName = "$host" + index;
            parameterNames[index] = parameterName;
            command.Parameters.AddWithValue(parameterName, values[index]);
        }

        return string.Join(',', parameterNames);
    }

    private static bool CopyCookieState(
        string sourceUserDataFolder,
        string destinationUserDataFolder,
        IReadOnlySet<string>? retainedCookieHosts)
    {
        // Chromium encrypts cookie values with the key stored in Local State. Copy it before taking a
        // consistent SQLite backup; without the matching key, the destination cannot decrypt cookies.
        if (!CopyFileIfExists(
                Path.Combine(sourceUserDataFolder, "Local State"),
                Path.Combine(destinationUserDataFolder, "Local State")))
        {
            return false;
        }

        var copied = false;
        foreach (var relativePath in CookieDatabaseRelativePaths)
        {
            copied |= TryBackupSqliteDatabase(
                Path.Combine(sourceUserDataFolder, relativePath),
                Path.Combine(destinationUserDataFolder, relativePath),
                retainedCookieHosts);
        }

        return copied;
    }

    private static bool TryBackupSqliteDatabase(
        string sourcePath,
        string destinationPath,
        IReadOnlySet<string>? retainedCookieHosts)
    {
        if (!File.Exists(sourcePath)) return false;

        var stagingPath = destinationPath + ".seed-" + Guid.NewGuid().ToString("N");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            var sourceBuilder = new SqliteConnectionStringBuilder
            {
                DataSource = sourcePath,
                Mode = SqliteOpenMode.ReadOnly,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
            };
            var destinationBuilder = new SqliteConnectionStringBuilder
            {
                DataSource = stagingPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Private,
                Pooling = false,
            };
            using var source = new SqliteConnection(sourceBuilder.ToString());
            using var destination = new SqliteConnection(destinationBuilder.ToString());
            source.Open();
            destination.Open();
            source.BackupDatabase(destination);
            if (retainedCookieHosts is not null)
            {
                using var command = destination.CreateCommand();
                var parameterNames = AddCookieHostParameters(command, retainedCookieHosts);
                command.CommandText = $"DELETE FROM cookies WHERE host_key NOT IN ({parameterNames})";
                command.ExecuteNonQuery();
            }
            destination.Close();
            File.Move(stagingPath, destinationPath, overwrite: true);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            try { if (File.Exists(stagingPath)) File.Delete(stagingPath); }
            catch { /* best-effort cleanup; a uniquely named orphan is harmless */ }
        }
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

    private static bool CopyFileIfExists(string sourceFile, string destinationFile)
    {
        try
        {
            if (!File.Exists(sourceFile)) return false;
            Directory.CreateDirectory(Path.GetDirectoryName(destinationFile)!);
            File.Copy(sourceFile, destinationFile, overwrite: true);
            return true;
        }
        catch
        {
            // Extension profile seeding is best-effort; locked files are skipped and rebuilt by WebView2.
            return false;
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
