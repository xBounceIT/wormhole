using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Wormhole.Helpers;

namespace Wormhole.Services.BitwardenBrowser;

internal static class BitwardenBrowserWebViewProfile
{
    internal const string PersistentRouteKeyFileName = "wormhole-bitwarden-route-key.txt";
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
            legacyCookieUri: null);

    internal static bool TrySeedExtensionStateFromExistingProfile(string userDataFolder, string profileRoot)
        => TrySeedProfileStateFromExistingProfile(
            userDataFolder,
            profileRoot,
            persistentRouteKey: null,
            legacyCookieUri: null);

    public static bool TrySeedProfileStateFromExistingProfile(
        string userDataFolder,
        string? persistentRouteKey,
        Uri? legacyCookieUri = null) =>
        TrySeedProfileStateFromExistingProfile(
            userDataFolder,
            AppPaths.GetBitwardenBrowserExtensionWebView2UserDataRoot(),
            persistentRouteKey,
            legacyCookieUri);

    internal static bool TrySeedProfileStateFromExistingProfile(
        string userDataFolder,
        string profileRoot,
        string? persistentRouteKey,
        Uri? legacyCookieUri = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(profileRoot);
        if (persistentRouteKey is not null) ArgumentException.ThrowIfNullOrWhiteSpace(persistentRouteKey);

        var hasInstalledExtension = HasInstalledExtensionMarker(userDataFolder);
        if (hasInstalledExtension && persistentRouteKey is null)
        {
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

            var matchingRouteSources = candidates.Where(candidate => persistentRouteKey is null
                ? ReadPersistentRouteKey(candidate.FullName) is null
                : string.Equals(
                    ReadPersistentRouteKey(candidate.FullName),
                    persistentRouteKey,
                    StringComparison.Ordinal)).ToList();
            if (hasInstalledExtension)
            {
                var refreshedCookies = TryRefreshCookieStateFromMatchingRoute(
                    userDataFolder,
                    matchingRouteSources);
                TryWritePersistentRouteKey(userDataFolder, persistentRouteKey);
                return refreshedCookies;
            }

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
                if (cookieSources.Count == 0 && persistentRouteKey is not null && legacyCookieUri is not null)
                {
                    legacyCookieHosts = GetCookieHosts(legacyCookieUri);
                    cookieSources = candidates.Where(source =>
                            ReadPersistentRouteKey(source.FullName) is null
                            && HasMigratableCookieState(source.FullName)
                            && CookieDatabaseContainsAnyHost(source.FullName, legacyCookieHosts))
                        .ToList();
                }

                foreach (var cookieSource in OrderCookieSourcesByFreshness(cookieSources))
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

    private static bool TryRefreshCookieStateFromMatchingRoute(
        string destinationUserDataFolder,
        IEnumerable<DirectoryInfo> matchingRouteSources)
    {
        var destinationFreshness = GetCookieStateLastWriteTimeUtcSafe(destinationUserDataFolder);
        var cookieSources = matchingRouteSources
            .Where(source => HasMigratableCookieState(source.FullName));
        foreach (var source in OrderCookieSourcesByFreshness(cookieSources))
        {
            if (GetCookieStateLastWriteTimeUtcSafe(source.FullName) <= destinationFreshness) break;
            if (CopyCookieState(source.FullName, destinationUserDataFolder, retainedCookieHosts: null))
            {
                return true;
            }
        }

        return false;
    }

    private static IOrderedEnumerable<DirectoryInfo> OrderCookieSourcesByFreshness(
        IEnumerable<DirectoryInfo> sources) =>
        sources
            .OrderByDescending(source => GetCookieStateLastWriteTimeUtcSafe(source.FullName))
            .ThenByDescending(source => GetLastWriteTimeUtcSafe(source.FullName));

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
        // Chromium encrypts cookie values with the key stored in Local State. Back up the destination
        // key before replacing it so a failed SQLite backup cannot leave existing cookies undecryptable.
        var sourceLocalStatePath = Path.Combine(sourceUserDataFolder, "Local State");
        if (!File.Exists(sourceLocalStatePath)) return false;

        var destinationLocalStatePath = Path.Combine(destinationUserDataFolder, "Local State");
        var destinationHadLocalState = File.Exists(destinationLocalStatePath);
        var rollbackPath = destinationLocalStatePath + ".seed-rollback-" + Guid.NewGuid().ToString("N");
        var copied = false;
        try
        {
            if (destinationHadLocalState)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(destinationLocalStatePath)!);
                File.Copy(destinationLocalStatePath, rollbackPath);
            }

            if (!CopyFileIfExists(sourceLocalStatePath, destinationLocalStatePath)) return false;

            foreach (var relativePath in CookieDatabaseRelativePaths)
            {
                copied |= TryBackupSqliteDatabase(
                    Path.Combine(sourceUserDataFolder, relativePath),
                    Path.Combine(destinationUserDataFolder, relativePath),
                    retainedCookieHosts);
            }

            return copied;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (!copied)
            {
                RestoreLocalStateAfterFailedCookieCopy(
                    destinationLocalStatePath,
                    rollbackPath,
                    destinationHadLocalState);
            }
            try { if (File.Exists(rollbackPath)) File.Delete(rollbackPath); }
            catch { /* best-effort cleanup; a uniquely named orphan is harmless */ }
        }
    }

    private static void RestoreLocalStateAfterFailedCookieCopy(
        string destinationPath,
        string rollbackPath,
        bool destinationExisted)
    {
        try
        {
            if (destinationExisted)
            {
                if (File.Exists(rollbackPath)) File.Move(rollbackPath, destinationPath, overwrite: true);
            }
            else if (File.Exists(destinationPath))
            {
                File.Delete(destinationPath);
            }
        }
        catch
        {
            // Best-effort migration must not prevent WebView2 startup.
        }
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

    private static string NormalizeUserDataFolder(string userDataFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userDataFolder);
        return Path.GetFullPath(userDataFolder)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .ToUpperInvariant();
    }
}
