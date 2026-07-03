using System.Net;
using Microsoft.Data.Sqlite;
using Wormhole.Services.BitwardenBrowser;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenBrowserWebViewProfileTests
{
    [Fact]
    public void IsHttpsTarget_UsesOriginalHttpsUriForLoopbackForwarderTargets()
    {
        Assert.True(BitwardenBrowserWebViewProfile.IsHttpsTarget(new Uri("https://router.example/login"), originalUri: null));
        Assert.True(BitwardenBrowserWebViewProfile.IsHttpsTarget(new Uri("http://127.0.0.1:54321"), new Uri("https://router.example/login")));
        Assert.False(BitwardenBrowserWebViewProfile.IsHttpsTarget(new Uri("http://router.example/login"), originalUri: null));
        Assert.False(BitwardenBrowserWebViewProfile.IsHttpsTarget(new Uri("http://127.0.0.1:54321"), new Uri("http://router.example/login")));
    }

    [Fact]
    public void ContextFolderName_ChangesForProxyAndCertificatePolicy()
    {
        var directArgs = BitwardenBrowserWebViewProfile.BuildBrowserArguments(null);
        var proxyArgs = BitwardenBrowserWebViewProfile.BuildBrowserArguments(new IPEndPoint(IPAddress.Loopback, 1080));

        var direct = BitwardenBrowserWebViewProfile.BuildContextFolderName(directArgs, ignoreCertificateErrors: false);
        var directIgnoreCert = BitwardenBrowserWebViewProfile.BuildContextFolderName(directArgs, ignoreCertificateErrors: true);
        var proxy = BitwardenBrowserWebViewProfile.BuildContextFolderName(proxyArgs, ignoreCertificateErrors: false);

        Assert.StartsWith("profile-", direct, StringComparison.Ordinal);
        Assert.NotEqual(direct, directIgnoreCert);
        Assert.NotEqual(direct, proxy);
    }

    [Fact]
    public void UserDataFolder_IncludesSocksPortInRuntimeProfileKey()
    {
        var firstProxy = new IPEndPoint(IPAddress.Loopback, 12000);
        var secondProxy = new IPEndPoint(IPAddress.Loopback, 23000);
        var firstArgs = BitwardenBrowserWebViewProfile.BuildBrowserArguments(firstProxy);
        var secondArgs = BitwardenBrowserWebViewProfile.BuildBrowserArguments(secondProxy);

        Assert.NotEqual(firstArgs, secondArgs);

        var first = BitwardenBrowserWebViewProfile.GetUserDataFolder(firstArgs, ignoreCertificateErrors: false);
        var second = BitwardenBrowserWebViewProfile.GetUserDataFolder(secondArgs, ignoreCertificateErrors: false);
        var direct = BitwardenBrowserWebViewProfile.GetUserDataFolder(
            BitwardenBrowserWebViewProfile.BuildBrowserArguments(null),
            ignoreCertificateErrors: false);
        var ignoreCert = BitwardenBrowserWebViewProfile.GetUserDataFolder(firstArgs, ignoreCertificateErrors: true);

        Assert.NotEqual(first, second);
        Assert.NotEqual(first, direct);
        Assert.NotEqual(first, ignoreCert);
    }

    [Fact]
    public async Task TrySeedExtensionStateFromExistingProfile_CopiesExtensionStateOnly()
    {
        var root = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        var source = Path.Combine(root, "profile-source");
        var destination = Path.Combine(root, "profile-destination");
        var extensionPath = Path.Combine(root, "extension");
        var extensionSettings = Path.Combine(source, "Default", "Local Extension Settings", "extension-id");
        var extensionIndexedDb = Path.Combine(source, "Default", "IndexedDB", "chrome-extension_extension-id_0.indexeddb.leveldb");
        var siteIndexedDb = Path.Combine(source, "Default", "IndexedDB", "https_router.example_0.indexeddb.leveldb");
        try
        {
            Directory.CreateDirectory(extensionSettings);
            await File.WriteAllTextAsync(Path.Combine(extensionSettings, "state.log"), "state");
            Directory.CreateDirectory(extensionIndexedDb);
            await File.WriteAllTextAsync(Path.Combine(extensionIndexedDb, "CURRENT"), "db");
            Directory.CreateDirectory(siteIndexedDb);
            await File.WriteAllTextAsync(Path.Combine(siteIndexedDb, "CURRENT"), "site");
            await BitwardenBrowserExtensionMarker.WriteAsync(
                BitwardenBrowserExtensionMarker.GetPath(source),
                extensionPath,
                "extension-id");

            Assert.True(BitwardenBrowserWebViewProfile.TrySeedExtensionStateFromExistingProfile(destination, root));

            Assert.True(File.Exists(BitwardenBrowserExtensionMarker.GetPath(destination)));
            Assert.Equal("state", File.ReadAllText(Path.Combine(destination, "Default", "Local Extension Settings", "extension-id", "state.log")));
            Assert.Equal("db", File.ReadAllText(Path.Combine(destination, "Default", "IndexedDB", "chrome-extension_extension-id_0.indexeddb.leveldb", "CURRENT")));
            Assert.False(Directory.Exists(Path.Combine(destination, "Default", "IndexedDB", "https_router.example_0.indexeddb.leveldb")));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void PendingWebDataOrigins_RoundTripsNormalizedHttpOrigins()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        try
        {
            BitwardenBrowserWebViewProfile.AddPendingWebDataOrigins(profile,
            [
                "https://Example.test/login",
                "https://example.test/other",
                "http://127.0.0.1:54321/path",
                "chrome-extension://abcdef/popup.html",
                "not a uri",
            ]);

            var origins = BitwardenBrowserWebViewProfile.ReadPendingWebDataOrigins(profile)
                .Order(StringComparer.Ordinal)
                .ToArray();

            Assert.Equal(["http://127.0.0.1:54321", "https://example.test"], origins);
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }

    [Fact]
    public void RemovePendingWebDataOrigins_RemovesOnlyClearedOrigins()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        try
        {
            BitwardenBrowserWebViewProfile.AddPendingWebDataOrigins(profile,
            [
                "https://first.example",
                "https://second.example",
            ]);

            BitwardenBrowserWebViewProfile.RemovePendingWebDataOrigins(profile, ["https://first.example/path"]);

            Assert.Equal(["https://second.example"], BitwardenBrowserWebViewProfile.ReadPendingWebDataOrigins(profile));

            BitwardenBrowserWebViewProfile.RemovePendingWebDataOrigins(profile, ["https://second.example"]);

            Assert.Empty(BitwardenBrowserWebViewProfile.ReadPendingWebDataOrigins(profile));
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }

    [Fact]
    public async Task StartupCleanupPaths_PreservesExtensionStateWhenMarkerExists()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        var siteIndexedDb = Path.Combine(profile, "Default", "IndexedDB", "https_example.test_0.indexeddb.leveldb");
        var extensionIndexedDb = Path.Combine(profile, "Default", "IndexedDB", "chrome-extension_abc_0.indexeddb.leveldb");
        try
        {
            Directory.CreateDirectory(siteIndexedDb);
            Directory.CreateDirectory(extensionIndexedDb);
            await BitwardenBrowserExtensionMarker.WriteAsync(
                BitwardenBrowserExtensionMarker.GetPath(profile),
                Path.Combine(profile, "extension"),
                "extension-id");

            var paths = BitwardenBrowserWebViewProfile.GetStartupWebDataCleanupPaths(profile);

            Assert.Contains(Path.Combine(profile, "Default", "History"), paths);
            Assert.Contains(Path.Combine(profile, "Default", "Cache"), paths);
            Assert.Contains(siteIndexedDb, paths);
            Assert.DoesNotContain(extensionIndexedDb, paths);
            Assert.DoesNotContain(Path.Combine(profile, "Default", "Network", "Cookies"), paths);
            Assert.DoesNotContain(Path.Combine(profile, "Default", "Local Storage"), paths);
            Assert.DoesNotContain(Path.Combine(profile, "Default", "Session Storage"), paths);
            Assert.DoesNotContain(paths, path => path.Contains("Extension", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }

    [Fact]
    public void StartupCleanupPaths_ClearsGlobalWebStateForLegacyProfiles()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        var siteIndexedDb = Path.Combine(profile, "Default", "IndexedDB", "https_example.test_0.indexeddb.leveldb");
        var extensionIndexedDb = Path.Combine(profile, "Default", "IndexedDB", "chrome-extension_abc_0.indexeddb.leveldb");
        try
        {
            Directory.CreateDirectory(siteIndexedDb);
            Directory.CreateDirectory(extensionIndexedDb);

            var paths = BitwardenBrowserWebViewProfile.GetStartupWebDataCleanupPaths(profile);

            Assert.Contains(Path.Combine(profile, "Default", "Network", "Cookies"), paths);
            Assert.Contains(Path.Combine(profile, "Default", "Local Storage"), paths);
            Assert.Contains(Path.Combine(profile, "Default", "Session Storage"), paths);
            Assert.Contains(siteIndexedDb, paths);
            Assert.DoesNotContain(extensionIndexedDb, paths);
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }

    [Fact]
    public void ClearStartupWebCookies_RemovesOnlyDiscoveredOriginCookies()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        var cookiesPath = Path.Combine(profile, "Default", "Network", "Cookies");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(cookiesPath)!);
            var builder = new SqliteConnectionStringBuilder { DataSource = cookiesPath, Pooling = false };
            using (var connection = new SqliteConnection(builder.ToString()))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE cookies(host_key TEXT, name TEXT);"
                    + "INSERT INTO cookies(host_key, name) VALUES "
                    + "('router.example.com', 'session'), "
                    + "('.router.example.com', 'domain-session'), "
                    + "('.example.com', 'parent-domain-session'), "
                    + "('vault.bitwarden.example', 'vault-session');";
                command.ExecuteNonQuery();
            }

            BitwardenBrowserWebViewProfile.ClearStartupWebCookies(profile, ["https://router.example.com/login"]);

            Assert.Equal(["vault.bitwarden.example"], ReadCookieHosts(cookiesPath));
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }

    [Fact]
    public void DiscoverStartupWebDataOrigins_RecoversLegacyIndexedDbOrigins()
    {
        var profile = Path.Combine(Path.GetTempPath(), "wormhole-bitwarden-webview-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(profile, "Default", "IndexedDB", "https_example.test_0.indexeddb.leveldb"));
            Directory.CreateDirectory(Path.Combine(profile, "Default", "IndexedDB", "http_127.0.0.1_0.indexeddb.leveldb"));
            Directory.CreateDirectory(Path.Combine(profile, "Default", "IndexedDB", "chrome-extension_abc_0.indexeddb.leveldb"));

            Directory.CreateDirectory(Path.Combine(profile, "Default"));
            var historyPath = Path.Combine(profile, "Default", "History");
            var historyBuilder = new SqliteConnectionStringBuilder { DataSource = historyPath, Pooling = false };
            using (var connection = new SqliteConnection(historyBuilder.ToString()))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE urls(url TEXT);"
                    + "INSERT INTO urls(url) VALUES ('https://history.example/login'), ('ftp://ignored.example/file');";
                command.ExecuteNonQuery();
            }

            var origins = BitwardenBrowserWebViewProfile.DiscoverStartupWebDataOrigins(profile)
                .Order(StringComparer.Ordinal)
                .ToArray();

            Assert.Equal(["http://127.0.0.1", "https://example.test", "https://history.example"], origins);
        }
        finally
        {
            if (Directory.Exists(profile)) Directory.Delete(profile, recursive: true);
        }
    }

    private static string[] ReadCookieHosts(string cookiesPath)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = cookiesPath, Pooling = false };
        using var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT host_key FROM cookies ORDER BY host_key";
        using var reader = command.ExecuteReader();
        var hosts = new List<string>();
        while (reader.Read())
        {
            hosts.Add(reader.GetString(0));
        }

        return hosts.ToArray();
    }
}
