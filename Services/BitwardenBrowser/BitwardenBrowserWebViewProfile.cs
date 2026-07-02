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
        return EphemeralWebDataRelativePaths
            .Select(relativePath => Path.Combine(userDataFolder, relativePath))
            .ToArray();
    }
}
