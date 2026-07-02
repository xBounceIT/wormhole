using System.Net;
using System.Security.Cryptography;
using System.Text;
using Wormhole.Helpers;

namespace Wormhole.Services.BitwardenBrowser;

internal static class BitwardenBrowserWebViewProfile
{
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
}
