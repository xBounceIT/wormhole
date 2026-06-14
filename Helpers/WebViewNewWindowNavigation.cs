using System;

namespace Wormhole.Helpers;

/// <summary>
/// Decides whether a WebView2 new-window request should be redirected into the existing browser
/// surface. Kept WinUI-free so the session browser behavior can be unit-tested without XAML.
/// </summary>
internal static class WebViewNewWindowNavigation
{
    private const string AboutBlank = "about:blank";

    internal static string? GetInSessionNavigationUri(
        string? rawUri,
        Uri? routedBaseUri = null,
        Uri? originalBaseUri = null)
    {
        if (string.IsNullOrWhiteSpace(rawUri)) return null;

        var candidate = rawUri.Trim();
        if (IsAboutBlank(candidate)) return null;
        if (originalBaseUri is null || routedBaseUri is null) return candidate;

        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri)) return null;
        if (IsSameOrigin(uri, routedBaseUri)) return candidate;
        if (!IsSameOrigin(uri, originalBaseUri)) return null;

        var builder = new UriBuilder(uri)
        {
            Scheme = routedBaseUri.Scheme,
            Host = routedBaseUri.Host,
            Port = routedBaseUri.Port,
        };
        return builder.Uri.ToString();
    }

    private static bool IsAboutBlank(string uri)
    {
        if (!uri.StartsWith(AboutBlank, StringComparison.OrdinalIgnoreCase)) return false;

        return uri.Length == AboutBlank.Length
            || uri[AboutBlank.Length] is '?' or '#';
    }

    private static bool IsSameOrigin(Uri uri, Uri? origin) =>
        origin is not null
        && uri.Scheme.Equals(origin.Scheme, StringComparison.OrdinalIgnoreCase)
        && uri.IdnHost.Equals(origin.IdnHost, StringComparison.OrdinalIgnoreCase)
        && uri.Port == origin.Port;
}
