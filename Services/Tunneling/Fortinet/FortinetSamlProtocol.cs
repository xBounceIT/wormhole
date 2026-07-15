using System;
using System.Collections.Generic;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Fortinet;

internal static class FortinetSamlProtocol
{
    private const int MaxAuthIdLength = 4096;

    internal static Uri BuildGatewayUri(FortinetSettings settings, string path = "/")
    {
        ArgumentNullException.ThrowIfNull(settings);
        var host = settings.Host.Trim();
        if (host.Length >= 2 && host[0] == '[' && host[^1] == ']')
            host = host[1..^1];

        return new UriBuilder(Uri.UriSchemeHttps, host, settings.Port, path).Uri;
    }

    internal static Uri BuildStartUri(FortinetSettings settings)
    {
        var builder = new UriBuilder(BuildGatewayUri(settings, "/remote/saml/start"));
        if (settings.UseExternalBrowser)
            builder.Query = "redirect=1";
        else if (!string.IsNullOrWhiteSpace(settings.Realm))
            builder.Query = "realm=" + Uri.EscapeDataString(settings.Realm.Trim());
        return builder.Uri;
    }

    internal static bool IsConfiguredGatewayUri(FortinetSettings settings, string? rawUri)
    {
        if (!Uri.TryCreate(rawUri, UriKind.Absolute, out var candidate))
            return false;
        var gateway = BuildGatewayUri(settings);
        return candidate.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && candidate.IdnHost.Equals(gateway.IdnHost, StringComparison.OrdinalIgnoreCase)
            && candidate.Port == gateway.Port;
    }

    internal static bool TryParseAuthId(string? requestTarget, out string authId)
    {
        authId = string.Empty;
        if (string.IsNullOrWhiteSpace(requestTarget)
            || requestTarget.Length > MaxAuthIdLength + 1024
            || requestTarget[0] != '/')
        {
            return false;
        }

        var queryIndex = requestTarget.IndexOf('?');
        if (queryIndex < 0 || queryIndex == requestTarget.Length - 1)
            return false;

        foreach (var part in requestTarget[(queryIndex + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pieces = part.Split('=', 2);
            if (!pieces[0].Equals("id", StringComparison.OrdinalIgnoreCase) || pieces.Length != 2)
                continue;

            try
            {
                if (!HasValidPercentEncoding(pieces[1]))
                    return false;
                var decoded = Uri.UnescapeDataString(pieces[1].Replace("+", " ", StringComparison.Ordinal));
                if (string.IsNullOrWhiteSpace(decoded) || decoded.Length > MaxAuthIdLength)
                    return false;
                authId = decoded;
                return true;
            }
            catch (UriFormatException)
            {
                return false;
            }
        }

        return false;
    }

    internal static bool IsSvpnCookieName(string? name) =>
        string.Equals(name, "SVPNCOOKIE", StringComparison.Ordinal);

    internal static string? SelectSvpnCookieValue(
        IEnumerable<(string Name, string Value, bool IsHttpOnly)> cookies)
    {
        ArgumentNullException.ThrowIfNull(cookies);
        foreach (var cookie in cookies)
        {
            if (cookie.IsHttpOnly
                && IsSvpnCookieName(cookie.Name)
                && !string.IsNullOrWhiteSpace(cookie.Value))
            {
                return cookie.Value;
            }
        }
        return null;
    }

    private static bool HasValidPercentEncoding(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] != '%') continue;
            if (i + 2 >= value.Length || !Uri.IsHexDigit(value[i + 1]) || !Uri.IsHexDigit(value[i + 2]))
                return false;
            i += 2;
        }
        return true;
    }
}
