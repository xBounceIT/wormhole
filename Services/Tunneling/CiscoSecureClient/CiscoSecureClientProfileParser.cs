using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.CiscoSecureClient;

/// <summary>
/// Parses Cisco Secure Client / AnyConnect profile XML into the non-secret fields Wormhole needs
/// to start an AnyConnect session. Credentials and MFA answers are intentionally left for the
/// user to enter in the tunnel editor.
/// </summary>
public static class CiscoSecureClientProfileParser
{
    public sealed record Result(CiscoSecureClientSettings Settings, string? ProfileName);

    public static Result Parse(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
            throw new InvalidOperationException("The file is empty.");

        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"The file is not valid XML: {ex.Message}", ex);
        }

        var root = doc.Root;
        if (root is null || !LocalNameIs(root, "AnyConnectProfile"))
        {
            throw new InvalidOperationException(
                "The file is not a Cisco Secure Client profile (expected an <AnyConnectProfile> root element).");
        }

        var serverList = Child(root, "ServerList");
        if (serverList is null)
            throw new InvalidOperationException("The profile has no <ServerList> block.");

        foreach (var entry in Children(serverList, "HostEntry"))
        {
            var address = Value(Child(entry, "HostAddress"));
            if (string.IsNullOrWhiteSpace(address))
                continue;

            var (host, port) = ParseHostAddress(address);
            var group = Value(Child(entry, "UserGroup"));
            var profileName = Value(Child(entry, "HostName"));
            return new Result(
                new CiscoSecureClientSettings
                {
                    Host = host,
                    Port = port,
                    Group = string.IsNullOrWhiteSpace(group) ? null : group.Trim(),
                },
                string.IsNullOrWhiteSpace(profileName) ? null : profileName.Trim());
        }

        throw new InvalidOperationException("The profile does not contain a HostEntry with a HostAddress value.");
    }

    private static (string Host, int Port) ParseHostAddress(string value)
    {
        var raw = value.Trim();
        if (raw.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host))
                throw new InvalidOperationException($"The profile's HostAddress '{raw}' is not a valid gateway address.");
            if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"The profile's HostAddress '{raw}' must use https when a URL scheme is present.");

            var port = uri.IsDefaultPort ? 443 : uri.Port;
            if (port is < 1 or > 65535)
                throw new InvalidOperationException($"The profile's HostAddress '{raw}' has an invalid port.");

            return (TrimIpv6Brackets(uri.Host), port);
        }

        HostSpec spec;
        try
        {
            spec = HostSpecParser.Parse(raw);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException($"The profile's HostAddress '{raw}' is invalid: {ex.Message}", ex);
        }

        if (spec.User is not null)
            throw new InvalidOperationException($"The profile's HostAddress '{raw}' must not include a username.");

        if (spec.Port is null && CountChar(raw.AsSpan(), ':') == 1)
            throw new InvalidOperationException($"The profile's HostAddress '{raw}' has an invalid port.");

        return (spec.Host, spec.Port ?? 443);
    }

    private static string TrimIpv6Brackets(string host) =>
        host.Length >= 2 && host[0] == '[' && host[^1] == ']'
            ? host[1..^1]
            : host;

    private static bool LocalNameIs(XElement element, string name) =>
        string.Equals(element.Name.LocalName, name, StringComparison.OrdinalIgnoreCase);

    private static XElement? Child(XElement? parent, string localName) =>
        parent?.Elements().FirstOrDefault(e => LocalNameIs(e, localName));

    private static IEnumerable<XElement> Children(XElement parent, string localName) =>
        parent.Elements().Where(e => LocalNameIs(e, localName));

    private static string? Value(XElement? element) => element?.Value;

    private static int CountChar(ReadOnlySpan<char> s, char c)
    {
        var n = 0;
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == c) n++;
        }
        return n;
    }
}
