using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Parses the <c>azurevpnconfig.xml</c> profile the Azure portal generates for point-to-site
/// clients (the <c>&lt;AzVpnProfile&gt;</c> DataContract shape shared by VPN Gateway and Virtual
/// WAN) into <see cref="AzureVpnSettings"/>. Used by the tunnel editor's import button.
///
/// <para>Parsing is deliberately namespace-agnostic (the file is emitted by .NET's
/// DataContractSerializer with a default namespace plus the <c>i</c> schema-instance prefix, but
/// hand-edited or tool-generated variants drop them) and treats <c>i:nil="true"</c> elements as
/// absent — the serializer emits those as null-sentinels alongside populated siblings.</para>
///
/// <para>Only <c>&lt;clientauth&gt;&lt;type&gt;aad&lt;/type&gt;</c> profiles are accepted:
/// certificate and username/password P2S profiles use a different credential model that this
/// provider does not implement, and silently importing one would produce a tunnel that can never
/// connect.</para>
/// </summary>
public static class AzureVpnProfileParser
{
    public sealed record Result(AzureVpnSettings Settings, string? ProfileName);

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
        if (root is null || !LocalNameIs(root, "AzVpnProfile"))
        {
            throw new InvalidOperationException(
                "The file is not an Azure VPN profile (expected an <AzVpnProfile> root element). "
                + "Import the azurevpnconfig.xml from the AzureVPN folder of the downloaded profile zip.");
        }

        var authType = Value(Child(Child(root, "clientauth"), "type"));
        if (!string.Equals(authType, "aad", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"This profile uses '{(string.IsNullOrEmpty(authType) ? "unknown" : authType)}' authentication, "
                + "but only Microsoft Entra ID ('aad') profiles are supported. Generate the profile from a P2S "
                + "gateway configured for Microsoft Entra ID authentication.");
        }

        var aad = Child(Child(root, "clientauth"), "aad")
            ?? throw new InvalidOperationException("The profile is missing its <aad> authentication block.");

        var tenantUrl = Value(Child(aad, "tenant"));
        if (string.IsNullOrWhiteSpace(tenantUrl))
            throw new InvalidOperationException("The profile's <aad> block has no <tenant> value.");

        var audience = Value(Child(aad, "audience"));
        if (string.IsNullOrWhiteSpace(audience))
            throw new InvalidOperationException("The profile's <aad> block has no <audience> value.");

        var servers = new List<string>();
        var serverList = Child(root, "serverlist");
        if (serverList is not null)
        {
            foreach (var entry in Children(serverList, "ServerEntry"))
            {
                var fqdn = Value(Child(entry, "fqdn"));
                if (!string.IsNullOrWhiteSpace(fqdn))
                    servers.Add(fqdn.Trim());
            }
        }
        if (servers.Count == 0)
            throw new InvalidOperationException("The profile lists no gateway servers (<serverlist> is empty).");

        var transportText = Value(
            Child(Child(Child(root, "protocolconfig"), "sslprotocolConfig"), "transportprotocol"));
        var transport = string.Equals(transportText, "udp", StringComparison.OrdinalIgnoreCase)
            ? AzureVpnTransport.Udp
            : AzureVpnTransport.Tcp;

        // <applicationid> is the documented spelling; <appid> is observed in some client parser
        // tables — accept either.
        var applicationId = Value(Child(aad, "applicationid")) ?? Value(Child(aad, "appid"));
        var serverSecret = Value(Child(Child(root, "servervalidation"), "serversecret"));

        var settings = new AzureVpnSettings
        {
            Servers = servers,
            Protocol = transport,
            TenantId = ExtractTenantId(tenantUrl),
            Audience = audience.Trim(),
            Issuer = Value(Child(aad, "issuer"))?.Trim(),
            ApplicationId = string.IsNullOrWhiteSpace(applicationId) ? null : applicationId.Trim(),
            ServerSecretHex = string.IsNullOrWhiteSpace(serverSecret) ? null : serverSecret.Trim(),
        };

        var name = Value(Child(root, "name"));
        return new Result(settings, string.IsNullOrWhiteSpace(name) ? null : name.Trim());
    }

    /// <summary>
    /// <c>https://login.microsoftonline.com/{tenant}/</c> → <c>{tenant}</c>. Tolerates a bare
    /// GUID/domain (already-extracted values round-trip unchanged) and a trailing slash.
    /// </summary>
    internal static string ExtractTenantId(string tenantUrl)
    {
        var trimmed = tenantUrl.Trim().TrimEnd('/');
        var lastSlash = trimmed.LastIndexOf('/');
        var candidate = lastSlash >= 0 ? trimmed[(lastSlash + 1)..] : trimmed;
        if (string.IsNullOrWhiteSpace(candidate))
            throw new InvalidOperationException($"Could not extract a tenant id from '{tenantUrl}'.");
        return candidate;
    }

    private static bool LocalNameIs(XElement element, string name) =>
        string.Equals(element.Name.LocalName, name, StringComparison.OrdinalIgnoreCase);

    // A DataContractSerializer null-sentinel (<elem i:nil="true"/>) is semantically an absent
    // element; treating it as present would read empty strings for populated-looking fields.
    private static bool IsNil(XElement element) =>
        element.Attributes().Any(a =>
            string.Equals(a.Name.LocalName, "nil", StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.Value, "true", StringComparison.OrdinalIgnoreCase));

    private static XElement? Child(XElement? parent, string localName) =>
        parent?.Elements().FirstOrDefault(e => LocalNameIs(e, localName) && !IsNil(e));

    private static IEnumerable<XElement> Children(XElement parent, string localName) =>
        parent.Elements().Where(e => LocalNameIs(e, localName) && !IsNil(e));

    private static string? Value(XElement? element) => element?.Value;
}
