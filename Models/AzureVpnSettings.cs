using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Wormhole.Models;

/// <summary>
/// User-facing Azure VPN Gateway / Virtual WAN point-to-site settings (Microsoft Entra ID
/// authentication). Serialized as JSON, DPAPI-encrypted, and stored in the per-config secret blob
/// alongside the other tunnel kinds.
///
/// <para>
/// Azure's Entra-authenticated P2S data plane is <b>stock OpenVPN over TLS</b> on port 443 — so,
/// like the WatchGuard and Stormshield providers, this tunnel ultimately runs through the shared
/// OpenVPN sidecar (<c>wormhole-ovpnproxy.exe</c>); no new binary is bundled. What is
/// Azure-specific is the authentication: there is no stored password. At connect time the provider
/// acquires a Microsoft Entra ID access token — silently via a cached refresh token when possible,
/// otherwise through an interactive Microsoft sign-in popup (the same Office 365 window the native
/// Azure VPN Client shows) — and sends it as the OpenVPN <c>auth-user-pass</c> password with the
/// fixed username <c>AzureAD</c>.
/// </para>
///
/// <para>
/// The fields mirror the <c>azurevpnconfig.xml</c> profile the Azure portal generates (the
/// <c>&lt;AzVpnProfile&gt;</c> DataContract shape shared by VPN Gateway and Virtual WAN); the
/// editor's import button populates them from that file. JsonPropertyName attributes pin on-disk
/// JSON keys so a future CLR rename does not silently break round-trip for existing tunnels.
/// <see cref="ServerSecretHex"/> is key material — never log it. Access/refresh tokens are never
/// stored here; the refresh token lives in the separate DPAPI token cache.
/// </para>
/// </summary>
public sealed class AzureVpnSettings
{
    /// <summary>
    /// Loopback redirect URI Microsoft has registered for the Azure VPN Client public app
    /// registrations. The native Linux client hardcodes <c>http://localhost:2023</c>; matching it
    /// exactly avoids <c>AADSTS50011: redirect_uri mismatch</c>. The sign-in WebView intercepts
    /// the navigation before it leaves the machine, so nothing ever listens on that port.
    /// </summary>
    public const string RedirectUri = "http://localhost:2023";

    /// <summary>
    /// Gateway FQDNs from <c>&lt;serverlist&gt;</c> (e.g. <c>azuregateway-….vpn.azure.com</c>).
    /// The first entry is primary; high-availability profiles carry additional entries that
    /// OpenVPN falls over to in order. The OpenVPN port is always 443.
    /// </summary>
    [JsonPropertyName("Servers")] public List<string> Servers { get; set; } = new();

    /// <summary>OpenVPN transport from <c>&lt;transportprotocol&gt;</c>; Azure defaults to TCP.</summary>
    [JsonPropertyName("Protocol")] public AzureVpnTransport Protocol { get; set; } = AzureVpnTransport.Tcp;

    /// <summary>
    /// Entra tenant identifier — the GUID (or verified domain) extracted from the profile's
    /// <c>&lt;tenant&gt;</c> URL (<c>https://login.microsoftonline.com/{tenant}/</c>).
    /// </summary>
    [JsonPropertyName("TenantId")] public string TenantId { get; set; } = string.Empty;

    /// <summary>
    /// OAuth audience the gateway validates tokens against — <c>&lt;audience&gt;</c>. For Azure
    /// Public this is <c>c632b3df-fb67-4d84-bdcf-b95ad541b5c8</c> (Microsoft-registered Azure VPN
    /// Client app) or <c>41b23e61-6c1e-4545-b367-cd054e0ed4b4</c> (legacy manually-registered app),
    /// or a custom app GUID.
    /// </summary>
    [JsonPropertyName("Audience")] public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Token issuer (<c>&lt;issuer&gt;</c>, e.g. <c>https://sts.windows.net/{tenant}/</c>).
    /// Carried for round-trip fidelity with the imported profile; the OAuth flow derives its
    /// endpoints from <see cref="TenantId"/> instead.
    /// </summary>
    [JsonPropertyName("Issuer")] public string? Issuer { get; set; }

    /// <summary>
    /// Optional OAuth client (application) id override from <c>&lt;applicationid&gt;</c>. When
    /// absent the audience GUID doubles as the client id — the pattern the Azure VPN public app
    /// registrations expect (see <see cref="ClientId"/>).
    /// </summary>
    [JsonPropertyName("ApplicationId")] public string? ApplicationId { get; set; }

    /// <summary>
    /// The gateway's OpenVPN <c>tls-auth</c> static key from <c>&lt;servervalidation&gt;
    /// &lt;serversecret&gt;</c> — 512 hex characters (a 2048-bit OpenVPN Static key V1). Key
    /// material: never log. Optional; gateways provisioned without it complete the TLS handshake
    /// without tls-auth.
    /// </summary>
    [JsonPropertyName("ServerSecretHex")] public string? ServerSecretHex { get; set; }

    /// <summary>
    /// Optional CA bundle (PEM) override for validating the gateway's TLS certificate. When empty
    /// the provider pins the DigiCert Global Root G2 that Azure's <c>*.vpn.azure.com</c> gateway
    /// certificates chain to.
    /// </summary>
    [JsonPropertyName("CaPem")] public string? CaPem { get; set; }

    /// <summary>Effective OAuth client id: the explicit application id when set, else the audience.</summary>
    [JsonIgnore]
    public string ClientId =>
        string.IsNullOrWhiteSpace(ApplicationId) ? Audience : ApplicationId;
}
