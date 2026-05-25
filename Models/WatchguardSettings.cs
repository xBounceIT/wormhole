using System.Text.Json.Serialization;

namespace Wormhole.Models;

/// <summary>
/// User-facing WatchGuard Mobile VPN with SSL settings. Serialized as JSON, DPAPI-encrypted,
/// and stored in the per-config secret blob alongside other tunnel kinds.
///
/// WatchGuard's SSL VPN is OpenVPN over TCP/443 with a Firebox CA and client certificate
/// chain — the `.wgssl` file a Firebox emits is a tar archive containing client.ovpn,
/// ca.crt, client.crt, client.pem. At connect time WatchguardTunnelProvider synthesizes an
/// in-memory .ovpn from these fields and hands it to the existing OpenVPN sidecar; no new
/// binary is bundled. If the gateway returns a 2FA challenge from /?action=sslvpn_logon,
/// the user-entered OTP becomes the OpenVPN auth-user-pass password (WatchGuard-specific
/// quirk — not standard OpenVPN static-challenge).
///
/// JsonPropertyName attributes pin on-disk JSON keys so a future CLR rename does not
/// silently break round-trip for existing tunnels.
/// </summary>
public sealed class WatchguardSettings
{
    /// <summary>
    /// Stock Firebox SSL VPN server certificate subject. Exposed as a const so the dialog
    /// (TunnelDialog.BuildWatchguard) and the model both use the same canonical value;
    /// duplicating it as string literals in two places would drift over time and break
    /// verify-x509-name pinning silently.
    /// </summary>
    public const string DefaultVerifyX509Name = "/O=WatchGuard_Technologies/OU=Fireware/CN=Fireware_SSLVPN_Server";

    [JsonPropertyName("Server")] public string Server { get; set; } = string.Empty;
    [JsonPropertyName("Port")] public int Port { get; set; } = 443;
    [JsonPropertyName("Username")] public string Username { get; set; } = string.Empty;
    [JsonPropertyName("Password")] public string Password { get; set; } = string.Empty;

    /// <summary>WatchGuard auth domain. "Firebox-DB" is the local user database; AD / RADIUS
    /// deployments name their own domain in the Mobile VPN with SSL configuration.</summary>
    [JsonPropertyName("Domain")] public string Domain { get; set; } = "Firebox-DB";

    [JsonPropertyName("CaPem")] public string CaPem { get; set; } = string.Empty;
    [JsonPropertyName("ClientCertPem")] public string ClientCertPem { get; set; } = string.Empty;
    [JsonPropertyName("ClientKeyPem")] public string ClientKeyPem { get; set; } = string.Empty;

    /// <summary>Subject string for OpenVPN's verify-x509-name directive. The default matches the
    /// stock Firebox SSL VPN server cert subject; custom CA deployments override this.</summary>
    [JsonPropertyName("VerifyX509Name")]
    public string VerifyX509Name { get; set; } = DefaultVerifyX509Name;

    /// <summary>Skip server certificate verification entirely. Matches the Fortinet field for
    /// parity; mirrors the official client's "Always trust this server" toggle. Off by default.</summary>
    [JsonPropertyName("TrustServerCertificate")] public bool TrustServerCertificate { get; set; }
}
