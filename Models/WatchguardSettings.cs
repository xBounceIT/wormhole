using System.Text.Json.Serialization;

namespace Wormhole.Models;

public enum WatchguardAuthMode
{
    Automatic = 0,
    UsernamePassword = 1,
    Saml = 2,
}

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
    public const string DefaultDomain = "Firebox-DB";

    /// <summary>
    /// Stock Firebox SSL VPN server certificate subject. Exposed as a const so the dialog
    /// (TunnelDialog.BuildWatchguard) and the model both use the same canonical value;
    /// duplicating it as string literals in two places would drift over time and break
    /// verify-x509-name pinning silently.
    /// </summary>
    public const string DefaultVerifyX509Name = "/O=WatchGuard_Technologies/OU=Fireware/CN=Fireware_SSLVPN_Server";

    [JsonPropertyName("Server")] public string Server { get; set; } = string.Empty;
    [JsonPropertyName("Port")] public int Port { get; set; } = 443;
    [JsonPropertyName("AuthMode")] public WatchguardAuthMode AuthMode { get; set; } = WatchguardAuthMode.Automatic;
    [JsonPropertyName("Username")] public string Username { get; set; } = string.Empty;
    [JsonPropertyName("Password")] public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Optional WatchGuard auth domain override. Empty means the provider auto-detects the domain
    /// from the Firebox status response and falls back to <see cref="DefaultDomain"/> when the
    /// gateway does not advertise a single usable domain.
    /// </summary>
    [JsonPropertyName("Domain")] public string Domain { get; set; } = string.Empty;

    [JsonPropertyName("CaPem")] public string CaPem { get; set; } = string.Empty;
    [JsonPropertyName("ClientCertPem")] public string ClientCertPem { get; set; } = string.Empty;
    [JsonPropertyName("ClientKeyPem")] public string ClientKeyPem { get; set; } = string.Empty;
    [JsonPropertyName("ProfileOvpn")] public string ProfileOvpn { get; set; } = string.Empty;

    /// <summary>Subject string for OpenVPN's verify-x509-name directive. The default matches the
    /// stock Firebox SSL VPN server cert subject; custom CA deployments override this.</summary>
    [JsonPropertyName("VerifyX509Name")]
    public string VerifyX509Name { get; set; } = DefaultVerifyX509Name;

    /// <summary>
    /// Skip TLS certificate verification on the pre-auth HTTPS POST (the credential / OTP
    /// exchange) and additionally omit the OpenVPN <c>verify-x509-name</c> subject pin in the
    /// synthesized .ovpn profile. Off by default.
    ///
    /// This does NOT relax the VPN tunnel itself: <see cref="CaPem"/> is still required and the
    /// synthesized profile still carries <c>remote-cert-tls server</c> + the inline
    /// <c>&lt;ca&gt;</c> block, so the data channel is still validated against the CA you supply.
    /// Enabling this is therefore not a CA-less path — it only loosens the pre-auth leg and the
    /// server-cert-subject pin.
    ///
    /// Security note: enabling this means the pre-auth POST accepts any server certificate,
    /// including a MITM, so the username / password / OTP can be intercepted in flight on
    /// hostile or captive networks. Only enable on a fully trusted network — e.g. when the
    /// Firebox presents a self-signed cert whose subject doesn't match the stock pin and you
    /// accept the pre-auth exposure. Mirrors the official client's "Always trust this server"
    /// toggle. The Fortinet provider has an equivalent field for parity.
    /// </summary>
    [JsonPropertyName("TrustServerCertificate")] public bool TrustServerCertificate { get; set; }
}
