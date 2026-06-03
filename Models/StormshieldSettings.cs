using System.Text.Json.Serialization;

namespace Wormhole.Models;

/// <summary>
/// User-facing Stormshield Network SSL VPN ("SN SSL VPN" / "rpv") settings. Serialized as JSON,
/// DPAPI-encrypted, and stored in the per-config secret blob alongside the other tunnel kinds.
///
/// <para>
/// Stormshield's SSL VPN data plane is <b>stock OpenVPN over TLS</b> — the SNS firewall's SSL VPN
/// service is literally an OpenVPN server and interoperates with unmodified OpenVPN Connect. So,
/// like the WatchGuard provider, this tunnel ultimately runs through the shared OpenVPN sidecar
/// (<c>wormhole-ovpnproxy.exe</c>); no new binary is bundled. What is Stormshield-specific is how
/// the OpenVPN profile is obtained and how the user authenticates:
/// </para>
///
/// <list type="number">
///   <item><see cref="StormshieldConnectionMode.Automatic"/>: the provider replicates the native v5
///   "SN SSL VPN Client" download — <c>POST https://{Server}:{Port}/auth/config.html?version=1&amp;type=openvpn</c>
///   with form <c>user</c> + <c>pass</c> (a single-use OTP, when enabled, is concatenated onto the
///   password) — and inlines the returned <c>openvpn_client.zip</c> bundle into one self-contained
///   <c>.ovpn</c>. No administration/serverd privilege required; the OpenVPN <c>auth-user-pass</c> uses
///   the real <see cref="Password"/>.</item>
///   <item><see cref="StormshieldConnectionMode.Import"/>: the user pastes the static <c>.ovpn</c>
///   downloaded from the portal "Personal data" page. The profile already embeds the CA, client
///   cert and (plaintext) client key, so no HTTPS pre-auth is needed.</item>
/// </list>
///
/// <para>
/// JsonPropertyName attributes pin on-disk JSON keys so a future CLR rename does not silently break
/// round-trip for existing tunnels. <see cref="Password"/>, <see cref="ProfileOvpn"/>,
/// <see cref="ClientKeyPem"/> are secrets — never log them. The single-use OTP is never persisted:
/// it is prompted for at connect time.
/// </para>
/// </summary>
public sealed class StormshieldSettings
{
    /// <summary>
    /// The <c>app</c> form value the portal expects. Stormshield's own <c>python-SNS-API</c> client
    /// uses <c>"sslclient"</c>; the GUI VPN client's exact token is unconfirmed, so it is exposed as
    /// an overridable advanced field defaulting to this value (correctable without a code change).
    /// </summary>
    public const string DefaultAppToken = "sslclient";

    [JsonPropertyName("Server")] public string Server { get; set; } = string.Empty;

    /// <summary>HTTPS captive-portal port (443 by default — "the only port below 1024 usable").
    /// This is the config-retrieval port; the OpenVPN tunnel declares its own remote/proto inside
    /// the fetched/imported profile (UDP/1194 preferred, TCP/443 fallback).</summary>
    [JsonPropertyName("Port")] public int Port { get; set; } = 443;

    /// <summary>Free-text note (maps to the client's "Description" field). Pure UI metadata.</summary>
    [JsonPropertyName("Description")] public string? Description { get; set; }

    [JsonPropertyName("Mode")] public StormshieldConnectionMode Mode { get; set; } = StormshieldConnectionMode.Automatic;

    /// <summary>
    /// Maps to the client's "Connect with single sign-on" checkbox. The v5 SSO path launches the
    /// system browser for an OIDC/SAML flow and cannot be reduced to a silent POST, so it is not yet
    /// supported here — the provider raises an actionable error when this is set. Persisted so the
    /// UI round-trips faithfully and so support can be added later without a schema change.
    /// </summary>
    [JsonPropertyName("UseSingleSignOn")] public bool UseSingleSignOn { get; set; }

    [JsonPropertyName("Username")] public string Username { get; set; } = string.Empty;
    [JsonPropertyName("Password")] public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Maps to the client's "Use an OTP" checkbox. When set, the provider prompts for a single-use code
    /// at connect time and concatenates it onto the password (no separator) for the v5 config download
    /// (<c>pass = password + otp</c>). The code is spent on that HTTPS download, so the OpenVPN
    /// <c>auth-user-pass</c> on the data plane uses the real <see cref="Password"/> alone.
    /// <para>Caveat (known limitation): the native client, on a cached-config reconnect, instead appends
    /// the OTP to the OpenVPN data-plane password. A firewall that ALSO enforces the OTP-as-password
    /// suffix on the SSL VPN data plane would reject Wormhole's password-only data-plane auth. Closing
    /// that gap needs the native hash-cache gate (download — and spend the OTP — only on a config change);
    /// cert+password deployments are unaffected.</para>
    /// </summary>
    [JsonPropertyName("UseOtp")] public bool UseOtp { get; set; }

    /// <summary>
    /// The self-contained OpenVPN profile for <see cref="StormshieldConnectionMode.Import"/> mode
    /// (inline <c>&lt;ca&gt;/&lt;cert&gt;/&lt;key&gt;</c>). Opaque to managed code — the OpenVPN3
    /// sidecar parses it. Empty in Automatic mode (the profile is fetched). Contains a plaintext
    /// private key, so it lives only in the DPAPI-encrypted blob, never in plaintext SQLite.
    /// </summary>
    [JsonPropertyName("ProfileOvpn")] public string ProfileOvpn { get; set; } = string.Empty;

    /// <summary>
    /// User-supplied PEM CA bundle used to validate the firewall portal's TLS certificate during the
    /// Automatic-mode pre-auth. Needed because SNS factory certs use the appliance serial number as
    /// the certificate CN and firmware ≥ 5.0 presents a custom CA ("SNS-WebServer-default-authority")
    /// that the OS trust store does not vouch for. Optional when <see cref="TrustServerCertificate"/>
    /// is set (or when the firewall uses a publicly-trusted cert).
    /// </summary>
    [JsonPropertyName("CaPem")] public string? CaPem { get; set; }

    /// <summary>
    /// Skip ALL TLS verification on the Automatic-mode pre-auth POST. Off by default. Security note:
    /// enabling this exposes the username / password / OTP to a MITM on a hostile network. Mirrors
    /// the official client's "Always trust this server" toggle and the Fortinet/WatchGuard equivalents.
    /// </summary>
    [JsonPropertyName("TrustServerCertificate")] public bool TrustServerCertificate { get; set; }

    /// <summary>The <c>app</c> form value sent to the portal. See <see cref="DefaultAppToken"/>.</summary>
    [JsonPropertyName("AppToken")] public string AppToken { get; set; } = DefaultAppToken;
}
