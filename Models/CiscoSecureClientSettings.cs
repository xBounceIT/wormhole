namespace Wormhole.Models;

/// <summary>
/// User-facing Cisco Secure Client (formerly AnyConnect) SSL VPN tunnel settings. Serialized as
/// JSON, DPAPI-encrypted, and stored in the per-config secret blob alongside other tunnel kinds.
/// Nothing here is ever persisted in plaintext SQLite — including <see cref="Password"/>,
/// <see cref="SecondaryPassword"/>, and <see cref="TotpSecret"/>.
/// </summary>
/// <remarks>
/// The data plane is the userspace <c>wormhole-ciscoproxy.exe</c> sidecar, which speaks the
/// AnyConnect protocol (aggregate-auth XML login + CSTP tunnel) directly rather than driving the
/// locally-installed Cisco client. v1 supports username/password, an optional tunnel group, and a
/// second factor answered with either a configured TOTP secret or a static secondary password.
/// SAML single sign-on, client-certificate auth, and endpoint posture (CSD/HostScan) are not yet
/// supported — gateways that require them will reject the connection.
/// </remarks>
public sealed class CiscoSecureClientSettings
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 443;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Tunnel group / connection profile to select on the gateway login form (AnyConnect's
    /// "Group" dropdown). Optional — many gateways expose a single default group.
    /// </summary>
    public string? Group { get; set; }

    /// <summary>
    /// Static answer for a second authentication form (challenge/response) when the gateway runs
    /// two-factor with a fixed secondary credential. Ignored when <see cref="TotpSecret"/> is set,
    /// which takes precedence for the second-factor answer.
    /// </summary>
    public string? SecondaryPassword { get; set; }

    /// <summary>
    /// Base32 TOTP shared secret used to answer a second-factor challenge with a freshly generated
    /// code, the same way the Fortinet tunnel does. Optional.
    /// </summary>
    public string? TotpSecret { get; set; }

    public bool TrustServerCertificate { get; set; }

    public string? ServerCertSha256Pin { get; set; }
}
