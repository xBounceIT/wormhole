namespace Wormhole.Models;

/// <summary>
/// User-facing Fortinet SSL VPN tunnel settings. Serialized as JSON, DPAPI-encrypted, and
/// stored in the per-config secret blob alongside other tunnel kinds. Nothing here is ever
/// persisted in plaintext SQLite — including <see cref="TotpSecret"/>, which the sidecar
/// uses to compute the current code itself when the gateway prompts for a 2FA challenge.
/// </summary>
public sealed class FortinetSettings
{
    public const int DefaultSamlRedirectPort = 8020;

    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 443;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? Realm { get; set; }
    public string? TotpSecret { get; set; }
    public bool UseSingleSignOn { get; set; }
    public bool UseExternalBrowser { get; set; } = true;
    public int SamlRedirectPort { get; set; } = DefaultSamlRedirectPort;
    public bool TrustServerCertificate { get; set; }
    public string? ServerCertSha256Pin { get; set; }

    public FortinetSettings SanitizedForAuthenticationMode()
    {
        if (!UseSingleSignOn) return this;

        var sanitized = (FortinetSettings)MemberwiseClone();
        sanitized.Username = string.Empty;
        sanitized.Password = string.Empty;
        sanitized.TotpSecret = null;
        if (UseExternalBrowser)
            sanitized.Realm = null;
        return sanitized;
    }
}
