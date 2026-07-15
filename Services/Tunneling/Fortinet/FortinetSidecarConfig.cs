using System.Text.Json.Serialization;

namespace Wormhole.Services.Tunneling.Fortinet;

/// <summary>
/// Wire format passed from the managed side to <c>wormhole-fortiproxy.exe</c> via stdin (one
/// JSON object, terminated by EOF on stdin). Field names are lower_snake_case to match Go
/// conventions. Mirrors <see cref="WireGuard.WireGuardSidecarConfig"/>.
/// </summary>
public sealed class FortinetSidecarConfig
{
    [JsonPropertyName("host")] public string Host { get; set; } = string.Empty;
    [JsonPropertyName("port")] public int Port { get; set; } = 443;
    [JsonPropertyName("username")] public string Username { get; set; } = string.Empty;
    [JsonPropertyName("password")] public string Password { get; set; } = string.Empty;
    [JsonPropertyName("realm")] public string? Realm { get; set; }
    [JsonPropertyName("totp_secret")] public string? TotpSecret { get; set; }
    [JsonPropertyName("saml_auth_id")] public string? SamlAuthId { get; set; }
    [JsonPropertyName("svpn_cookie")] public string? SvpnCookie { get; set; }
    [JsonPropertyName("trust_server_certificate")] public bool TrustServerCertificate { get; set; }
    [JsonPropertyName("server_cert_sha256_pin")] public string? ServerCertSha256Pin { get; set; }
}
