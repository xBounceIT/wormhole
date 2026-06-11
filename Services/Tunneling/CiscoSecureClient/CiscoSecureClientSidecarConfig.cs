using System.Text.Json.Serialization;

namespace Wormhole.Services.Tunneling.CiscoSecureClient;

/// <summary>
/// Wire format passed from the managed side to <c>wormhole-ciscoproxy.exe</c> via stdin (one
/// JSON object, terminated by EOF on stdin). Field names are lower_snake_case to match Go
/// conventions. Mirrors <see cref="Fortinet.FortinetSidecarConfig"/>.
/// </summary>
public sealed class CiscoSecureClientSidecarConfig
{
    [JsonPropertyName("host")] public string Host { get; set; } = string.Empty;
    [JsonPropertyName("port")] public int Port { get; set; } = 443;
    [JsonPropertyName("username")] public string Username { get; set; } = string.Empty;
    [JsonPropertyName("password")] public string Password { get; set; } = string.Empty;
    [JsonPropertyName("group")] public string? Group { get; set; }
    [JsonPropertyName("secondary_password")] public string? SecondaryPassword { get; set; }
    [JsonPropertyName("totp_secret")] public string? TotpSecret { get; set; }
    [JsonPropertyName("trust_server_certificate")] public bool TrustServerCertificate { get; set; }
    [JsonPropertyName("server_cert_sha256_pin")] public string? ServerCertSha256Pin { get; set; }
}
