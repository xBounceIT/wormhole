using System.Text.Json.Serialization;

namespace Wormhole.Services.Tunneling.OpenVpn;

/// <summary>
/// Wire format passed from the managed side to <c>wormhole-ovpnproxy.exe</c> via stdin (one
/// JSON object, terminated by EOF on stdin). Field names are lower_snake_case to match Go
/// conventions. The profile blob is opaque from the managed side — OpenVPN3 parses it on the
/// sidecar; we only forward the bytes plus optional credentials and a mock-mode flag for tests.
/// </summary>
public sealed class OpenVpnSidecarConfig
{
    [JsonPropertyName("profile_ovpn")] public string ProfileOvpn { get; set; } = string.Empty;
    [JsonPropertyName("username")] public string? Username { get; set; }
    [JsonPropertyName("password")] public string? Password { get; set; }
    [JsonPropertyName("mock")] public bool Mock { get; set; }
}
