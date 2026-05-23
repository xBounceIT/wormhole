using System.Text.Json.Serialization;

namespace Wormhole.Models;

/// <summary>
/// User-facing OpenVPN tunnel settings. Serialized as JSON, DPAPI-encrypted, and stored
/// alongside other tunnel-config secret blobs. The full .ovpn profile contents are kept
/// opaque here — OpenVPN3 parses every directive (remote, cipher, ca/cert/key, tls-auth,
/// etc.) on the sidecar side. Username/Password are surfaced as separate fields so the
/// dialog can collect them via a PasswordBox rather than asking the user to inline
/// auth-user-pass in the profile.
///
/// JsonPropertyName attributes pin the on-disk JSON key for each field — without them, a
/// future CLR rename (e.g. ProfileOvpn → OvpnProfile) would silently break round-trip for
/// every existing tunnel because the new code would read missing keys as empty defaults.
/// </summary>
public sealed class OpenVpnSettings
{
    [JsonPropertyName("ProfileOvpn")] public string ProfileOvpn { get; set; } = string.Empty;
    [JsonPropertyName("Username")] public string? Username { get; set; }
    [JsonPropertyName("Password")] public string? Password { get; set; }
}
