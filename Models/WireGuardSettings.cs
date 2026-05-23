using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Wormhole.Models;

/// <summary>
/// User-facing WireGuard tunnel settings. Serialized as JSON, DPAPI-encrypted, and stored
/// alongside other tunnel-config secret blobs. The local interface IP is required for
/// netstack to accept inbound replies; AllowedIps narrows what the sidecar routes through
/// the tunnel (typically the host CIDR you intend to reach).
///
/// JsonPropertyName attributes pin the on-disk JSON key for each field. Without them, a
/// future CLR rename would silently break round-trip for every existing tunnel — the new
/// code would read missing keys as empty defaults and the user would see a blank dialog.
/// The literal names match the property names so existing on-disk blobs continue to read
/// correctly; the attribute exists to prevent the rename from drifting the format.
/// </summary>
public sealed class WireGuardSettings
{
    [JsonPropertyName("InterfacePrivateKey")] public string InterfacePrivateKey { get; set; } = string.Empty;
    [JsonPropertyName("InterfaceAddress")] public string InterfaceAddress { get; set; } = string.Empty;
    [JsonPropertyName("Mtu")] public int? Mtu { get; set; }
    [JsonPropertyName("Dns")] public List<string> Dns { get; set; } = new();

    [JsonPropertyName("PeerPublicKey")] public string PeerPublicKey { get; set; } = string.Empty;
    [JsonPropertyName("PeerPresharedKey")] public string? PeerPresharedKey { get; set; }
    [JsonPropertyName("PeerEndpoint")] public string PeerEndpoint { get; set; } = string.Empty;
    [JsonPropertyName("AllowedIps")] public List<string> AllowedIps { get; set; } = new();
    [JsonPropertyName("PersistentKeepaliveSeconds")] public int? PersistentKeepaliveSeconds { get; set; }
}
