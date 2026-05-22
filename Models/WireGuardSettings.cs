using System.Collections.Generic;

namespace Wormhole.Models;

/// <summary>
/// User-facing WireGuard tunnel settings. Serialized as JSON, DPAPI-encrypted, and stored
/// alongside other tunnel-config secret blobs. The local interface IP is required for
/// netstack to accept inbound replies; AllowedIps narrows what the sidecar routes through
/// the tunnel (typically the host CIDR you intend to reach).
/// </summary>
public sealed class WireGuardSettings
{
    public string InterfacePrivateKey { get; set; } = string.Empty;
    public string InterfaceAddress { get; set; } = string.Empty;
    public int? Mtu { get; set; }
    public List<string> Dns { get; set; } = new();

    public string PeerPublicKey { get; set; } = string.Empty;
    public string? PeerPresharedKey { get; set; }
    public string PeerEndpoint { get; set; } = string.Empty;
    public List<string> AllowedIps { get; set; } = new();
    public int? PersistentKeepaliveSeconds { get; set; }
}
