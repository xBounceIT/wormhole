using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Wormhole.Services.Tunneling.WireGuard;

/// <summary>
/// Wire format passed from the managed side to <c>wormhole-wgproxy.exe</c> via stdin (one JSON
/// object, terminated by EOF on stdin). Field names are lower_snake_case to match Go conventions.
/// </summary>
public sealed class WireGuardSidecarConfig
{
    [JsonPropertyName("interface_private_key")] public string InterfacePrivateKey { get; set; } = string.Empty;
    [JsonPropertyName("interface_address")]     public string InterfaceAddress     { get; set; } = string.Empty;
    [JsonPropertyName("mtu")]                   public int? Mtu                    { get; set; }
    [JsonPropertyName("dns")]                   public List<string> Dns            { get; set; } = new();

    [JsonPropertyName("peer_public_key")]        public string PeerPublicKey         { get; set; } = string.Empty;
    [JsonPropertyName("peer_preshared_key")]     public string? PeerPresharedKey     { get; set; }
    [JsonPropertyName("peer_endpoint")]          public string PeerEndpoint          { get; set; } = string.Empty;
    [JsonPropertyName("allowed_ips")]            public List<string> AllowedIps      { get; set; } = new();
    [JsonPropertyName("persistent_keepalive_s")] public int? PersistentKeepaliveSeconds { get; set; }
}
