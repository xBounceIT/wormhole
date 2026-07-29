using System.Collections.Generic;
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

    /// <summary>
    /// Optional answer to an OpenVPN data-channel dynamic challenge (CRV1) that the server may
    /// issue after the initial username/password auth — e.g. WatchGuard AuthPoint 2FA presented
    /// at the OpenVPN layer rather than a web portal. The user's one-time passcode, or
    /// <c>"p"</c>/<c>"push"</c> to request a push notification. When set, the sidecar connects
    /// and, if the server challenges, reconnects carrying this response so the user is prompted
    /// for a second factor exactly once. Null/empty for non-2FA VPNs or when 2FA was already
    /// satisfied out of band.
    /// </summary>
    [JsonPropertyName("challenge_response")] public string? ChallengeResponse { get; set; }

    /// <summary>
    /// Stable Windows adapter IDs eligible for the outer OpenVPN transport. The sidecar
    /// resolves the current interface index immediately before every DNS query and socket
    /// connect, so network transitions cannot leave a stale index behind.
    /// </summary>
    [JsonPropertyName("transport_adapter_ids")]
    public IReadOnlyList<string>? TransportAdapterIds { get; set; }

    /// <summary>
    /// Effective OpenVPN remotes in profile order. When supplied with adapter IDs, the
    /// sidecar prefers physical-adapter DNS, falls back to the system resolver when a
    /// native VPN blocks it, and feeds the resulting IP to OpenVPN3 while preserving the
    /// original hostname. The transport socket remains pinned to the physical adapter.
    /// </summary>
    [JsonPropertyName("transport_remotes")]
    public IReadOnlyList<OpenVpnTransportRemote>? TransportRemotes { get; set; }

    [JsonPropertyName("mock")] public bool Mock { get; set; }
}

public sealed class OpenVpnTransportRemote
{
    [JsonPropertyName("host")] public string Host { get; set; } = string.Empty;
    [JsonPropertyName("port")] public string Port { get; set; } = string.Empty;
    [JsonPropertyName("protocol")] public string Protocol { get; set; } = string.Empty;
}
