namespace Wormhole.Models;

/// <summary>
/// The user's answer to the per-connect "use the configured VPN tunnel or connect directly"
/// prompt (see <c>ITunnelRoutePrompter</c>). Surfaced only when the
/// <see cref="AppSettings.PromptBeforeTunnelConnect"/> setting is on and the profile is
/// configured for a tunnel — for targets that are reachable directly on some networks and
/// only through the VPN on others.
/// </summary>
public enum TunnelRouteChoice
{
    /// <summary>Establish the configured tunnel and route the connection through it.</summary>
    UseTunnel,

    /// <summary>Skip the tunnel and connect straight to the target for this attempt.</summary>
    Direct,

    /// <summary>Abort the connection without connecting either way.</summary>
    Cancel,
}
