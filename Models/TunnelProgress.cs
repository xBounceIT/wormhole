namespace Wormhole.Models;

/// <summary>
/// Coarse, user-facing phases a tunnel provider passes through while bringing a VPN up. Surfaced to
/// the connecting overlay as a live sub-status under the "VPN tunnel" step. Providers report only
/// the subset that applies to their flow (e.g. WireGuard/OpenVPN jump straight to
/// <see cref="StartingTunnel"/>; Stormshield/WatchGuard also report <see cref="Authenticating"/>
/// and, for a fresh download, <see cref="DownloadingConfiguration"/>). The session view-models map
/// each phase to a human-readable line via <see cref="ViewModels.Sessions.ConnectionProgress"/>.
/// </summary>
public enum TunnelPhase
{
    /// <summary>Reading the tunnel config + secret blob, before the provider does any network work.</summary>
    Preparing,

    /// <summary>Authenticating to the VPN gateway / captive portal (may include an interactive OTP prompt).</summary>
    Authenticating,

    /// <summary>Downloading the per-user VPN profile from the gateway.</summary>
    DownloadingConfiguration,

    /// <summary>Launching the VPN sidecar and waiting for the data-plane tunnel to come up.</summary>
    StartingTunnel,
}

/// <summary>
/// A single progress report emitted by a tunnel provider during <c>EstablishAsync</c>. <see
/// cref="Detail"/> is an optional provider-supplied override for the default phase description.
/// </summary>
public sealed record TunnelProgress(TunnelPhase Phase, string? Detail = null);
