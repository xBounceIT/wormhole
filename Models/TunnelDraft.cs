namespace Wormhole.Models;

/// <summary>
/// Editor-state carrier between TunnelDialog and TunnelConfigsViewModel. Name + Kind are
/// always set; exactly one of the per-kind settings groups is populated (matching <see
/// cref="Kind"/>), the rest stay null. The dialog gates panel visibility off Kind and only
/// reads the relevant settings group when building the draft.
/// </summary>
public sealed record TunnelDraft(
    string Name,
    TunnelKind Kind,
    WireGuardSettings? WireGuard,
    OpenVpnSettings? OpenVpn,
    FortinetSettings? Fortinet,
    WatchguardSettings? Watchguard = null);
