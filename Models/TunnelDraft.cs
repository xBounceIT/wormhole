namespace Wormhole.Models;

/// <summary>
/// Editor-state carrier between TunnelDialog and TunnelConfigsViewModel. Name + Kind are
/// always set; the per-kind settings group is populated only for the selected Kind. Today
/// that's just <see cref="WireGuardSettings"/>; future kinds add sibling properties and the
/// dialog gates field visibility off Kind.
/// </summary>
public sealed record TunnelDraft(string Name, TunnelKind Kind, WireGuardSettings WireGuard);
