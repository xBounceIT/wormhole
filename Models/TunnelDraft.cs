namespace Wormhole.Models;

/// <summary>
/// Editor-state carrier between TunnelDialog and TunnelConfigsViewModel. Name + Kind are
/// always set; the per-kind settings groups are populated for every kind regardless of the
/// selected one so the dialog can preserve field values when the user toggles Kind back and
/// forth. The dialog gates visibility off Kind; the view model picks the right group when
/// serializing the secret blob.
/// </summary>
public sealed record TunnelDraft(
    string Name,
    TunnelKind Kind,
    WireGuardSettings WireGuard,
    FortinetSettings Fortinet);
