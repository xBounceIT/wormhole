using Wormhole.Models;

namespace Wormhole.Helpers;

/// <summary>
/// Heuristic for recognising Azure-AD-joined RDP credentials. Used by the editor to
/// auto-flag a connection for the external mstsc.exe path, by data migration 0005 to
/// backfill the same flag on existing profiles, and by <see cref="ViewModels.Sessions.RdpSessionViewModel"/>
/// to route AAD targets unconditionally at connect time. The embedded mstscax host
/// crashes the unpackaged WinUI process with SEH 0xC06D007F when it tries to delay-load
/// WAM during AAD auth, so routing AAD targets through mstsc.exe is the only stable
/// option.
///
/// Signals checked, in order of strength:
/// <list type="number">
///   <item>The saved credential's <c>Domain</c> equals "AzureAD" (case-insensitive).
///         This is the form Microsoft documents for AAD users in mstsc credential
///         prompts.</item>
///   <item>The saved credential's <c>Username</c> carries the "AzureAD\" prefix —
///         covers users who paste the full "AzureAD\user@tenant" into Username and
///         leave Domain empty.</item>
///   <item>The connection node's own <c>RdpDomain</c> field equals "AzureAD" — for
///         users who configure the domain on the node itself rather than on a saved
///         credential (typical for "Prompt every time" connections, where Wormhole
///         has no saved credential to inspect).</item>
///   <item>The connection node's own <c>Username</c> field carries the "AzureAD\"
///         prefix — same rationale as (3) for the username path.</item>
/// </list>
/// We deliberately do NOT match bare <c>*@*.onmicrosoft.com</c> UPNs: on-prem AD
/// accounts synced to M365 share that format without being AAD-joined for RDP purposes,
/// and a false positive would silently re-route a working embedded connection through
/// mstsc.exe.
/// </summary>
public static class AzureAdCredentialDetector
{
    private const string AzureAdDomain = "AzureAD";
    private const string AzureAdUsernamePrefix = "AzureAD\\";

    /// <summary>
    /// True when the connection profile is identified as Azure-AD-joined via either its
    /// own fields (Username / RdpDomain) or its linked saved credential. <paramref name="credential"/>
    /// may be null when the profile uses "Prompt every time" — in that case only the
    /// node-level fields are inspected.
    /// </summary>
    public static bool IsAzureAd(ConnectionProfile profile, CredentialProfile? credential)
    {
        if (profile is null) throw new ArgumentNullException(nameof(profile));
        if (IsAzureAd(credential)) return true;
        if (HasAzureAdDomain(profile.RdpDomain)) return true;
        if (HasAzureAdPrefix(profile.Username)) return true;
        return false;
    }

    /// <summary>
    /// Credential-only check. Used by the editor when it doesn't yet have a full
    /// <see cref="ConnectionProfile"/> in hand (the user is editing fields that compose
    /// one). Combine with <see cref="HasAzureAdDomain(string?)"/> and
    /// <see cref="HasAzureAdPrefix(string?)"/> for the node-side signals.
    /// </summary>
    public static bool IsAzureAd(CredentialProfile? credential)
    {
        if (credential is null) return false;
        if (HasAzureAdDomain(credential.Domain)) return true;
        if (HasAzureAdPrefix(credential.Username)) return true;
        return false;
    }

    /// <summary>True when a Domain field equals "AzureAD" (case-insensitive, ignoring
    /// surrounding whitespace). Whitespace-trimming protects against editor users who
    /// paste a value with stray spaces — without it, " AzureAD " would not match.</summary>
    public static bool HasAzureAdDomain(string? domain) =>
        domain is not null
        && string.Equals(domain.Trim(), AzureAdDomain, StringComparison.OrdinalIgnoreCase);

    /// <summary>True when a Username field starts with "AzureAD\" (case-insensitive,
    /// ignoring leading whitespace).</summary>
    public static bool HasAzureAdPrefix(string? username) =>
        username is not null
        && username.TrimStart().StartsWith(AzureAdUsernamePrefix, StringComparison.OrdinalIgnoreCase);
}
