using Wormhole.Models;

namespace Wormhole.Helpers;

/// <summary>
/// Heuristic for recognising Azure-AD-joined RDP credentials. Used by the editor to
/// auto-flag a connection for the external mstsc.exe path and by data migration 0005
/// to backfill the same flag on existing profiles. The embedded mstscax host crashes
/// the unpackaged WinUI process with SEH 0xC06D007F when it tries to delay-load WAM
/// during AAD auth, so routing AAD targets through mstsc.exe is the only stable option.
/// </summary>
public static class AzureAdCredentialDetector
{
    /// <summary>
    /// Returns true when the credential looks Azure-AD-joined. Two signals:
    /// (1) Domain equals "AzureAD" — the form Microsoft documents for AAD users in
    /// mstsc credential prompts; (2) Username carries the "AzureAD\" prefix —
    /// covers users who paste the full "AzureAD\user@tenant" into Username and
    /// leave Domain empty. Deliberately NOT matching bare "*@*.onmicrosoft.com"
    /// UPNs: on-prem AD accounts synced to M365 share that format without being
    /// AAD-joined for RDP purposes, and a false positive would silently re-route
    /// a working embedded connection through mstsc.exe.
    /// </summary>
    public static bool IsAzureAd(CredentialProfile? credential)
    {
        if (credential is null) return false;
        if (string.Equals(credential.Domain, "AzureAD", StringComparison.OrdinalIgnoreCase)) return true;
        if (credential.Username is { } username
            && username.StartsWith("AzureAD\\", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
