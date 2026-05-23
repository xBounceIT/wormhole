using System.Security.Cryptography;

namespace Wormhole.Services.Ssh;

public enum HostKeyDecision
{
    Trust,
    TofuAccept,
    Mismatch,
}

public static class SshHostKeyValidator
{
    public static string ComputeFingerprint(byte[] hostKey)
    {
        ArgumentNullException.ThrowIfNull(hostKey);
        var digest = SHA256.HashData(hostKey);
        return "SHA256:" + Convert.ToBase64String(digest).TrimEnd('=');
    }

    public static HostKeyDecision Decide(string? knownFingerprint, string capturedFingerprint)
    {
        if (string.IsNullOrEmpty(capturedFingerprint))
        {
            throw new ArgumentException("Captured fingerprint must be non-empty.", nameof(capturedFingerprint));
        }
        if (string.IsNullOrEmpty(knownFingerprint)) return HostKeyDecision.TofuAccept;
        return string.Equals(knownFingerprint, capturedFingerprint, StringComparison.Ordinal)
            ? HostKeyDecision.Trust
            : HostKeyDecision.Mismatch;
    }
}
