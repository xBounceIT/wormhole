namespace Wormhole.Services.Ssh;

public sealed class SshHostKeyMismatchException : Exception
{
    public SshHostKeyMismatchException(string host, string expected, string actual)
        : base($"SSH host key for '{host}' does not match the pinned fingerprint. " +
               $"Expected {expected}, server presented {actual}.")
    {
        Host = host;
        ExpectedFingerprint = expected;
        ActualFingerprint = actual;
    }

    public string Host { get; }
    public string ExpectedFingerprint { get; }
    public string ActualFingerprint { get; }
}
