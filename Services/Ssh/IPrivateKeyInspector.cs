namespace Wormhole.Services.Ssh;

/// <summary>
/// Probes a private-key blob to determine whether it needs a passphrase to decrypt.
/// Extracted to an interface so consumers (and tests) don't have to take a hard
/// dependency on SSH.NET just to ask that one question.
/// </summary>
public interface IPrivateKeyInspector
{
    bool IsEncrypted(byte[] keyBytes);
}
