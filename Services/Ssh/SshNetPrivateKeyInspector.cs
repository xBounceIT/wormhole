using System.IO;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace Wormhole.Services.Ssh;

public sealed class SshNetPrivateKeyInspector : IPrivateKeyInspector
{
    public bool IsEncrypted(byte[] keyBytes)
    {
        try
        {
            using var stream = new MemoryStream(keyBytes);
            _ = new PrivateKeyFile(stream);
            return false;
        }
        catch (SshPassPhraseNullOrEmptyException)
        {
            return true;
        }
        catch
        {
            // Malformed key or unsupported format isn't "encrypted" per se. Let the
            // caller hand the bytes to SshSessionService where the parse error
            // surfaces with more specific context.
            return false;
        }
    }
}
