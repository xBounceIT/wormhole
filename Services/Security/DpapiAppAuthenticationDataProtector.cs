using System.Security.Cryptography;
using System.Text;

namespace Wormhole.Services.Security;

public sealed class DpapiAppAuthenticationDataProtector : IAppAuthenticationDataProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Wormhole.AppAuthentication.v1");

    public byte[] Protect(byte[] plaintext) =>
        ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] protectedBlob) =>
        ProtectedData.Unprotect(protectedBlob, Entropy, DataProtectionScope.CurrentUser);
}
