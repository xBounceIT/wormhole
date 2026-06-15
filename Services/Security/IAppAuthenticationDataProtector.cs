namespace Wormhole.Services.Security;

public interface IAppAuthenticationDataProtector
{
    byte[] Protect(byte[] plaintext);
    byte[] Unprotect(byte[] protectedBlob);
}
