using Renci.SshNet;

namespace Wormhole.Services.Ssh;

/// <summary>
/// Builds SSH.NET <see cref="AuthenticationMethod"/> instances from resolved
/// <see cref="SshCredentials"/>. Shared by <see cref="SshSessionService"/> (terminal)
/// and <c>SftpService</c> (file transfer) so both surfaces honor the same key/password
/// precedence and passphrase semantics.
/// </summary>
public static class SshAuthMethodsBuilder
{
    public static List<AuthenticationMethod> Build(string username, SshCredentials credentials)
    {
        var methods = new List<AuthenticationMethod>();
        if (credentials.PrivateKey is { Length: > 0 })
        {
            // KeyPassphrase is consumed locally to decrypt the key — never sent as a login
            // password. SSH.NET throws SshPassPhraseNullOrEmptyException at parse time if the
            // key is encrypted and we passed no passphrase; the caller re-prompts.
            var keyFile = string.IsNullOrEmpty(credentials.KeyPassphrase)
                ? new PrivateKeyFile(new MemoryStream(credentials.PrivateKey))
                : new PrivateKeyFile(new MemoryStream(credentials.PrivateKey), credentials.KeyPassphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(username, keyFile));
        }
        if (!string.IsNullOrEmpty(credentials.Password))
        {
            methods.Add(new PasswordAuthenticationMethod(username, credentials.Password));
        }
        return methods;
    }
}
