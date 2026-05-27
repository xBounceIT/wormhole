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
    public static AuthenticationMethod[] Build(string username, SshCredentials credentials)
    {
        var privateKey = credentials.PrivateKey;
        var password = credentials.Password;
        var hasPrivateKey = privateKey is { Length: > 0 };
        var hasPassword = !string.IsNullOrEmpty(password);
        var count = (hasPrivateKey ? 1 : 0) + (hasPassword ? 1 : 0);
        if (count == 0) return Array.Empty<AuthenticationMethod>();

        var methods = new AuthenticationMethod[count];
        var index = 0;
        if (hasPrivateKey)
        {
            // KeyPassphrase is consumed locally to decrypt the key — never sent as a login
            // password. SSH.NET throws SshPassPhraseNullOrEmptyException at parse time if the
            // key is encrypted and we passed no passphrase; the caller re-prompts.
            var keyFile = string.IsNullOrEmpty(credentials.KeyPassphrase)
                ? new PrivateKeyFile(new MemoryStream(privateKey!))
                : new PrivateKeyFile(new MemoryStream(privateKey!), credentials.KeyPassphrase);
            methods[index++] = new PrivateKeyAuthenticationMethod(username, keyFile);
        }
        if (hasPassword)
        {
            methods[index] = new PasswordAuthenticationMethod(username, password);
        }
        return methods;
    }
}
