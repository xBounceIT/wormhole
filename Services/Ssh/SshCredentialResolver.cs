using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Services.Ssh;

public interface ISshCredentialResolver
{
    Task<SshCredentials> ResolveAsync(ConnectionProfile profile, XamlRoot xamlRoot, CancellationToken cancellationToken = default);
}

/// <summary>
/// Credentials presented to <see cref="ISshSessionService.ConnectAsync"/>.
/// <para>
/// <paramref name="Password"/> is the *account login* password (PasswordAuthenticationMethod).
/// <paramref name="KeyPassphrase"/> is used only to decrypt <paramref name="PrivateKey"/> and is
/// NEVER sent as a password to the server. Mixing them risks leaking the key passphrase as
/// a login attempt and tripping account lockouts.
/// </para>
/// </summary>
public sealed record SshCredentials(string? Password, string? KeyPassphrase, byte[]? PrivateKey)
{
    public bool HasAny => !string.IsNullOrEmpty(Password) || PrivateKey is { Length: > 0 };
    public static SshCredentials Empty { get; } = new(null, null, null);
}

public sealed class SshCredentialResolver : ISshCredentialResolver
{
    private readonly ICredentialRepository _credentialRepo;
    private readonly ICredentialService _credentialService;
    private readonly IDialogService _dialogs;

    public SshCredentialResolver(
        ICredentialRepository credentialRepo,
        ICredentialService credentialService,
        IDialogService dialogs)
    {
        _credentialRepo = credentialRepo;
        _credentialService = credentialService;
        _dialogs = dialogs;
    }

    public async Task<SshCredentials> ResolveAsync(ConnectionProfile profile, XamlRoot xamlRoot, CancellationToken cancellationToken = default)
    {
        if (profile.CredentialId is null)
        {
            return await PromptForPasswordAsync(profile, xamlRoot).ConfigureAwait(true);
        }

        var credential = await _credentialRepo.GetByIdAsync(profile.CredentialId.Value, cancellationToken).ConfigureAwait(true);
        if (credential is null)
        {
            return await PromptForPasswordAsync(profile, xamlRoot).ConfigureAwait(true);
        }

        if (credential.Kind == CredentialKind.SshKey)
        {
            var key = await _credentialService.ReadPrivateKeyAsync(credential.Id).ConfigureAwait(true);
            if (key is null || key.Length == 0)
            {
                return await PromptForPasswordAsync(profile, xamlRoot).ConfigureAwait(true);
            }
            // Any stored secret for a key credential is the passphrase used to *decrypt the
            // key*, not a login password. Surface it in KeyPassphrase so the service won't
            // also try it as PasswordAuthenticationMethod.
            var passphrase = await _credentialService.ReadPasswordAsync(credential.Id).ConfigureAwait(true);
            return new SshCredentials(null, passphrase, key);
        }

        var stored = await _credentialService.ReadPasswordAsync(credential.Id).ConfigureAwait(true);
        if (!string.IsNullOrEmpty(stored))
        {
            return new SshCredentials(stored, null, null);
        }
        return await PromptForPasswordAsync(profile, xamlRoot).ConfigureAwait(true);
    }

    private async Task<SshCredentials> PromptForPasswordAsync(ConnectionProfile profile, XamlRoot xamlRoot)
    {
        var user = string.IsNullOrEmpty(profile.Username) ? profile.Host : profile.Username + "@" + profile.Host;
        var password = await _dialogs.PromptPasswordAsync(
            xamlRoot,
            "SSH password",
            "Enter the password for " + user + ":").ConfigureAwait(true);
        return string.IsNullOrEmpty(password) ? SshCredentials.Empty : new SshCredentials(password, null, null);
    }
}
