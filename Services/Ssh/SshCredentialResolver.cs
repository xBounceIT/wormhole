using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Services.Ssh;

public interface ISshCredentialResolver
{
    Task<SshCredentials> ResolveAsync(ConnectionProfile profile, CancellationToken cancellationToken = default);
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
    private readonly IPrivateKeyInspector _keyInspector;

    public SshCredentialResolver(
        ICredentialRepository credentialRepo,
        ICredentialService credentialService,
        IDialogService dialogs,
        IPrivateKeyInspector keyInspector)
    {
        _credentialRepo = credentialRepo;
        _credentialService = credentialService;
        _dialogs = dialogs;
        _keyInspector = keyInspector;
    }

    public async Task<SshCredentials> ResolveAsync(ConnectionProfile profile, CancellationToken cancellationToken = default)
    {
        // Inline per-connection password (the editor forces CredentialId null when this is on,
        // so the two are mutually exclusive). The secret lives in Credential Manager keyed by
        // the node Id. A missing OR empty entry — e.g. a DB restored onto a machine without the
        // secret, or an inline connection saved with a blank password — falls back to a prompt
        // rather than failing the connect opaquely. (An empty Password yields no auth method, so
        // treat it like the no-credential path, matching the saved-credential branch below.)
        if (profile.UseInlinePassword)
        {
            var inline = await _credentialService.ReadPasswordAsync(profile.NodeId).ConfigureAwait(true);
            cancellationToken.ThrowIfCancellationRequested();
            if (!string.IsNullOrEmpty(inline))
            {
                return new SshCredentials(inline, null, null);
            }
            return await PromptForPasswordAsync(profile, cancellationToken).ConfigureAwait(true);
        }

        if (profile.CredentialId is null)
        {
            return await PromptForPasswordAsync(profile, cancellationToken).ConfigureAwait(true);
        }

        var credential = await _credentialRepo.GetByIdAsync(profile.CredentialId.Value, cancellationToken).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
        if (credential is null)
        {
            return await PromptForPasswordAsync(profile, cancellationToken).ConfigureAwait(true);
        }

        if (credential.Kind == CredentialKind.SshKey)
        {
            var passphraseTask = _credentialService.ReadPasswordAsync(credential.Id);
            byte[]? key;
            try
            {
                key = await _credentialService.ReadPrivateKeyAsync(credential.Id).ConfigureAwait(true);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch
            {
                _ = ObserveCredentialReadAsync(passphraseTask);
                throw;
            }

            if (key is null || key.Length == 0)
            {
                _ = ObserveCredentialReadAsync(passphraseTask);
                return await PromptForPasswordAsync(profile, cancellationToken).ConfigureAwait(true);
            }
            // Any stored secret for a key credential is the passphrase used to *decrypt the
            // key*, not a login password. Surface it in KeyPassphrase so the service won't
            // also try it as PasswordAuthenticationMethod.
            var passphrase = await passphraseTask.ConfigureAwait(true);
            cancellationToken.ThrowIfCancellationRequested();
            // If no passphrase was stored, probe whether the key actually needs one.
            // If encrypted, prompt rather than handing the blob to SshSessionService
            // where it would surface as a generic failed connect with no recovery.
            if (string.IsNullOrEmpty(passphrase) && _keyInspector.IsEncrypted(key))
            {
                passphrase = await _dialogs.PromptPasswordAsync(
                    "SSH key passphrase",
                    "Enter the passphrase for the SSH key:",
                    cancellationToken).ConfigureAwait(true);
                cancellationToken.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(passphrase))
                {
                    return SshCredentials.Empty;
                }
            }
            return new SshCredentials(null, passphrase, key);
        }

        var stored = await _credentialService.ReadPasswordAsync(credential.Id).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.IsNullOrEmpty(stored))
        {
            return new SshCredentials(stored, null, null);
        }
        return await PromptForPasswordAsync(profile, cancellationToken).ConfigureAwait(true);
    }

    private static async Task ObserveCredentialReadAsync(Task<string?> task)
    {
        try { await task.ConfigureAwait(false); }
        catch { /* best-effort observer for an abandoned overlapping read */ }
    }

    private async Task<SshCredentials> PromptForPasswordAsync(ConnectionProfile profile, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = string.IsNullOrEmpty(profile.Username) ? profile.Host : profile.Username + "@" + profile.Host;
        var password = await _dialogs.PromptPasswordAsync(
            "SSH password",
            "Enter the password for " + user + ":",
            cancellationToken).ConfigureAwait(true);
        // Re-check after the await: the user may have closed the tab (canceling the
        // connect CTS) while the dialog was open. Don't act on a stale password.
        cancellationToken.ThrowIfCancellationRequested();
        return string.IsNullOrEmpty(password) ? SshCredentials.Empty : new SshCredentials(password, null, null);
    }
}
