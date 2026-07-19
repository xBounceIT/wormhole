using Microsoft.Extensions.DependencyInjection;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services.Bitwarden;

namespace Wormhole.Services.Ssh;

public interface ISshCredentialResolver
{
    /// <summary>
    /// Resolves saved or interactive SSH credentials. Throws
    /// <see cref="Wormhole.Services.UserInteractionCancelledException"/> when the user dismisses a required prompt.
    /// </summary>
    Task<SshCredentials> ResolveAsync(ConnectionProfile profile, CancellationToken cancellationToken = default);
}

/// <summary>
/// Credentials presented to <see cref="ISshSessionService.ConnectAsync"/>.
/// <para>
/// <paramref name="Password"/> is the *account login* password (PasswordAuthenticationMethod).
/// <paramref name="KeyPassphrase"/> is used only to decrypt <paramref name="PrivateKey"/> and is
/// NEVER sent as a password to the server. Mixing them risks leaking the key passphrase as
/// a login attempt and tripping account lockouts.
/// <paramref name="CredentialUsername"/> is the username stored on the selected credential profile;
/// SSH/SFTP use it only when the resolved connection profile has no explicit/inherited username.
/// </para>
/// </summary>
public sealed record SshCredentials(
    string? Password,
    string? KeyPassphrase,
    byte[]? PrivateKey,
    string? CredentialUsername = null)
{
    public string? UsernameOverride { get; init; }
    public bool HasAny => !string.IsNullOrEmpty(Password) || PrivateKey is { Length: > 0 };
    public static SshCredentials Empty { get; } = new(null, null, null);

    public string? ResolveUsername(ConnectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return string.IsNullOrWhiteSpace(profile.Username)
            ? NullIfWhiteSpace(CredentialUsername)
            : profile.Username;
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value;
}

public sealed class SshCredentialResolver : ISshCredentialResolver
{
    private readonly IBitwardenCredentialCatalogService _credentialCatalog;
    private readonly ICredentialService _credentialService;
    private readonly ICredentialPasswordResolver _passwordResolver;
    private readonly IConnectionCredentialBindingService _credentialBindings;
    private readonly IDialogService _dialogs;
    private readonly IPrivateKeyInspector _keyInspector;
    private readonly ITransientSessionCredentialStore? _transientCredentials;

    public SshCredentialResolver(
        ICredentialRepository credentialRepo,
        ICredentialService credentialService,
        ICredentialPasswordResolver passwordResolver,
        IConnectionCredentialBindingService credentialBindings,
        IDialogService dialogs,
        IPrivateKeyInspector keyInspector,
        ITransientSessionCredentialStore? transientCredentials = null)
        : this(
            new RepositoryCredentialCatalogAdapter(credentialRepo),
            credentialService,
            passwordResolver,
            credentialBindings,
            dialogs,
            keyInspector,
            transientCredentials)
    {
    }

    [ActivatorUtilitiesConstructor]
    public SshCredentialResolver(
        IBitwardenCredentialCatalogService credentialCatalog,
        ICredentialService credentialService,
        ICredentialPasswordResolver passwordResolver,
        IConnectionCredentialBindingService credentialBindings,
        IDialogService dialogs,
        IPrivateKeyInspector keyInspector,
        ITransientSessionCredentialStore? transientCredentials = null)
    {
        _credentialCatalog = credentialCatalog;
        _credentialService = credentialService;
        _passwordResolver = passwordResolver;
        _credentialBindings = credentialBindings;
        _dialogs = dialogs;
        _keyInspector = keyInspector;
        _transientCredentials = transientCredentials;
    }

    public async Task<SshCredentials> ResolveAsync(ConnectionProfile profile, CancellationToken cancellationToken = default)
    {
        if (profile.IsEphemeral &&
            !string.IsNullOrWhiteSpace(profile.Username) &&
            _transientCredentials?.Read(profile.NodeId) is { Length: > 0 } transient)
        {
            return new SshCredentials(transient, null, null);
        }

        // Inline per-connection password (the editor forces CredentialId null when this is on,
        // so the two are mutually exclusive). The secret lives in Credential Manager keyed by
        // the node Id. A missing OR empty entry — e.g. a DB restored onto a machine without the
        // secret, or an inline connection saved with a blank password — falls back to a prompt
        // rather than failing the connect opaquely. (An empty Password yields no auth method, so
        // treat it like the no-credential path, matching the saved-credential branch below.)
        if (profile.UseInlinePassword && !profile.IsEphemeral)
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

        var credential = await _credentialCatalog.GetByIdAsync(profile.CredentialId.Value, cancellationToken).ConfigureAwait(true);
        cancellationToken.ThrowIfCancellationRequested();
        if (credential is null)
        {
            return await PromptForPasswordAsync(profile, cancellationToken).ConfigureAwait(true);
        }

        if (credential.Protocol != ProtocolType.Ssh)
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
                return await PromptForPasswordAsync(profile, cancellationToken, credential.Username).ConfigureAwait(true);
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
                if (passphrase is null)
                {
                    throw new UserInteractionCancelledException("SSH key passphrase prompt was cancelled.");
                }
                if (passphrase.Length == 0) return SshCredentials.Empty;
            }
            return new SshCredentials(null, passphrase, key, credential.Username);
        }

        string? stored;
        try
        {
            stored = await _passwordResolver.ReadPasswordAsync(
                credential,
                _dialogs.PromptBitwardenUnlockAsync,
                cancellationToken).ConfigureAwait(true);
        }
        catch (BitwardenVaultException)
        {
            return await PromptForPasswordAsync(profile, cancellationToken, credential.Username).ConfigureAwait(true);
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.IsNullOrEmpty(stored))
        {
            return new SshCredentials(stored, null, null, credential.Username);
        }
        return await PromptForPasswordAsync(profile, cancellationToken, credential.Username).ConfigureAwait(true);
    }

    private static async Task ObserveCredentialReadAsync(Task<string?> task)
    {
        try { await task.ConfigureAwait(false); }
        catch { /* best-effort observer for an abandoned overlapping read */ }
    }

    private async Task<SshCredentials> PromptForPasswordAsync(
        ConnectionProfile profile,
        CancellationToken cancellationToken,
        string? credentialUsername = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var username = string.IsNullOrWhiteSpace(profile.Username) ? credentialUsername : profile.Username;
        var requiresUsername = string.IsNullOrWhiteSpace(username);
        var user = requiresUsername ? profile.Host : username + "@" + profile.Host;
        var result = await _dialogs.PromptAccountCredentialsAsync(
            "SSH password",
            "Enter the password for " + user + ":",
            ProtocolType.Ssh,
            requireUsername: requiresUsername,
            initialUsername: username,
            allowSaveCredentialToConnection: !profile.IsEphemeral,
            cancellationToken: cancellationToken).ConfigureAwait(true);
        // Re-check after the await: the user may have closed the tab (canceling the
        // connect CTS) while the dialog was open. Don't act on a stale password.
        cancellationToken.ThrowIfCancellationRequested();
        if (result is null)
        {
            throw new UserInteractionCancelledException("SSH password prompt was cancelled.");
        }
        if (string.IsNullOrEmpty(result.Password))
        {
            return SshCredentials.Empty;
        }

        if (profile.IsEphemeral)
        {
            _transientCredentials?.Store(profile.NodeId, result.Password);
        }

        if (!profile.IsEphemeral &&
            result.SelectedCredential is { } selectedCredential &&
            result.SaveCredentialToConnection)
        {
            await _credentialBindings.SaveCredentialBindingAsync(
                profile.NodeId,
                selectedCredential,
                cancellationToken).ConfigureAwait(true);
            cancellationToken.ThrowIfCancellationRequested();
        }

        var selectedUsername = NullIfWhiteSpace(result.Username)
            ?? NullIfWhiteSpace(result.SelectedCredential?.Username);

        return new SshCredentials(result.Password, null, null, selectedUsername ?? credentialUsername)
        {
            UsernameOverride = selectedUsername,
        };

        static string? NullIfWhiteSpace(string? value) =>
            string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
