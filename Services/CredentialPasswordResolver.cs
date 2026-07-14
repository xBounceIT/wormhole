using Microsoft.Extensions.Logging;
using Wormhole.Models;
using Wormhole.Services.Bitwarden;

namespace Wormhole.Services;

public sealed class CredentialPasswordResolver : ICredentialPasswordResolver, IDisposable
{
    private readonly ICredentialService _localCredentials;
    private readonly IBitwardenVaultClient _bitwarden;
    private readonly IBitwardenSessionService _bitwardenSession;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<CredentialPasswordResolver> _logger;
    private readonly SemaphoreSlim _unlockGate = new(1, 1);

    public CredentialPasswordResolver(
        ICredentialService localCredentials,
        IBitwardenVaultClient bitwarden,
        IBitwardenSessionService bitwardenSession,
        IAppSettingsService settings,
        ILogger<CredentialPasswordResolver> logger)
    {
        _localCredentials = localCredentials;
        _bitwarden = bitwarden;
        _bitwardenSession = bitwardenSession;
        _settings = settings;
        _logger = logger;
    }

    public async Task<string?> ReadPasswordAsync(
        CredentialProfile credential,
        BitwardenUnlockPrompt? unlockPrompt = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        if (credential.SecretProvider != CredentialSecretProvider.Bitwarden)
        {
            return await _localCredentials.ReadPasswordAsync(credential.Id).ConfigureAwait(false);
        }

        if (!_settings.Current.EnableBitwardenVault)
        {
            throw new BitwardenVaultException("Bitwarden credential vault is disabled in Settings.");
        }

        var itemId = credential.BitwardenItemId;
        if (string.IsNullOrWhiteSpace(itemId))
        {
            throw new BitwardenVaultException("This credential is missing its Bitwarden item reference.");
        }

        var sessionKey = await EnsureSessionKeyAsync(unlockPrompt, cancellationToken).ConfigureAwait(true);
        var item = await GetItemWithRetryAsync(itemId, sessionKey, unlockPrompt, cancellationToken).ConfigureAwait(true);
        if (item is null)
        {
            await _bitwarden.SyncAsync(_bitwardenSession.SessionKey, cancellationToken).ConfigureAwait(false);
            item = await GetItemWithRetryAsync(itemId, _bitwardenSession.SessionKey, unlockPrompt, cancellationToken).ConfigureAwait(true);
        }

        if (item is null)
        {
            throw new BitwardenVaultException("The linked Bitwarden item was not found.");
        }
        if (string.IsNullOrEmpty(item.Password))
        {
            throw new BitwardenVaultException("The linked Bitwarden item does not contain login.password.");
        }

        return item.Password;
    }

    private async Task<BitwardenLoginItem?> GetItemWithRetryAsync(
        string itemId,
        string? sessionKey,
        BitwardenUnlockPrompt? unlockPrompt,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _bitwarden.GetLoginItemAsync(itemId, sessionKey, cancellationToken).ConfigureAwait(true);
        }
        catch (BitwardenVaultException ex) when (ex.IsAuthenticationError)
        {
            _logger.LogInformation("Bitwarden session key was rejected; requesting a fresh unlock.");
            _bitwardenSession.ClearSessionKey();
            sessionKey = await EnsureSessionKeyAsync(unlockPrompt, cancellationToken).ConfigureAwait(true);
            return await _bitwarden.GetLoginItemAsync(itemId, sessionKey, cancellationToken).ConfigureAwait(true);
        }
    }

    public void Dispose() => _unlockGate.Dispose();

    private async Task<string?> EnsureSessionKeyAsync(
        BitwardenUnlockPrompt? unlockPrompt,
        CancellationToken cancellationToken)
    {
        if (_bitwardenSession.SessionKey is { Length: > 0 } existing) return existing;

        await _unlockGate.WaitAsync(cancellationToken).ConfigureAwait(true);
        try
        {
            if (_bitwardenSession.SessionKey is { Length: > 0 } cached) return cached;

            var status = await _bitwarden.GetStatusAsync(cancellationToken).ConfigureAwait(true);
            if (status.Status == BitwardenVaultStatus.Unauthenticated)
            {
                throw new BitwardenVaultException("Bitwarden CLI is not logged in. Run bw login, then unlock the vault in Wormhole.", isAuthenticationError: true);
            }
            if (status.Status == BitwardenVaultStatus.Unlocked)
            {
                return null;
            }

            if (unlockPrompt is null)
            {
                throw new BitwardenVaultException("Bitwarden vault is locked.", isAuthenticationError: true);
            }

            var sessionKey = await unlockPrompt(_bitwarden.UnlockAsync, cancellationToken).ConfigureAwait(true);
            cancellationToken.ThrowIfCancellationRequested();
            if (sessionKey is null)
            {
                throw new BitwardenUnlockCancelledException();
            }

            _bitwardenSession.SetSessionKey(sessionKey);
            return sessionKey;
        }
        finally
        {
            _unlockGate.Release();
        }
    }
}
