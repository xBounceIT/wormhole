using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Meziantou.Framework.Win32;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;

namespace Wormhole.Services;

public sealed class CredentialService : ICredentialService
{
    private const string CredentialPrefix = "Wormhole:";

    private readonly ILogger<CredentialService> _logger;

    public CredentialService(ILogger<CredentialService> logger)
    {
        _logger = logger;
    }

    public Task StorePasswordAsync(Guid credentialId, string password)
    {
        CredentialManager.WriteCredential(
            applicationName: CredentialName(credentialId),
            userName: credentialId.ToString(),
            secret: password,
            comment: "Wormhole credential",
            persistence: CredentialPersistence.LocalMachine);
        return Task.CompletedTask;
    }

    public Task<string?> ReadPasswordAsync(Guid credentialId)
    {
        var cred = CredentialManager.ReadCredential(CredentialName(credentialId));
        return Task.FromResult(cred?.Password);
    }

    public Task DeletePasswordAsync(Guid credentialId)
    {
        try
        {
            CredentialManager.DeleteCredential(CredentialName(credentialId));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete credential {CredentialId} from Credential Manager.", credentialId);
        }
        return Task.CompletedTask;
    }

    public async Task StorePrivateKeyAsync(Guid credentialId, byte[] privateKeyBytes)
    {
        Directory.CreateDirectory(AppPaths.GetKeysDirectory());
        var protectedBlob = ProtectedData.Protect(privateKeyBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        await File.WriteAllBytesAsync(KeyPath(credentialId), protectedBlob);
    }

    public async Task<byte[]?> ReadPrivateKeyAsync(Guid credentialId)
    {
        try
        {
            var protectedBlob = await File.ReadAllBytesAsync(KeyPath(credentialId));
            return ProtectedData.Unprotect(protectedBlob, optionalEntropy: null, DataProtectionScope.CurrentUser);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    public Task DeletePrivateKeyAsync(Guid credentialId)
    {
        try
        {
            File.Delete(KeyPath(credentialId));
        }
        catch (FileNotFoundException)
        {
        }
        catch (DirectoryNotFoundException)
        {
        }
        return Task.CompletedTask;
    }

    private static string CredentialName(Guid credentialId) => CredentialPrefix + credentialId;

    private static string KeyPath(Guid credentialId) =>
        Path.Combine(AppPaths.GetKeysDirectory(), credentialId.ToString("N") + ".dpapi");
}
