using System.Security.Cryptography;
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

    public Task StorePasswordAsync(Guid credentialId, string password) =>
        Task.Run(() => CredentialManager.WriteCredential(
            applicationName: CredentialName(credentialId),
            userName: credentialId.ToString(),
            secret: password,
            comment: "Wormhole credential",
            persistence: CredentialPersistence.LocalMachine));

    public Task<string?> ReadPasswordAsync(Guid credentialId) =>
        Task.Run(() =>
        {
            var cred = CredentialManager.ReadCredential(CredentialName(credentialId));
            return cred?.Password;
        });

    public Task DeletePasswordAsync(Guid credentialId) =>
        Task.Run(() =>
        {
            try
            {
                CredentialManager.DeleteCredential(CredentialName(credentialId));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to delete credential {CredentialId} from Credential Manager.", credentialId);
            }
        });

    public Task StorePrivateKeyAsync(Guid credentialId, byte[] privateKeyBytes) =>
        WriteProtectedAsync(KeyPath(credentialId), privateKeyBytes);

    public Task<byte[]?> ReadPrivateKeyAsync(Guid credentialId) =>
        ReadProtectedAsync(KeyPath(credentialId));

    public Task DeletePrivateKeyAsync(Guid credentialId) =>
        DeleteFileIfExistsAsync(KeyPath(credentialId));

    public Task StoreTunnelConfigAsync(Guid tunnelConfigId, byte[] configBytes) =>
        WriteProtectedAsync(TunnelConfigPath(tunnelConfigId), configBytes);

    public Task<byte[]?> ReadTunnelConfigAsync(Guid tunnelConfigId) =>
        ReadProtectedAsync(TunnelConfigPath(tunnelConfigId));

    public Task DeleteTunnelConfigAsync(Guid tunnelConfigId) =>
        DeleteFileIfExistsAsync(TunnelConfigPath(tunnelConfigId));

    private static async Task WriteProtectedAsync(string path, byte[] data)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var protectedBlob = await Task.Run(() =>
            ProtectedData.Protect(data, optionalEntropy: null, DataProtectionScope.CurrentUser)).ConfigureAwait(false);
        await File.WriteAllBytesAsync(path, protectedBlob).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadProtectedAsync(string path)
    {
        byte[] protectedBlob;
        try
        {
            protectedBlob = await File.ReadAllBytesAsync(path).ConfigureAwait(false);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }

        return await Task.Run(() =>
            ProtectedData.Unprotect(protectedBlob, optionalEntropy: null, DataProtectionScope.CurrentUser)).ConfigureAwait(false);
    }

    private static Task DeleteFileIfExistsAsync(string path) =>
        Task.Run(() =>
        {
            try
            {
                File.Delete(path);
            }
            catch (FileNotFoundException)
            {
            }
            catch (DirectoryNotFoundException)
            {
            }
        });

    private static string CredentialName(Guid credentialId) => CredentialPrefix + credentialId;

    private static string KeyPath(Guid credentialId) =>
        Path.Combine(AppPaths.GetKeysDirectory(), credentialId.ToString("N") + ".dpapi");

    private static string TunnelConfigPath(Guid tunnelConfigId) =>
        Path.Combine(AppPaths.GetTunnelConfigsDirectory(), tunnelConfigId.ToString("N") + ".dpapi");
}
