using System;
using System.Threading.Tasks;

namespace Wormhole.Services;

public interface ICredentialService
{
    Task StorePasswordAsync(Guid credentialId, string password);
    Task<string?> ReadPasswordAsync(Guid credentialId);
    Task DeletePasswordAsync(Guid credentialId);

    Task StorePrivateKeyAsync(Guid credentialId, byte[] privateKeyBytes);
    Task<byte[]?> ReadPrivateKeyAsync(Guid credentialId);
    Task DeletePrivateKeyAsync(Guid credentialId);
}
