using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Wormhole.Services;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// In-memory test double for <see cref="ICredentialService"/>. Construct with dictionaries
/// keyed by credential id for the passwords / private-key bytes that <c>ReadXxxAsync</c>
/// should return; the Store/Delete methods are no-ops (tests that care about persistence
/// drive the dictionaries directly).
/// </summary>
public sealed class FakeCredentialService : ICredentialService
{
    private readonly Dictionary<Guid, string> _passwords;
    private readonly Dictionary<Guid, byte[]> _keys;

    public FakeCredentialService(Dictionary<Guid, string>? passwords = null, Dictionary<Guid, byte[]>? keys = null)
    {
        _passwords = passwords ?? new();
        _keys = keys ?? new();
    }

    public Task StorePasswordAsync(Guid credentialId, string password)
    {
        _passwords[credentialId] = password;
        return Task.CompletedTask;
    }

    public Task<string?> ReadPasswordAsync(Guid credentialId)
        => Task.FromResult(_passwords.TryGetValue(credentialId, out var p) ? p : null);

    public Task DeletePasswordAsync(Guid credentialId)
    {
        _passwords.Remove(credentialId);
        return Task.CompletedTask;
    }

    public Task StorePrivateKeyAsync(Guid credentialId, byte[] privateKeyBytes)
    {
        _keys[credentialId] = privateKeyBytes;
        return Task.CompletedTask;
    }

    public Task<byte[]?> ReadPrivateKeyAsync(Guid credentialId)
        => Task.FromResult(_keys.TryGetValue(credentialId, out var b) ? b : null);

    public Task DeletePrivateKeyAsync(Guid credentialId)
    {
        _keys.Remove(credentialId);
        return Task.CompletedTask;
    }
}
