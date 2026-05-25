using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Wormhole.Services;

namespace Wormhole.Tests.Fakes;

/// Shared in-memory <see cref="ICredentialService"/> for tests. Replaces three near-identical
/// copies that lived inline in test files. Each backing dictionary is exposed so tests can
/// pre-populate or assert against it.
/// </summary>
public sealed class FakeCredentialService : ICredentialService
{
    public Dictionary<Guid, string> Passwords { get; } = new();
    public Dictionary<Guid, byte[]> PrivateKeys { get; } = new();
    public Dictionary<Guid, byte[]> TunnelConfigs { get; } = new();
    public HashSet<Guid> CorruptPrivateKeyIds { get; } = new();
    public HashSet<Guid> CorruptTunnelConfigIds { get; } = new();

    public FakeCredentialService(
        Dictionary<Guid, string>? passwords = null,
        Dictionary<Guid, byte[]>? keys = null,
        Dictionary<Guid, byte[]>? tunnelConfigs = null)
    {
        if (passwords is not null) foreach (var kv in passwords) Passwords[kv.Key] = kv.Value;
        if (keys is not null) foreach (var kv in keys) PrivateKeys[kv.Key] = kv.Value;
        if (tunnelConfigs is not null) foreach (var kv in tunnelConfigs) TunnelConfigs[kv.Key] = kv.Value;
    }

    public Task StorePasswordAsync(Guid credentialId, string password) { Passwords[credentialId] = password; return Task.CompletedTask; }
    public Task<string?> ReadPasswordAsync(Guid credentialId) =>
        Task.FromResult(Passwords.TryGetValue(credentialId, out var p) ? p : null);
    public Task DeletePasswordAsync(Guid credentialId) { Passwords.Remove(credentialId); return Task.CompletedTask; }

    // Production CredentialService.StorePrivateKeyAsync hands the bytes to ProtectedData.Protect
    // which copies before returning, so callers are free to zero/reuse the input array. Mirror
    // that contract here with an explicit defensive copy so tests reflect the real lifetime,
    // not an aliased reference.
    public Task StorePrivateKeyAsync(Guid credentialId, byte[] privateKeyBytes)
    {
        CorruptPrivateKeyIds.Remove(credentialId);
        PrivateKeys[credentialId] = (byte[])privateKeyBytes.Clone();
        return Task.CompletedTask;
    }
    // Clone on Read too — production ReadProtectedAsync returns a fresh ProtectedData.Unprotect
    // buffer per call, so callers are free to zero/mutate the result. The fake must match that
    // lifetime contract or callers that zero the returned bytes corrupt the in-memory dict.
    public Task<byte[]?> ReadPrivateKeyAsync(Guid credentialId)
    {
        if (CorruptPrivateKeyIds.Contains(credentialId))
        {
            throw new CryptographicException("simulated corrupt private key blob");
        }
        return Task.FromResult(PrivateKeys.TryGetValue(credentialId, out var b) ? (byte[]?)b.Clone() : null);
    }
    public Task DeletePrivateKeyAsync(Guid credentialId)
    {
        CorruptPrivateKeyIds.Remove(credentialId);
        PrivateKeys.Remove(credentialId);
        return Task.CompletedTask;
    }

    /// <summary>Set true to make <see cref="StoreTunnelConfigAsync"/> throw — drives the
    /// VM's compensate-on-failure rollback path under test.</summary>
    public bool ThrowOnStoreTunnelConfig { get; set; }

    public Task StoreTunnelConfigAsync(Guid tunnelConfigId, byte[] configBytes)
    {
        if (ThrowOnStoreTunnelConfig) throw new InvalidOperationException("simulated secret write failure");
        // Defensive copy — production CredentialService passes the bytes through DPAPI.Protect
        // before retaining anything, so callers can zero the input.
        CorruptTunnelConfigIds.Remove(tunnelConfigId);
        TunnelConfigs[tunnelConfigId] = (byte[])configBytes.Clone();
        return Task.CompletedTask;
    }
    public Task<byte[]?> ReadTunnelConfigAsync(Guid tunnelConfigId)
    {
        if (CorruptTunnelConfigIds.Contains(tunnelConfigId))
        {
            throw new CryptographicException("simulated corrupt tunnel config blob");
        }
        return Task.FromResult(TunnelConfigs.TryGetValue(tunnelConfigId, out var b) ? (byte[]?)b.Clone() : null);
    }
    public Task DeleteTunnelConfigAsync(Guid tunnelConfigId)
    {
        CorruptTunnelConfigIds.Remove(tunnelConfigId);
        TunnelConfigs.Remove(tunnelConfigId);
        return Task.CompletedTask;
    }
}
