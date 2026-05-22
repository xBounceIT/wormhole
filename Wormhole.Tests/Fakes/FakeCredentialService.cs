using System;
using System.Collections.Generic;
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

    public Task StorePrivateKeyAsync(Guid credentialId, byte[] privateKeyBytes) { PrivateKeys[credentialId] = privateKeyBytes; return Task.CompletedTask; }
    public Task<byte[]?> ReadPrivateKeyAsync(Guid credentialId) =>
        Task.FromResult(PrivateKeys.TryGetValue(credentialId, out var b) ? b : null);
    public Task DeletePrivateKeyAsync(Guid credentialId) { PrivateKeys.Remove(credentialId); return Task.CompletedTask; }

    /// <summary>Set true to make <see cref="StoreTunnelConfigAsync"/> throw — drives the
    /// VM's compensate-on-failure rollback path under test.</summary>
    public bool ThrowOnStoreTunnelConfig { get; set; }

    public Task StoreTunnelConfigAsync(Guid tunnelConfigId, byte[] configBytes)
    {
        if (ThrowOnStoreTunnelConfig) throw new InvalidOperationException("simulated secret write failure");
        TunnelConfigs[tunnelConfigId] = configBytes;
        return Task.CompletedTask;
    }
    public Task<byte[]?> ReadTunnelConfigAsync(Guid tunnelConfigId) =>
        Task.FromResult(TunnelConfigs.TryGetValue(tunnelConfigId, out var b) ? b : null);
    public Task DeleteTunnelConfigAsync(Guid tunnelConfigId) { TunnelConfigs.Remove(tunnelConfigId); return Task.CompletedTask; }
}
