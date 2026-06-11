using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;
using Wormhole.Services.Tunneling.AzureVpn;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// In-memory <see cref="IAzureVpnTokenCache"/> for tests. Stores refresh tokens by tunnel Id
/// (bypassing the real DPAPI / identity-hash / max-age machinery, which the concrete cache owns),
/// and counts calls so tests can assert whether the silent-refresh path was taken and whether a
/// granted token was persisted.
/// </summary>
internal sealed class FakeAzureVpnTokenCache : IAzureVpnTokenCache
{
    private readonly Dictionary<Guid, string> _store = new();

    public int ReadCalls { get; private set; }
    public int WriteCalls { get; private set; }
    public int DeleteCalls { get; private set; }
    public string? LastWritten { get; private set; }

    /// <summary>When set, <see cref="WriteAsync"/> throws — exercises the best-effort write path.</summary>
    public bool FailWrites { get; set; }

    public void Seed(Guid id, string refreshToken) => _store[id] = refreshToken;

    public Task<string?> TryReadAsync(Guid tunnelConfigId, AzureVpnSettings settings, CancellationToken cancellationToken)
    {
        ReadCalls++;
        return Task.FromResult(_store.TryGetValue(tunnelConfigId, out var token) ? token : null);
    }

    public Task WriteAsync(Guid tunnelConfigId, AzureVpnSettings settings, string refreshToken, CancellationToken cancellationToken)
    {
        WriteCalls++;
        if (FailWrites) throw new InvalidOperationException("simulated cache write failure");
        _store[tunnelConfigId] = refreshToken;
        LastWritten = refreshToken;
        return Task.CompletedTask;
    }

    public Task DeleteAsync(Guid tunnelConfigId, CancellationToken cancellationToken)
    {
        DeleteCalls++;
        _store.Remove(tunnelConfigId);
        return Task.CompletedTask;
    }
}
