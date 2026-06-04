using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;
using Wormhole.Services.Tunneling.Stormshield;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// In-memory <see cref="IStormshieldConfigCache"/> for tests. Stores records by tunnel Id (bypassing the
/// real DPAPI / site-identity / max-age machinery, which the concrete cache owns), and counts calls so
/// tests can assert whether a download was avoided (cache hit) or performed + persisted (cache miss).
/// </summary>
internal sealed class FakeStormshieldConfigCache : IStormshieldConfigCache
{
    private readonly Dictionary<Guid, StormshieldCacheRecord> _store = new();

    public int ReadCalls { get; private set; }
    public int WriteCalls { get; private set; }
    public int DeleteCalls { get; private set; }
    public StormshieldCacheRecord? LastWritten { get; private set; }

    public void Seed(Guid id, string configHash, string profileOvpn) =>
        _store[id] = new StormshieldCacheRecord
        {
            ConfigHash = configHash,
            ProfileOvpn = profileOvpn,
            CachedAtUtc = DateTimeOffset.UtcNow,
        };

    public Task<StormshieldCacheRecord?> TryReadAsync(
        Guid tunnelConfigId, StormshieldSettings settings, CancellationToken cancellationToken)
    {
        ReadCalls++;
        return Task.FromResult(_store.TryGetValue(tunnelConfigId, out var record) ? record : null);
    }

    public Task WriteAsync(
        Guid tunnelConfigId, StormshieldSettings settings, string configHash, string profileOvpn,
        CancellationToken cancellationToken)
    {
        WriteCalls++;
        var record = new StormshieldCacheRecord
        {
            ConfigHash = configHash,
            ProfileOvpn = profileOvpn,
            CachedAtUtc = DateTimeOffset.UtcNow,
        };
        _store[tunnelConfigId] = record;
        LastWritten = record;
        return Task.CompletedTask;
    }

    public Task DeleteAsync(Guid tunnelConfigId, CancellationToken cancellationToken)
    {
        DeleteCalls++;
        _store.Remove(tunnelConfigId);
        return Task.CompletedTask;
    }
}
