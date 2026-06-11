using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Tests.Fakes;

public sealed class FakeTunnelConfigRepository : ITunnelConfigRepository
{
    public Dictionary<Guid, TunnelConfig> Configs { get; } = new();
    public int GetAllCallCount { get; private set; }

    /// <summary>Invoked at the start of every <see cref="UpdateAsync"/> call (before the row is
    /// stored), so a test can observe the sequence of row writes — e.g. assert the UpdatedAt-bump
    /// write lands only after the secret payload was stored.</summary>
    public Action<TunnelConfig>? OnUpdate { get; set; }

    public Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        GetAllCallCount++;
        return Task.FromResult<IReadOnlyList<TunnelConfig>>(Configs.Values.ToList());
    }

    public Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        Task.FromResult(Configs.TryGetValue(id, out var c) ? c : null);

    public Task AddAsync(TunnelConfig config, CancellationToken cancellationToken = default)
    {
        Configs[config.Id] = config;
        return Task.CompletedTask;
    }

    public Task UpdateAsync(TunnelConfig config, CancellationToken cancellationToken = default)
    {
        // OnUpdate reads the config's values synchronously here, before the ViewModel can mutate the
        // (reused) snapshot for a later write — so observing the call sequence stays accurate.
        OnUpdate?.Invoke(config);
        Configs[config.Id] = config;
        return Task.CompletedTask;
    }

    public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        Configs.Remove(id);
        return Task.CompletedTask;
    }
}
