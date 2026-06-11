using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public sealed class TunnelConfigRepository : ITunnelConfigRepository
{
    private const string SelectColumns = "Id, Name, Kind, CreatedAt, UpdatedAt";

    private readonly ISqliteConnectionFactory _factory;

    public TunnelConfigRepository(ISqliteConnectionFactory factory)
    {
        _factory = factory;
    }

    public async Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        var rows = await connection.QueryAsync<TunnelConfig>(new CommandDefinition(
            $"SELECT {SelectColumns} FROM TunnelConfigs ORDER BY Name;",
            cancellationToken: cancellationToken));
        return rows as IReadOnlyList<TunnelConfig> ?? rows.ToList();
    }

    public async Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        return await connection.QuerySingleOrDefaultAsync<TunnelConfig>(new CommandDefinition(
            $"SELECT {SelectColumns} FROM TunnelConfigs WHERE Id = @id;",
            new { id },
            cancellationToken: cancellationToken));
    }

    public async Task AddAsync(TunnelConfig config, CancellationToken cancellationToken = default)
    {
        config.CreatedAt = DateTime.UtcNow;
        config.UpdatedAt = config.CreatedAt;
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(@"
            INSERT INTO TunnelConfigs (Id, Name, Kind, CreatedAt, UpdatedAt)
            VALUES (@Id, @Name, @Kind, @CreatedAt, @UpdatedAt);",
            config,
            cancellationToken: cancellationToken));
    }

    // Persists the caller-supplied UpdatedAt verbatim — it does NOT stamp "now" itself. That timing
    // is load-bearing: TunnelManager's shared-tunnel pool snapshots UpdatedAt to detect config edits,
    // and the edit must become visible to the pool only AFTER the new DPAPI payload is on disk, or a
    // connection starting mid-save would cache the old payload under the new timestamp. So
    // TunnelConfigsViewModel writes the row (Name/Kind) with the OLD timestamp first, stores the
    // payload, then calls UpdateAsync again with a freshly bumped timestamp to publish the change.
    // Auto-stamping "now" here would reintroduce that race.
    public async Task UpdateAsync(TunnelConfig config, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(@"
            UPDATE TunnelConfigs SET
                Name = @Name,
                Kind = @Kind,
                UpdatedAt = @UpdatedAt
            WHERE Id = @Id;",
            config,
            cancellationToken: cancellationToken));
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM TunnelConfigs WHERE Id = @id;",
            new { id },
            cancellationToken: cancellationToken));
    }
}
