using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public interface IConnectionRepository
{
    Task<IReadOnlyList<ConnectionNode>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<ConnectionNode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    /// <summary>
    /// Returns up to <paramref name="limit"/> (Id, Name) pairs for nodes referencing the given
    /// tunnel config. Lets the tunnel-delete reference check avoid pulling every row of Nodes
    /// off SQLite just to count + name three offending connections.
    /// </summary>
    Task<IReadOnlyList<(Guid Id, string Name)>> GetByTunnelConfigIdAsync(Guid tunnelConfigId, int limit, CancellationToken cancellationToken = default);
    Task AddAsync(ConnectionNode node, CancellationToken cancellationToken = default);
    Task UpdateAsync(ConnectionNode node, CancellationToken cancellationToken = default);
    Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, CancellationToken cancellationToken = default);
    Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
}
