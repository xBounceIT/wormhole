using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public interface IConnectionRepository
{
    Task<IReadOnlyList<ConnectionNode>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<ConnectionNode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task AddAsync(ConnectionNode node, CancellationToken cancellationToken = default);
    Task UpdateAsync(ConnectionNode node, CancellationToken cancellationToken = default);
    Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, CancellationToken cancellationToken = default);
    Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
}
