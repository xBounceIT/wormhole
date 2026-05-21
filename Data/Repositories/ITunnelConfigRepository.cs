using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public interface ITunnelConfigRepository
{
    Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task AddAsync(TunnelConfig config, CancellationToken cancellationToken = default);
    Task UpdateAsync(TunnelConfig config, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
}
