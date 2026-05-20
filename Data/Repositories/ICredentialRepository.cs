using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public interface ICredentialRepository
{
    Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task AddAsync(CredentialProfile profile, CancellationToken cancellationToken = default);
    Task UpdateAsync(CredentialProfile profile, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
}
