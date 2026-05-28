using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// In-memory <see cref="ICredentialRepository"/> for tests. The backing dictionary is exposed
/// so tests can pre-populate credential metadata (notably <see cref="CredentialProfile.Kind"/>).
/// </summary>
public sealed class FakeCredentialRepository : ICredentialRepository
{
    public Dictionary<Guid, CredentialProfile> Credentials { get; } = new();

    public FakeCredentialRepository(params CredentialProfile[] seed)
    {
        foreach (var profile in seed) Credentials[profile.Id] = profile;
    }

    public Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<CredentialProfile>>(Credentials.Values.ToList());

    public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        Task.FromResult(Credentials.TryGetValue(id, out var p) ? p : null);

    public Task AddAsync(CredentialProfile profile, CancellationToken cancellationToken = default)
    {
        Credentials[profile.Id] = profile;
        return Task.CompletedTask;
    }

    public Task UpdateAsync(CredentialProfile profile, CancellationToken cancellationToken = default)
    {
        Credentials[profile.Id] = profile;
        return Task.CompletedTask;
    }

    public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        Credentials.Remove(id);
        return Task.CompletedTask;
    }
}
