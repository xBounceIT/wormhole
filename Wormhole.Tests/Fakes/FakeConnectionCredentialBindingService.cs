using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.Tests.Fakes;

public sealed class FakeConnectionCredentialBindingService : IConnectionCredentialBindingService
{
    public int SaveCount { get; private set; }
    public Guid? LastNodeId { get; private set; }
    public CredentialProfile? LastCredential { get; private set; }
    public CancellationToken LastCancellationToken { get; private set; }

    public Task SaveCredentialBindingAsync(
        Guid nodeId,
        CredentialProfile credential,
        CancellationToken cancellationToken = default)
    {
        SaveCount++;
        LastNodeId = nodeId;
        LastCredential = credential;
        LastCancellationToken = cancellationToken;
        return Task.CompletedTask;
    }
}
