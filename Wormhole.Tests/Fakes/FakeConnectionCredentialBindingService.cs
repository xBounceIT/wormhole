using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.Tests.Fakes;

public sealed class FakeConnectionCredentialBindingService : IConnectionCredentialBindingService
{
    public int SaveCount { get; private set; }
    public int SaveInlineCount { get; private set; }
    public Guid? LastNodeId { get; private set; }
    public CredentialProfile? LastCredential { get; private set; }
    public string? LastInlinePassword { get; private set; }
    public string? LastInlineUsername { get; private set; }
    public string? LastInlineRdpDomain { get; private set; }
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

    public Task SaveInlinePasswordAsync(
        Guid nodeId,
        string password,
        string? username = null,
        string? rdpDomain = null,
        CancellationToken cancellationToken = default)
    {
        SaveInlineCount++;
        LastNodeId = nodeId;
        LastInlinePassword = password;
        LastInlineUsername = username;
        LastInlineRdpDomain = rdpDomain;
        LastCancellationToken = cancellationToken;
        return Task.CompletedTask;
    }
}
