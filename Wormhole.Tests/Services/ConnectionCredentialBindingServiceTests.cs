using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services;

public class ConnectionCredentialBindingServiceTests
{
    [Fact]
    public async Task SaveCredentialBindingAsync_UpdatesLeafNodeAndClearsInlineSecret()
    {
        var nodeId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var node = new ConnectionNode
        {
            Id = nodeId,
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Rdp,
            Username = "old-user",
            RdpDomain = "OLD",
            CredentialMode = CredentialBindingMode.None,
            UseInlinePassword = true,
        };
        var repo = new RecordingConnectionRepository(node);
        var secrets = new FakeCredentialService(new Dictionary<Guid, string> { [nodeId] = "inline-secret" });
        var service = new ConnectionCredentialBindingService(
            repo,
            secrets,
            NullLogger<ConnectionCredentialBindingService>.Instance);

        await service.SaveCredentialBindingAsync(
            nodeId,
            new CredentialProfile
            {
                Id = credentialId,
                Protocol = ProtocolType.Rdp,
                Kind = CredentialKind.Password,
                Username = "saved-user",
                Domain = "CORP",
            });

        Assert.Equal(1, repo.UpdateCount);
        Assert.Equal(credentialId, node.CredentialId);
        Assert.Equal(CredentialBindingMode.Saved, node.CredentialMode);
        Assert.False(node.UseInlinePassword);
        Assert.Equal("saved-user", node.Username);
        Assert.Equal("CORP", node.RdpDomain);
        Assert.False(secrets.Passwords.ContainsKey(nodeId));
    }

    private sealed class RecordingConnectionRepository : IConnectionRepository
    {
        private readonly ConnectionNode _node;

        public RecordingConnectionRepository(ConnectionNode node) => _node = node;

        public int UpdateCount { get; private set; }

        public Task<IReadOnlyList<ConnectionNode>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ConnectionNode>>(new[] { _node });

        public Task<ConnectionNode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
            Task.FromResult<ConnectionNode?>(id == _node.Id ? _node : null);

        public Task<IReadOnlyList<(Guid Id, string Name)>> GetByTunnelConfigIdAsync(
            Guid tunnelConfigId,
            int limit,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<(Guid, string)>>(Array.Empty<(Guid, string)>());

        public Task AddAsync(ConnectionNode node, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task UpdateAsync(ConnectionNode node, CancellationToken cancellationToken = default)
        {
            UpdateCount++;
            return Task.CompletedTask;
        }

        public Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteManyAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
