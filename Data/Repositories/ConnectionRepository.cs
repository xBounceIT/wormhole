using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public sealed class ConnectionRepository : IConnectionRepository
{
    private const string SelectColumns = @"
        Id, ParentId, Name, Kind, SortOrder,
        Protocol, Host, Port, Username, CredentialId,
        RdpDomain, RdpScreenSize, RdpFullScreen,
        SshKeyFileName, SshKnownHostFingerprint,
        CreatedAt, UpdatedAt";

    private readonly ISqliteConnectionFactory _factory;

    public ConnectionRepository(ISqliteConnectionFactory factory)
    {
        _factory = factory;
    }

    public async Task<IReadOnlyList<ConnectionNode>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        var rows = await connection.QueryAsync<ConnectionNode>(new CommandDefinition(
            $"SELECT {SelectColumns} FROM Nodes ORDER BY SortOrder, Name;",
            cancellationToken: cancellationToken));
        return rows.ToList();
    }

    public async Task<ConnectionNode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        return await connection.QuerySingleOrDefaultAsync<ConnectionNode>(new CommandDefinition(
            $"SELECT {SelectColumns} FROM Nodes WHERE Id = @id;",
            new { id },
            cancellationToken: cancellationToken));
    }

    public async Task AddAsync(ConnectionNode node, CancellationToken cancellationToken = default)
    {
        node.CreatedAt = DateTime.UtcNow;
        node.UpdatedAt = node.CreatedAt;
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(@"
            INSERT INTO Nodes (
                Id, ParentId, Name, Kind, SortOrder,
                Protocol, Host, Port, Username, CredentialId,
                RdpDomain, RdpScreenSize, RdpFullScreen,
                SshKeyFileName, SshKnownHostFingerprint,
                CreatedAt, UpdatedAt
            ) VALUES (
                @Id, @ParentId, @Name, @Kind, @SortOrder,
                @Protocol, @Host, @Port, @Username, @CredentialId,
                @RdpDomain, @RdpScreenSize, @RdpFullScreen,
                @SshKeyFileName, @SshKnownHostFingerprint,
                @CreatedAt, @UpdatedAt
            );", node, cancellationToken: cancellationToken));
    }

    public async Task UpdateAsync(ConnectionNode node, CancellationToken cancellationToken = default)
    {
        node.UpdatedAt = DateTime.UtcNow;
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(@"
            UPDATE Nodes SET
                ParentId = @ParentId,
                Name = @Name,
                Kind = @Kind,
                SortOrder = @SortOrder,
                Protocol = @Protocol,
                Host = @Host,
                Port = @Port,
                Username = @Username,
                CredentialId = @CredentialId,
                RdpDomain = @RdpDomain,
                RdpScreenSize = @RdpScreenSize,
                RdpFullScreen = @RdpFullScreen,
                SshKeyFileName = @SshKeyFileName,
                SshKnownHostFingerprint = @SshKnownHostFingerprint,
                UpdatedAt = @UpdatedAt
            WHERE Id = @Id;", node, cancellationToken: cancellationToken));
    }

    public async Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, CancellationToken cancellationToken = default)
    {
        if (nodeId == Guid.Empty) throw new ArgumentException("nodeId must not be empty.", nameof(nodeId));
        if (string.IsNullOrWhiteSpace(fingerprint))
            throw new ArgumentException("fingerprint must be a non-empty string.", nameof(fingerprint));

        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE Nodes SET SshKnownHostFingerprint = @fingerprint, UpdatedAt = @now WHERE Id = @nodeId;",
            new { nodeId, fingerprint, now = DateTime.UtcNow },
            cancellationToken: cancellationToken));
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM Nodes WHERE Id = @id;",
            new { id },
            cancellationToken: cancellationToken));
    }
}
