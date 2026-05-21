using Dapper;
using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public sealed class ConnectionRepository : IConnectionRepository
{
    /// <summary>
    /// Canonical column list — the single source of truth used to derive every SQL fragment
    /// (SELECT, INSERT cols, INSERT @params, UPDATE col=@col). Adding a column means editing
    /// only this array (and the migration). Order matters only for the SELECT projection;
    /// Dapper materialisation is by-name.
    /// </summary>
    private static readonly string[] Columns =
    {
        "Id", "ParentId", "Name", "Kind", "SortOrder",
        "Protocol", "Host", "Port", "Username", "CredentialId",
        "RdpDomain", "RdpScreenSize", "RdpFullScreen",
        "RdpColorDepth", "RdpUseAllMonitors",
        "RdpAudioMode", "RdpAudioCaptureMode", "RdpKeyboardHookMode",
        "RdpRedirectClipboard", "RdpRedirectPrinters", "RdpRedirectSmartCards",
        "RdpRedirectPorts", "RdpRedirectDevices", "RdpRedirectDrives",
        "RdpConnectionSpeed", "RdpDesktopBackground", "RdpFontSmoothing",
        "RdpDesktopComposition", "RdpWindowDrag", "RdpMenuAnimation",
        "RdpVisualStyles", "RdpBitmapCaching", "RdpAutoReconnect",
        "RdpServerAuthentication", "RdpGatewayUsageMethod", "RdpGatewayHostname",
        "RdpGatewayCredentialId", "RdpGatewayBypassLocal", "RdpGatewayUseSameCreds",
        "SshKeyFileName", "SshKnownHostFingerprint",
        "CreatedAt", "UpdatedAt",
    };

    /// <summary>Columns excluded from UPDATE SET (identity / create-time).</summary>
    private static readonly HashSet<string> UpdateExcluded = new(StringComparer.Ordinal)
    {
        "Id", "CreatedAt",
    };

    private static readonly string SelectColumns = string.Join(", ", Columns);
    private static readonly string InsertParameters = string.Join(", ", Columns.Select(c => "@" + c));
    private static readonly string UpdateAssignments = string.Join(", ",
        Columns.Where(c => !UpdateExcluded.Contains(c)).Select(c => $"{c} = @{c}"));

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
        await connection.ExecuteAsync(new CommandDefinition(
            $"INSERT INTO Nodes ({SelectColumns}) VALUES ({InsertParameters});",
            node,
            cancellationToken: cancellationToken));
    }

    public async Task UpdateAsync(ConnectionNode node, CancellationToken cancellationToken = default)
    {
        node.UpdatedAt = DateTime.UtcNow;
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(
            $"UPDATE Nodes SET {UpdateAssignments} WHERE Id = @Id;",
            node,
            cancellationToken: cancellationToken));
    }

    public async Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, CancellationToken cancellationToken = default)
    {
        if (nodes.Count == 0) return;
        var now = DateTime.UtcNow;
        foreach (var node in nodes) node.UpdatedAt = now;

        using var connection = _factory.Open();
        using var tx = connection.BeginTransaction();
        await connection.ExecuteAsync(new CommandDefinition(
            $"UPDATE Nodes SET {UpdateAssignments} WHERE Id = @Id;",
            nodes,
            transaction: tx,
            cancellationToken: cancellationToken));
        tx.Commit();
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
