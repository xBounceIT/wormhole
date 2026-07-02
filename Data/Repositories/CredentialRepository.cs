using Dapper;
using Wormhole.Models;

namespace Wormhole.Data.Repositories;

public sealed class CredentialRepository : ICredentialRepository
{
    private const string SelectColumns = @"
        Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol,
        SecretProvider, BitwardenItemId, BitwardenItemName, BitwardenFieldPath,
        CreatedAt";

    private readonly ISqliteConnectionFactory _factory;

    public CredentialRepository(ISqliteConnectionFactory factory)
    {
        _factory = factory;
    }

    public async Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        var rows = await connection.QueryAsync<CredentialProfile>(new CommandDefinition(
            $"SELECT {SelectColumns} FROM CredentialProfiles ORDER BY Name;",
            cancellationToken: cancellationToken));
        return rows as IReadOnlyList<CredentialProfile> ?? rows.ToList();
    }

    public async Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        return await connection.QuerySingleOrDefaultAsync<CredentialProfile>(new CommandDefinition(
            $"SELECT {SelectColumns} FROM CredentialProfiles WHERE Id = @id;",
            new { id },
            cancellationToken: cancellationToken));
    }

    public async Task AddAsync(CredentialProfile profile, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(@"
            INSERT INTO CredentialProfiles
                (Id, Name, Username, Domain, Kind, PrivateKeyFileName, Protocol,
                 SecretProvider, BitwardenItemId, BitwardenItemName, BitwardenFieldPath, CreatedAt)
            VALUES
                (@Id, @Name, @Username, @Domain, @Kind, @PrivateKeyFileName, @Protocol,
                 @SecretProvider, @BitwardenItemId, @BitwardenItemName, @BitwardenFieldPath, @CreatedAt);",
            profile,
            cancellationToken: cancellationToken));
    }

    public async Task UpdateAsync(CredentialProfile profile, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(@"
            UPDATE CredentialProfiles SET
                Name = @Name,
                Username = @Username,
                Domain = @Domain,
                Kind = @Kind,
                PrivateKeyFileName = @PrivateKeyFileName,
                Protocol = @Protocol,
                SecretProvider = @SecretProvider,
                BitwardenItemId = @BitwardenItemId,
                BitwardenItemName = @BitwardenItemName,
                BitwardenFieldPath = @BitwardenFieldPath
            WHERE Id = @Id;",
            profile,
            cancellationToken: cancellationToken));
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM CredentialProfiles WHERE Id = @id;",
            new { id },
            cancellationToken: cancellationToken));
    }
}
