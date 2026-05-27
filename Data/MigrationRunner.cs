using System.Reflection;
using Dapper;
using Microsoft.Extensions.Logging;

namespace Wormhole.Data;

/// <summary>
/// Applies pending SQL migrations in alphabetical order, tracking applied IDs in
/// a <c>__migration_history</c> table. Migrations are discovered as embedded resources
/// named <c>Wormhole.Data.Migrations.*.sql</c> by default; tests can pass explicit migrations.
/// </summary>
public sealed class MigrationRunner
{
    private const string ResourcePrefix = "Wormhole.Data.Migrations.";

    private readonly ISqliteConnectionFactory _factory;
    private readonly ILogger<MigrationRunner> _logger;
    private readonly IReadOnlyList<Migration> _migrations;

    public MigrationRunner(ISqliteConnectionFactory factory, ILogger<MigrationRunner> logger)
        : this(factory, logger, LoadEmbeddedMigrations(typeof(MigrationRunner).Assembly))
    {
    }

    // Test-friendly constructor that lets callers pass explicit migrations.
    public MigrationRunner(
        ISqliteConnectionFactory factory,
        ILogger<MigrationRunner> logger,
        IReadOnlyList<Migration> migrations)
    {
        _factory = factory;
        _logger = logger;
        _migrations = migrations;
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();

        await connection.ExecuteAsync(new CommandDefinition(@"
            CREATE TABLE IF NOT EXISTS __migration_history (
                Id TEXT PRIMARY KEY NOT NULL,
                AppliedAtUtc TEXT NOT NULL
            );",
            cancellationToken: cancellationToken));

        var appliedRows = await connection.QueryAsync<string>(new CommandDefinition(
            "SELECT Id FROM __migration_history;",
            cancellationToken: cancellationToken));
        var applied = new HashSet<string>(StringComparer.Ordinal);
        foreach (var id in appliedRows)
        {
            applied.Add(id);
        }

        var pending = new List<Migration>(_migrations.Count);
        foreach (var migration in _migrations)
        {
            if (!applied.Contains(migration.Id))
            {
                pending.Add(migration);
            }
        }

        foreach (var migration in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogInformation("Applying migration {Id}", migration.Id);
            using var tx = connection.BeginTransaction();
            try
            {
                await connection.ExecuteAsync(new CommandDefinition(
                    migration.Sql,
                    transaction: tx,
                    cancellationToken: cancellationToken));
                await connection.ExecuteAsync(new CommandDefinition(
                    "INSERT INTO __migration_history (Id, AppliedAtUtc) VALUES (@Id, @AppliedAtUtc);",
                    new { migration.Id, AppliedAtUtc = DateTime.UtcNow.ToString("O") },
                    transaction: tx,
                    cancellationToken: cancellationToken));
                tx.Commit();
            }
            catch
            {
                tx.Rollback();
                throw;
            }
        }
    }

    public static IReadOnlyList<Migration> LoadEmbeddedMigrations(Assembly assembly)
    {
        var results = new List<Migration>();
        foreach (var name in assembly.GetManifestResourceNames())
        {
            if (!name.StartsWith(ResourcePrefix, StringComparison.Ordinal)) continue;
            if (!name.EndsWith(".sql", StringComparison.OrdinalIgnoreCase)) continue;

            using var stream = assembly.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException($"Could not open migration resource '{name}'.");
            using var reader = new StreamReader(stream);
            var sql = reader.ReadToEnd();
            var id = name.Substring(ResourcePrefix.Length, name.Length - ResourcePrefix.Length - 4);
            results.Add(new Migration(id, sql));
        }
        results.Sort((a, b) => string.CompareOrdinal(a.Id, b.Id));
        return results;
    }
}

public sealed record Migration(string Id, string Sql);
