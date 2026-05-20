using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
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

        await connection.ExecuteAsync(@"
            CREATE TABLE IF NOT EXISTS __migration_history (
                Id TEXT PRIMARY KEY NOT NULL,
                AppliedAtUtc TEXT NOT NULL
            );");

        var applied = (await connection.QueryAsync<string>(
            "SELECT Id FROM __migration_history;")).ToHashSet(StringComparer.Ordinal);

        var pending = _migrations.Where(m => !applied.Contains(m.Id)).ToList();

        foreach (var migration in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogInformation("Applying migration {Id}", migration.Id);
            using var tx = connection.BeginTransaction();
            try
            {
                await connection.ExecuteAsync(migration.Sql, transaction: tx);
                await connection.ExecuteAsync(
                    "INSERT INTO __migration_history (Id, AppliedAtUtc) VALUES (@Id, @AppliedAtUtc);",
                    new { migration.Id, AppliedAtUtc = DateTime.UtcNow.ToString("O") },
                    transaction: tx);
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
