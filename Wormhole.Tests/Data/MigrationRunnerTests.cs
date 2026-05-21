using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data;
using Xunit;

namespace Wormhole.Tests.Data;

public class MigrationRunnerTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteConnectionFactory _factory;

    public MigrationRunnerTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"wormhole-test-{Guid.NewGuid():N}.db");
        _factory = new SqliteConnectionFactory($"Data Source={_dbPath}");
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    [Fact]
    public async Task RunAsync_AppliesAllPendingMigrations()
    {
        var migrations = new List<Migration>
        {
            new("0001_one", "CREATE TABLE t1 (Id INTEGER PRIMARY KEY);"),
            new("0002_two", "CREATE TABLE t2 (Id INTEGER PRIMARY KEY);"),
        };
        var runner = new MigrationRunner(_factory, NullLogger<MigrationRunner>.Instance, migrations);

        await runner.RunAsync();

        using var conn = _factory.Open();
        var tables = (await conn.QueryAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"))
            .ToList();
        Assert.Contains("t1", tables);
        Assert.Contains("t2", tables);
        Assert.Contains("__migration_history", tables);

        var applied = (await conn.QueryAsync<string>(
            "SELECT Id FROM __migration_history ORDER BY Id;")).ToList();
        Assert.Equal(new[] { "0001_one", "0002_two" }, applied);
    }

    [Fact]
    public async Task RunAsync_IsIdempotent_DoesNotReapplyMigrations()
    {
        var migrations = new List<Migration>
        {
            new("0001_one", "CREATE TABLE t1 (Id INTEGER PRIMARY KEY);"),
        };
        var runner = new MigrationRunner(_factory, NullLogger<MigrationRunner>.Instance, migrations);

        await runner.RunAsync();
        // Second run would fail (CREATE TABLE t1 again) if the runner re-applied.
        await runner.RunAsync();

        using var conn = _factory.Open();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM __migration_history WHERE Id = '0001_one';");
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task RunAsync_AppliesNewMigrationsOnSecondRun()
    {
        var firstRun = new List<Migration>
        {
            new("0001_one", "CREATE TABLE t1 (Id INTEGER PRIMARY KEY);"),
        };
        await new MigrationRunner(_factory, NullLogger<MigrationRunner>.Instance, firstRun).RunAsync();

        var secondRun = new List<Migration>
        {
            new("0001_one", "CREATE TABLE t1 (Id INTEGER PRIMARY KEY);"),
            new("0002_two", "CREATE TABLE t2 (Id INTEGER PRIMARY KEY);"),
        };
        await new MigrationRunner(_factory, NullLogger<MigrationRunner>.Instance, secondRun).RunAsync();

        using var conn = _factory.Open();
        var tables = (await conn.QueryAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"))
            .ToList();
        Assert.Contains("t1", tables);
        Assert.Contains("t2", tables);
    }

    [Fact]
    public async Task RunAsync_RollsBackOnFailure()
    {
        var migrations = new List<Migration>
        {
            new("0001_one", "CREATE TABLE t1 (Id INTEGER PRIMARY KEY);"),
            new("0002_bad", "CREATE TABLE t2 (Id INTEGER PRIMARY KEY); INVALID SQL HERE;"),
        };
        var runner = new MigrationRunner(_factory, NullLogger<MigrationRunner>.Instance, migrations);

        await Assert.ThrowsAnyAsync<Exception>(() => runner.RunAsync());

        using var conn = _factory.Open();
        var tables = (await conn.QueryAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"))
            .ToList();
        Assert.Contains("t1", tables);
        Assert.DoesNotContain("t2", tables);

        var applied = (await conn.QueryAsync<string>(
            "SELECT Id FROM __migration_history ORDER BY Id;")).ToList();
        Assert.Equal(new[] { "0001_one" }, applied);
    }

    // Note: the embedded-resource discovery path (LoadEmbeddedMigrations) is exercised at
    // runtime when the app launches. We can't unit-test it here because the test project
    // links source files from the main project rather than referencing the assembly, so the
    // migration .sql resource lives in Wormhole.dll, not in this test assembly.
}
