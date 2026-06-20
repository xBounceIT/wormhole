using Microsoft.Data.Sqlite;

namespace Wormhole.Data;

public interface ISqliteConnectionFactory
{
    SqliteConnection Open();
}

public sealed class SqliteConnectionFactory : ISqliteConnectionFactory
{
    private static readonly object SqliteInitLock = new();
    private static bool sqliteInitialized;

    private readonly string _connectionString;

    public SqliteConnectionFactory(string connectionString)
    {
        EnsureSqliteInitialized();

        var builder = new SqliteConnectionStringBuilder(connectionString)
        {
            ForeignKeys = true,
        };
        _connectionString = builder.ToString();
    }

    public SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private static void EnsureSqliteInitialized()
    {
        lock (SqliteInitLock)
        {
            if (sqliteInitialized)
            {
                return;
            }

            SQLitePCL.Batteries_V2.Init();
            sqliteInitialized = true;
        }
    }
}
