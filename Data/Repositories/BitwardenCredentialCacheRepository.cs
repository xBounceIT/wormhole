using Dapper;
using Wormhole.Models;
using Wormhole.Services.Bitwarden;

namespace Wormhole.Data.Repositories;

public sealed class BitwardenCredentialCacheRepository : IBitwardenCredentialCacheRepository
{
    private const string SelectColumns = @"
        ItemId, SshCredentialId, RdpCredentialId, VncCredentialId,
        Name, Username, RevisionDate, LastSeenSyncUtc, UpdatedAtUtc";

    private readonly ISqliteConnectionFactory _factory;

    public BitwardenCredentialCacheRepository(ISqliteConnectionFactory factory)
    {
        _factory = factory;
    }

    public async Task<IReadOnlyList<BitwardenCredentialCacheEntry>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        var rows = await connection.QueryAsync<BitwardenCredentialCacheEntry>(new CommandDefinition(
            $"SELECT {SelectColumns} FROM BitwardenCredentialCache ORDER BY Name;",
            cancellationToken: cancellationToken));
        var list = rows as IReadOnlyList<BitwardenCredentialCacheEntry> ?? rows.ToList();
        foreach (var entry in list)
        {
            BitwardenVirtualCredentialIds.EnsureIds(entry);
        }
        return list;
    }

    public async Task ReplaceFromFullSyncAsync(
        IReadOnlyList<BitwardenCredentialCacheEntry> entries,
        DateTimeOffset syncTimeUtc,
        CancellationToken cancellationToken = default)
    {
        using var connection = _factory.Open();
        using var tx = connection.BeginTransaction();
        try
        {
            var normalized = Normalize(entries, syncTimeUtc);
            foreach (var entry in normalized)
            {
                await UpsertAsync(connection, tx, entry, cancellationToken).ConfigureAwait(false);
            }

            if (normalized.Count == 0)
            {
                await connection.ExecuteAsync(new CommandDefinition(
                    "DELETE FROM BitwardenCredentialCache;",
                    transaction: tx,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }
            else
            {
                await connection.ExecuteAsync(new CommandDefinition(
                    "DELETE FROM BitwardenCredentialCache WHERE ItemId NOT IN @ItemIds;",
                    new { ItemIds = normalized.Select(e => e.ItemId).ToArray() },
                    transaction: tx,
                    cancellationToken: cancellationToken)).ConfigureAwait(false);
            }

            tx.Commit();
        }
        catch
        {
            tx.Rollback();
            throw;
        }
    }

    public async Task UpsertImportedAsync(
        IReadOnlyList<BitwardenCredentialCacheEntry> entries,
        CancellationToken cancellationToken = default)
    {
        if (entries.Count == 0) return;

        using var connection = _factory.Open();
        using var tx = connection.BeginTransaction();
        try
        {
            var normalized = Normalize(entries, DateTimeOffset.UtcNow);
            foreach (var entry in normalized)
            {
                await UpsertAsync(connection, tx, entry, cancellationToken).ConfigureAwait(false);
            }
            tx.Commit();
        }
        catch
        {
            tx.Rollback();
            throw;
        }
    }

    private static List<BitwardenCredentialCacheEntry> Normalize(
        IReadOnlyList<BitwardenCredentialCacheEntry> entries,
        DateTimeOffset defaultSyncTimeUtc)
    {
        var byItemId = new Dictionary<string, BitwardenCredentialCacheEntry>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.ItemId)) continue;

            var normalized = new BitwardenCredentialCacheEntry
            {
                ItemId = entry.ItemId.Trim(),
                SshCredentialId = entry.SshCredentialId,
                RdpCredentialId = entry.RdpCredentialId,
                VncCredentialId = entry.VncCredentialId,
                Name = string.IsNullOrWhiteSpace(entry.Name) ? entry.ItemId.Trim() : entry.Name.Trim(),
                Username = string.IsNullOrWhiteSpace(entry.Username) ? null : entry.Username.Trim(),
                RevisionDate = string.IsNullOrWhiteSpace(entry.RevisionDate) ? null : entry.RevisionDate.Trim(),
                LastSeenSyncUtc = entry.LastSeenSyncUtc == default ? defaultSyncTimeUtc : entry.LastSeenSyncUtc,
                UpdatedAtUtc = entry.UpdatedAtUtc == default ? defaultSyncTimeUtc : entry.UpdatedAtUtc,
            };
            BitwardenVirtualCredentialIds.EnsureIds(normalized);
            byItemId[normalized.ItemId] = normalized;
        }
        return byItemId.Values.OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
    }

    private static Task<int> UpsertAsync(
        Microsoft.Data.Sqlite.SqliteConnection connection,
        Microsoft.Data.Sqlite.SqliteTransaction tx,
        BitwardenCredentialCacheEntry entry,
        CancellationToken cancellationToken) =>
        connection.ExecuteAsync(new CommandDefinition(@"
            INSERT INTO BitwardenCredentialCache
                (ItemId, SshCredentialId, RdpCredentialId, VncCredentialId,
                 Name, Username, RevisionDate, LastSeenSyncUtc, UpdatedAtUtc)
            VALUES
                (@ItemId, @SshCredentialId, @RdpCredentialId, @VncCredentialId,
                 @Name, @Username, @RevisionDate, @LastSeenSyncUtc, @UpdatedAtUtc)
            ON CONFLICT(ItemId) DO UPDATE SET
                SshCredentialId = excluded.SshCredentialId,
                RdpCredentialId = excluded.RdpCredentialId,
                VncCredentialId = excluded.VncCredentialId,
                Name = excluded.Name,
                Username = excluded.Username,
                RevisionDate = excluded.RevisionDate,
                LastSeenSyncUtc = excluded.LastSeenSyncUtc,
                UpdatedAtUtc = excluded.UpdatedAtUtc;",
            entry,
            transaction: tx,
            cancellationToken: cancellationToken));
}
