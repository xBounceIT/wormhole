using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;

namespace Wormhole.Services.BitwardenBrowser;

/// <summary>
/// Shares Bitwarden extension storage across WebView2 profiles. Proxy and certificate-policy
/// isolation requires distinct user-data folders, so Chromium cannot share this state itself.
/// Persistent data is protected with current-user DPAPI and written atomically; session storage
/// remains memory-only so restarting Wormhole retains Bitwarden's normal lock semantics.
/// </summary>
internal sealed class BitwardenBrowserSharedStorage : IDisposable
{
    internal const string ProfileRevisionFileName = "wormhole-bitwarden-shared-storage-v1.txt";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Wormhole.BitwardenBrowser.SharedStorage.v1");

    private readonly ILogger<BitwardenBrowserSharedStorage> _logger;
    private readonly string _path;
    private readonly Func<byte[], byte[]> _protect;
    private readonly Func<byte[], byte[]> _unprotect;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SharedSnapshot? _snapshot;
    private bool _loaded;
    private bool _primaryNeedsRepair;

    public BitwardenBrowserSharedStorage(ILogger<BitwardenBrowserSharedStorage> logger)
        : this(
            logger,
            AppPaths.GetBitwardenBrowserSharedStorageFilePath(),
            bytes => ProtectedData.Protect(bytes, Entropy, DataProtectionScope.CurrentUser),
            bytes => ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.CurrentUser))
    {
    }

    internal BitwardenBrowserSharedStorage(
        ILogger<BitwardenBrowserSharedStorage> logger,
        string path,
        Func<byte[], byte[]> protect,
        Func<byte[], byte[]> unprotect)
    {
        _logger = logger;
        _path = path;
        _protect = protect;
        _unprotect = unprotect;
    }

    /// <summary>
    /// Serializes a complete import/capture transaction so two new WebViews cannot both decide they
    /// are the first profile and race an empty snapshot over a live session.
    /// </summary>
    public async Task RunExclusiveAsync(Func<Task> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        await _gate.WaitAsync().ConfigureAwait(true);
        try { await action().ConfigureAwait(true); }
        finally { _gate.Release(); }
    }

    public Task<BitwardenBrowserStorageRestore?> GetRestoreAsync(string userDataFolder)
    {
        EnsureLoaded();
        var snapshot = _snapshot;
        var restore = snapshot is null || ReadProfileRevision(userDataFolder) >= snapshot.Revision
            ? null
            : new BitwardenBrowserStorageRestore(
                snapshot.Revision,
                snapshot.LocalJson,
                snapshot.SessionJson,
                snapshot.IsDurable);
        return Task.FromResult(restore);
    }

    public async Task CaptureAsync(
        string userDataFolder,
        BitwardenBrowserStorageSnapshot captured,
        CancellationToken cancellationToken = default)
    {
        var localJson = NormalizeObjectJson(captured.LocalJson, nameof(captured.LocalJson));
        var sessionJson = NormalizeObjectJson(captured.SessionJson, nameof(captured.SessionJson));
        if (!EnsureLoaded())
        {
            RememberVolatileCapture(localJson, sessionJson);
            return;
        }

        var current = _snapshot;

        if (current is not null
            && ReadProfileRevision(userDataFolder) < current.Revision
            && (!string.Equals(current.LocalJson, localJson, StringComparison.Ordinal)
                || !string.Equals(current.SessionJson, sessionJson, StringComparison.Ordinal)))
        {
            _logger.LogDebug(
                "Ignored stale Bitwarden browser storage captured from a profile that has a newer shared revision pending.");
            return;
        }

        if (current is not null
            && string.Equals(current.LocalJson, localJson, StringComparison.Ordinal)
            && string.Equals(current.SessionJson, sessionJson, StringComparison.Ordinal))
        {
            if (current.IsDurable && !_primaryNeedsRepair)
            {
                WriteProfileRevision(userDataFolder, current.Revision);
                return;
            }

            await TryPersistAndMarkAsync(userDataFolder, current, cancellationToken).ConfigureAwait(false);
            return;
        }

        var next = new SharedSnapshot((current?.Revision ?? 0) + 1, localJson, sessionJson, IsDurable: false);
        _snapshot = next;
        await TryPersistAndMarkAsync(userDataFolder, next, cancellationToken).ConfigureAwait(false);
    }

    private void RememberVolatileCapture(string localJson, string sessionJson)
    {
        var current = _snapshot;
        if (current is not null
            && string.Equals(current.LocalJson, localJson, StringComparison.Ordinal)
            && string.Equals(current.SessionJson, sessionJson, StringComparison.Ordinal))
        {
            return;
        }

        _snapshot = new SharedSnapshot(
            (current?.Revision ?? 0) + 1,
            localJson,
            sessionJson,
            IsDurable: false);
    }

    public Task MarkRestoredAsync(string userDataFolder, BitwardenBrowserStorageRestore restored)
    {
        if (restored.IsDurable) WriteProfileRevision(userDataFolder, restored.Revision);
        return Task.CompletedTask;
    }

    private async Task TryPersistAndMarkAsync(
        string userDataFolder,
        SharedSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        try
        {
            var recoveryReady = await PersistAsync(snapshot, cancellationToken).ConfigureAwait(false);
            var durable = snapshot with { IsDurable = true };
            _snapshot = durable;
            WriteProfileRevision(userDataFolder, durable.Revision);
            _primaryNeedsRepair = !recoveryReady;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            // Keep the snapshot in memory for the other live connections, but do not advance the
            // marker. A later capture will retry durable persistence.
            _logger.LogWarning(ex, "Could not persist shared Bitwarden browser storage.");
        }
    }

    private bool EnsureLoaded()
    {
        if (_loaded) return true;

        var primary = TryRead(_path);
        if (primary.Snapshot is { } primarySnapshot)
        {
            var recovery = TryRead(_path + ".bak");
            AdoptLoadedSnapshot(primarySnapshot);
            _primaryNeedsRepair = recovery.Snapshot?.Revision != primarySnapshot.Revision;
            _loaded = true;
            return true;
        }

        var backup = TryRead(_path + ".bak");
        if (backup.Snapshot is { } backupSnapshot)
        {
            AdoptLoadedSnapshot(backupSnapshot);
            _primaryNeedsRepair = true;
            _loaded = true;
            return true;
        }

        if (primary.State == SnapshotReadState.Missing && backup.State == SnapshotReadState.Missing)
        {
            _loaded = true;
            return true;
        }

        // Do not turn a transient read/DPAPI failure into an empty store. Keeping _loaded false makes
        // the next transaction retry, while CaptureAsync retains live state only in memory.
        return false;
    }

    private void AdoptLoadedSnapshot(SharedSnapshot durableSnapshot)
    {
        if (_snapshot is not { IsDurable: false } volatileSnapshot)
        {
            _snapshot = durableSnapshot;
            return;
        }

        _snapshot = volatileSnapshot with
        {
            Revision = Math.Max(volatileSnapshot.Revision, durableSnapshot.Revision + 1),
        };
    }

    private SnapshotReadResult TryRead(string path)
    {
        try
        {
            var protectedBytes = File.ReadAllBytes(path);
            var json = Encoding.UTF8.GetString(_unprotect(protectedBytes));
            var record = JsonSerializer.Deserialize<PersistedRecord>(json);
            if (record is null || record.SchemaVersion != 1 || record.Revision <= 0)
                throw new InvalidDataException("The shared Bitwarden browser storage record is invalid.");
            return new SnapshotReadResult(SnapshotReadState.Success, new SharedSnapshot(
                record.Revision,
                NormalizeObjectJson(record.LocalJson, nameof(record.LocalJson)),
                SessionJson: "{}",
                IsDurable: true));
        }
        catch (FileNotFoundException) { return new SnapshotReadResult(SnapshotReadState.Missing, null); }
        catch (DirectoryNotFoundException) { return new SnapshotReadResult(SnapshotReadState.Missing, null); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read a shared Bitwarden browser storage snapshot; trying recovery copy.");
            return new SnapshotReadResult(SnapshotReadState.Unreadable, null);
        }
    }

    private async Task<bool> PersistAsync(SharedSnapshot snapshot, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("The Bitwarden storage path has no parent directory.");
        Directory.CreateDirectory(directory);
        var tempPath = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var record = new PersistedRecord(1, snapshot.Revision, snapshot.LocalJson);
            var protectedBytes = await Task.Run(
                () => _protect(JsonSerializer.SerializeToUtf8Bytes(record)),
                cancellationToken).ConfigureAwait(false);

            await using (var stream = new FileStream(
                tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(protectedBytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(_path))
            {
                File.Replace(tempPath, _path, _path + ".bak", ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, _path);
            }
            return RefreshBackupCopy();
        }
        finally
        {
            try { File.Delete(tempPath); } catch { /* best effort */ }
        }
    }

    private bool RefreshBackupCopy()
    {
        var backupPath = _path + ".bak";
        var tempPath = backupPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.Copy(_path, tempPath);
            File.Move(tempPath, backupPath, overwrite: true);
            return true;
        }
        catch (Exception ex)
        {
            // The primary snapshot is already atomically committed. A backup failure must not make
            // that successful capture look non-durable.
            _logger.LogDebug(ex, "Could not refresh the Bitwarden browser storage recovery copy.");
            return false;
        }
        finally
        {
            try { File.Delete(tempPath); } catch { /* best effort */ }
        }
    }

    private static string NormalizeObjectJson(string json, string parameterName)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new ArgumentException("Bitwarden storage must be a JSON object.", parameterName);
        return JsonSerializer.Serialize(document.RootElement);
    }

    private static long ReadProfileRevision(string userDataFolder)
    {
        try
        {
            var text = File.ReadAllText(Path.Combine(userDataFolder, ProfileRevisionFileName));
            return long.TryParse(
                text,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var revision) ? revision : 0;
        }
        catch { return 0; }
    }

    private void WriteProfileRevision(string userDataFolder, long revision)
    {
        var path = Path.Combine(userDataFolder, ProfileRevisionFileName);
        var tempPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(userDataFolder);
            File.WriteAllText(tempPath, revision.ToString(System.Globalization.CultureInfo.InvariantCulture));
            File.Move(tempPath, path, overwrite: true);
        }
        catch (Exception ex)
        {
            try { File.Delete(tempPath); } catch { /* best effort */ }
            _logger.LogDebug(ex, "Could not update a Bitwarden WebView2 profile revision marker.");
        }
    }

    public void Dispose() => _gate.Dispose();

    private enum SnapshotReadState { Missing, Success, Unreadable }
    private readonly record struct SnapshotReadResult(SnapshotReadState State, SharedSnapshot? Snapshot);
    private sealed record SharedSnapshot(long Revision, string LocalJson, string SessionJson, bool IsDurable);
    private sealed record PersistedRecord(int SchemaVersion, long Revision, string LocalJson);
}

internal sealed record BitwardenBrowserStorageSnapshot(string LocalJson, string SessionJson);
internal sealed record BitwardenBrowserStorageRestore(
    long Revision,
    string LocalJson,
    string SessionJson,
    bool IsDurable);
