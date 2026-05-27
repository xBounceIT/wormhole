using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;

namespace Wormhole.Services.Rdp;

/// <summary>
/// File-backed implementation of <see cref="IRdpCrashSentinelService"/>. The sentinel is a
/// single JSON document at <c>%LOCALAPPDATA%\Wormhole\rdp-in-flight.json</c>. Writes go
/// through a tmp+rename pair so a crash during the write itself leaves the previous sentinel
/// intact instead of producing a half-written file. Reads tolerate malformed JSON by logging
/// + deleting the sentinel — a corrupt sentinel must not block app startup.
///
/// Single-file design tradeoff: if two RDP tabs are mid-handshake at the same instant and one
/// crashes while the other completes first, the completing tab's <see cref="ClearAsync"/> will
/// delete the sentinel that named the crashing tab. The orphan recovery on next launch would
/// then miss the crash. We accept this because: (1) the UI does not normally start two RDP
/// connects in parallel — opening a second tab while the first is mid-handshake requires
/// deliberate effort; (2) the AAD WAM crash kills the entire process, so a "concurrent
/// crash + concurrent success" scenario is impossible in the AAD case the sentinel targets.
/// </summary>
public sealed class RdpCrashSentinelService : IRdpCrashSentinelService, IDisposable
{
    private const string SentinelFileName = "rdp-in-flight.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    private readonly ILogger<RdpCrashSentinelService> _logger;
    private readonly string _sentinelPath;
    private readonly SemaphoreSlim _fileGate = new(1, 1);

    public RdpCrashSentinelService(ILogger<RdpCrashSentinelService> logger)
        : this(logger, Path.Combine(AppPaths.GetAppDataDirectory(), SentinelFileName))
    {
    }

    // Test-friendly ctor: tests pass an explicit path to a temp directory so the production
    // %LOCALAPPDATA% sentinel is not touched.
    internal RdpCrashSentinelService(ILogger<RdpCrashSentinelService> logger, string sentinelPath)
    {
        _logger = logger;
        _sentinelPath = sentinelPath;
    }

    public async Task MarkConnectInFlightAsync(Guid nodeId, string host, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var record = new RdpCrashRecord(nodeId, host ?? string.Empty, DateTimeOffset.UtcNow);
        var payload = JsonSerializer.SerializeToUtf8Bytes(record, JsonOptions);

        // Serialize Mark/Clear/Read without pinning a ThreadPool worker for disk I/O.
        // Once the gate is acquired, complete the tmp+rename sequence even if the caller's
        // token is later canceled; that matches the old Task.Run semantics, where the token
        // only affected scheduling and the in-flight file operation ran to completion.
        await _fileGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var dir = Path.GetDirectoryName(_sentinelPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            var tmp = _sentinelPath + ".tmp";
            await File.WriteAllBytesAsync(tmp, payload, CancellationToken.None).ConfigureAwait(false);
            // Move with overwrite is atomic on Windows NTFS — either the new file is in
            // place or the old one is. No "half-written sentinel" failure mode.
            File.Move(tmp, _sentinelPath, overwrite: true);
            _logger.LogDebug("RDP crash sentinel written for node {NodeId} host {Host}.", nodeId, host);
        }
        finally
        {
            _fileGate.Release();
        }
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _fileGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_sentinelPath)) return;
            try
            {
                File.Delete(_sentinelPath);
                _logger.LogDebug("RDP crash sentinel cleared.");
            }
            catch (IOException ex)
            {
                // A locked-file race (e.g. virus scanner) shouldn't fail the connect path.
                // Worst case: the next launch sees the sentinel and auto-flags the profile
                // even though it actually succeeded — an annoying but not dangerous false
                // positive (the user can manually uncheck in the editor afterwards).
                _logger.LogWarning(ex, "Failed to clear RDP crash sentinel — next launch may see a stale orphan.");
            }
        }
        finally
        {
            _fileGate.Release();
        }
    }

    public async Task<RdpCrashRecord?> TryReadOrphanAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _fileGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_sentinelPath)) return null;
            try
            {
                var bytes = await File.ReadAllBytesAsync(_sentinelPath, CancellationToken.None).ConfigureAwait(false);
                var record = JsonSerializer.Deserialize<RdpCrashRecord>(bytes, JsonOptions);
                return record;
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
                // Malformed payload: we can't act on it. Delete defensively so we don't
                // log the same warning every launch, then return null. Healthy sentinels
                // stay on disk until the caller explicitly calls ClearAsync after a
                // successful recovery action.
                _logger.LogWarning(ex, "RDP crash sentinel is malformed — deleting without acting on it.");
                try { File.Delete(_sentinelPath); }
                catch (IOException deleteEx) { _logger.LogWarning(deleteEx, "Failed to delete malformed RDP crash sentinel."); }
                return null;
            }
        }
        finally
        {
            _fileGate.Release();
        }
    }

    public void Dispose() => _fileGate.Dispose();
}
