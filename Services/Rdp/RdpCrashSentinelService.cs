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
public sealed class RdpCrashSentinelService : IRdpCrashSentinelService
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
    private readonly object _writeLock = new();

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

    public Task MarkConnectInFlightAsync(Guid nodeId, string host, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var record = new RdpCrashRecord(nodeId, host ?? string.Empty, DateTimeOffset.UtcNow);
        var payload = JsonSerializer.SerializeToUtf8Bytes(record, JsonOptions);

        // The write itself is synchronous so a crash mid-Mark can't interleave with a
        // concurrent Clear from another VM's terminal-status hook. The lock pairs with
        // ClearAsync. Threaded as Task.Run so we don't block the dispatcher with file I/O.
        return Task.Run(() =>
        {
            lock (_writeLock)
            {
                var dir = Path.GetDirectoryName(_sentinelPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                var tmp = _sentinelPath + ".tmp";
                File.WriteAllBytes(tmp, payload);
                // Move with overwrite is atomic on Windows NTFS — either the new file is in
                // place or the old one is. No "half-written sentinel" failure mode.
                File.Move(tmp, _sentinelPath, overwrite: true);
                _logger.LogDebug("RDP crash sentinel written for node {NodeId} host {Host}.", nodeId, host);
            }
        }, cancellationToken);
    }

    public Task ClearAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.Run(() =>
        {
            lock (_writeLock)
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
        }, cancellationToken);
    }

    public Task<RdpCrashRecord?> TryClaimOrphanAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.Run<RdpCrashRecord?>(() =>
        {
            lock (_writeLock)
            {
                if (!File.Exists(_sentinelPath)) return null;
                RdpCrashRecord? record = null;
                try
                {
                    var bytes = File.ReadAllBytes(_sentinelPath);
                    record = JsonSerializer.Deserialize<RdpCrashRecord>(bytes, JsonOptions);
                }
                catch (Exception ex) when (ex is JsonException or IOException)
                {
                    _logger.LogWarning(ex, "RDP crash sentinel is malformed — discarding without acting on it.");
                }

                // Always delete on read: even a malformed sentinel must not stick around to
                // re-trigger on every launch. The act of reading is the act of claiming.
                try { File.Delete(_sentinelPath); }
                catch (IOException ex) { _logger.LogWarning(ex, "Failed to delete RDP crash sentinel after read."); }

                return record;
            }
        }, cancellationToken);
    }
}
