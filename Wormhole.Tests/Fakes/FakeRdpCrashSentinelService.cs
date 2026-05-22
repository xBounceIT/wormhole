using Wormhole.Models;
using Wormhole.Services.Rdp;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// In-memory implementation of <see cref="IRdpCrashSentinelService"/> for tests. Records every
/// mark/clear/read call so VM tests can verify the sentinel side effects without touching the
/// filesystem. <see cref="OrphanQueue"/> seeds the next <see cref="TryReadOrphanAsync"/> call
/// when exercising the recovery path; reads do NOT auto-clear (matching the production
/// contract that the caller must explicitly call <see cref="ClearAsync"/> on success).
/// </summary>
public sealed class FakeRdpCrashSentinelService : IRdpCrashSentinelService
{
    public List<RdpCrashRecord> Marks { get; } = new();
    public int ClearCount { get; private set; }
    public Queue<RdpCrashRecord?> OrphanQueue { get; } = new();

    public Task MarkConnectInFlightAsync(Guid nodeId, string host, CancellationToken cancellationToken = default)
    {
        // Production tolerates null host via ?? string.Empty; mirror that here so a caller
        // passing null doesn't ArgumentNullException at RdpCrashRecord construction (the
        // record's Host param is non-nullable).
        Marks.Add(new RdpCrashRecord(nodeId, host ?? string.Empty, DateTimeOffset.UtcNow));
        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken = default)
    {
        ClearCount++;
        return Task.CompletedTask;
    }

    public Task<RdpCrashRecord?> TryReadOrphanAsync(CancellationToken cancellationToken = default)
    {
        if (OrphanQueue.Count == 0) return Task.FromResult<RdpCrashRecord?>(null);
        return Task.FromResult(OrphanQueue.Dequeue());
    }
}
