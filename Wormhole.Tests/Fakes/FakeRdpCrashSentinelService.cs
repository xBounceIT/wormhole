using Wormhole.Models;
using Wormhole.Services.Rdp;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// In-memory implementation of <see cref="IRdpCrashSentinelService"/> for tests. Records every
/// mark/clear/orphan-claim call so VM tests can verify the sentinel side effects without
/// touching the filesystem. <see cref="OrphanQueue"/> seeds the next
/// <see cref="TryClaimOrphanAsync"/> call when exercising the recovery path.
/// </summary>
public sealed class FakeRdpCrashSentinelService : IRdpCrashSentinelService
{
    public List<RdpCrashRecord> Marks { get; } = new();
    public int ClearCount { get; private set; }
    public Queue<RdpCrashRecord?> OrphanQueue { get; } = new();

    public Task MarkConnectInFlightAsync(Guid nodeId, string host, CancellationToken cancellationToken = default)
    {
        Marks.Add(new RdpCrashRecord(nodeId, host, DateTimeOffset.UtcNow));
        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken = default)
    {
        ClearCount++;
        return Task.CompletedTask;
    }

    public Task<RdpCrashRecord?> TryClaimOrphanAsync(CancellationToken cancellationToken = default)
    {
        if (OrphanQueue.Count == 0) return Task.FromResult<RdpCrashRecord?>(null);
        return Task.FromResult(OrphanQueue.Dequeue());
    }
}
