using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Services.Rdp;
using Xunit;

namespace Wormhole.Tests.Services;

/// <summary>
/// Filesystem-backed tests for <see cref="RdpCrashSentinelService"/>. Each test gets its own
/// temp file path so the production %LOCALAPPDATA% sentinel is never touched. The internal
/// path-overload constructor exists exactly for this isolation.
/// </summary>
public sealed class RdpCrashSentinelServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _sentinelPath;

    public RdpCrashSentinelServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "wormhole-sentinel-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _sentinelPath = Path.Combine(_tempDir, "rdp-in-flight.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best-effort */ }
    }

    private RdpCrashSentinelService CreateService()
        => new(NullLogger<RdpCrashSentinelService>.Instance, _sentinelPath);

    [Fact]
    public async Task Mark_WritesSentinelFileWithRecordContents()
    {
        var svc = CreateService();
        var nodeId = Guid.NewGuid();

        await svc.MarkConnectInFlightAsync(nodeId, "host.example.com");

        Assert.True(File.Exists(_sentinelPath));
        var json = await File.ReadAllTextAsync(_sentinelPath);
        Assert.Contains(nodeId.ToString(), json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("host.example.com", json);
    }

    [Fact]
    public async Task Mark_OverwritesPreviousSentinel()
    {
        // Two embedded attempts in sequence: the second mark must completely replace the
        // first. Without overwrite semantics, a clear from attempt #2 would leave attempt
        // #1's mark behind and the next launch would incorrectly auto-flag the wrong node.
        var svc = CreateService();
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();

        await svc.MarkConnectInFlightAsync(first, "host-a");
        await svc.MarkConnectInFlightAsync(second, "host-b");

        var orphan = await svc.TryClaimOrphanAsync();
        Assert.NotNull(orphan);
        Assert.Equal(second, orphan!.NodeId);
        Assert.Equal("host-b", orphan.Host);
    }

    [Fact]
    public async Task Clear_RemovesSentinelFile()
    {
        var svc = CreateService();
        await svc.MarkConnectInFlightAsync(Guid.NewGuid(), "host");

        await svc.ClearAsync();

        Assert.False(File.Exists(_sentinelPath));
    }

    [Fact]
    public async Task Clear_OnMissingFile_IsNoOp()
    {
        // Clear may fire repeatedly during teardown (Status hops through Failed →
        // Disconnected) — it must tolerate "nothing to delete" without throwing.
        var svc = CreateService();
        await svc.ClearAsync();
        await svc.ClearAsync(); // second call also tolerated
        Assert.False(File.Exists(_sentinelPath));
    }

    [Fact]
    public async Task TryClaimOrphan_NoFile_ReturnsNull()
    {
        var svc = CreateService();
        var orphan = await svc.TryClaimOrphanAsync();
        Assert.Null(orphan);
    }

    [Fact]
    public async Task TryClaimOrphan_ReturnsRecordAndDeletesFile()
    {
        var svc = CreateService();
        var nodeId = Guid.NewGuid();
        await svc.MarkConnectInFlightAsync(nodeId, "host");

        var orphan = await svc.TryClaimOrphanAsync();

        Assert.NotNull(orphan);
        Assert.Equal(nodeId, orphan!.NodeId);
        Assert.Equal("host", orphan.Host);
        Assert.False(File.Exists(_sentinelPath));
    }

    [Fact]
    public async Task TryClaimOrphan_MalformedJson_DeletesFileAndReturnsNull()
    {
        // A corrupt sentinel must not loop the recovery indefinitely. The act of reading
        // is the act of claiming — even on parse failure the file goes away.
        Directory.CreateDirectory(_tempDir);
        await File.WriteAllTextAsync(_sentinelPath, "{ this is not valid json");
        var svc = CreateService();

        var orphan = await svc.TryClaimOrphanAsync();

        Assert.Null(orphan);
        Assert.False(File.Exists(_sentinelPath));
    }

    [Fact]
    public async Task MarkThenClaim_NoStaleFile_LeavesDirectoryClean()
    {
        // After the happy path (mark → clear), the directory should not retain a stale
        // file or the .tmp swap artefact.
        var svc = CreateService();
        await svc.MarkConnectInFlightAsync(Guid.NewGuid(), "host");
        await svc.ClearAsync();

        Assert.False(File.Exists(_sentinelPath));
        Assert.False(File.Exists(_sentinelPath + ".tmp"));
    }

    [Fact]
    public async Task ConcurrentMarksAndClears_DoNotCorruptSentinel()
    {
        // Stress test: many overlapping mark/clear pairs from different tasks. The internal
        // lock plus atomic File.Move means we should never see a half-written file or a
        // throw — the last operation wins as far as file state is concerned.
        var svc = CreateService();
        var tasks = new List<Task>();
        for (var i = 0; i < 50; i++)
        {
            var id = Guid.NewGuid();
            tasks.Add(svc.MarkConnectInFlightAsync(id, $"host-{i}"));
            tasks.Add(svc.ClearAsync());
        }
        await Task.WhenAll(tasks);

        // Whatever the final file state is, TryClaimOrphan must not throw.
        var orphan = await svc.TryClaimOrphanAsync();
        // Either a record or null — both are valid; the contract is no exceptions and no
        // partial writes.
        if (orphan is not null)
        {
            Assert.False(string.IsNullOrEmpty(orphan.Host));
        }
    }
}
