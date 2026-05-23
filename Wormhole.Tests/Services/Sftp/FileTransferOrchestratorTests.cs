using System.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Sftp;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels.Sessions.Transfer;
using Xunit;

namespace Wormhole.Tests.Services.Sftp;

public sealed class FileTransferOrchestratorTests : IDisposable
{
    private readonly string _localRoot;

    public FileTransferOrchestratorTests()
    {
        _localRoot = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "wormhole-orch-" + Guid.NewGuid().ToString("N"))).FullName;
    }

    public void Dispose()
    {
        try { Directory.Delete(_localRoot, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public async Task EnqueueAsync_LocalToRemote_UploadsFileBytes()
    {
        var sftp = new FakeSftpSession();
        await using var orch = NewOrchestrator(sftp);
        var localFile = Path.Combine(_localRoot, "hello.txt");
        File.WriteAllText(localFile, "world");

        var request = new TransferRequest(
            TransferDirection.LocalToRemote,
            "/home/user",
            new[] { new TransferItem(localFile, "hello.txt", false) });
        await orch.EnqueueAsync(request, NeverPrompted, CancellationToken.None);

        Assert.True(sftp.Files.TryGetValue("/home/user/hello.txt", out var bytes));
        Assert.Equal("world", System.Text.Encoding.UTF8.GetString(bytes!));
    }

    [Fact]
    public async Task EnqueueAsync_RemoteToLocal_DownloadsFileBytes()
    {
        var sftp = new FakeSftpSession();
        sftp.Files["/home/user/data.bin"] = new byte[] { 1, 2, 3, 4 };
        await using var orch = NewOrchestrator(sftp);
        var destDir = _localRoot;

        var request = new TransferRequest(
            TransferDirection.RemoteToLocal,
            destDir,
            new[] { new TransferItem("/home/user/data.bin", "data.bin", false) });
        await orch.EnqueueAsync(request, NeverPrompted, CancellationToken.None);

        var local = Path.Combine(destDir, "data.bin");
        Assert.True(File.Exists(local));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, File.ReadAllBytes(local));
    }

    [Fact]
    public async Task EnqueueAsync_OnConflict_InvokesResolver()
    {
        var sftp = new FakeSftpSession();
        sftp.Files["/home/user/conflict.txt"] = new byte[] { 99 };
        await using var orch = NewOrchestrator(sftp);

        File.WriteAllText(Path.Combine(_localRoot, "conflict.txt"), "new");

        int prompts = 0;
        var request = new TransferRequest(
            TransferDirection.LocalToRemote,
            "/home/user",
            new[] { new TransferItem(Path.Combine(_localRoot, "conflict.txt"), "conflict.txt", false) });

        await orch.EnqueueAsync(request, async (_, _) =>
        {
            prompts++;
            return (ConflictDecision.Skip, false);
        }, CancellationToken.None);

        Assert.Equal(1, prompts);
        // Skip means the file was untouched (still 99, not "new").
        Assert.Equal(new byte[] { 99 }, sftp.Files["/home/user/conflict.txt"]);
    }

    [Fact]
    public async Task EnqueueAsync_ApplyToAll_SuppressesSubsequentPrompts()
    {
        var sftp = new FakeSftpSession();
        sftp.Files["/home/user/a.txt"] = new byte[] { 1 };
        sftp.Files["/home/user/b.txt"] = new byte[] { 2 };
        await using var orch = NewOrchestrator(sftp);

        File.WriteAllText(Path.Combine(_localRoot, "a.txt"), "A");
        File.WriteAllText(Path.Combine(_localRoot, "b.txt"), "B");

        int prompts = 0;
        var request = new TransferRequest(
            TransferDirection.LocalToRemote,
            "/home/user",
            new[]
            {
                new TransferItem(Path.Combine(_localRoot, "a.txt"), "a.txt", false),
                new TransferItem(Path.Combine(_localRoot, "b.txt"), "b.txt", false),
            });

        await orch.EnqueueAsync(request, async (_, _) =>
        {
            prompts++;
            return (ConflictDecision.Overwrite, true);
        }, CancellationToken.None);

        Assert.Equal(1, prompts);
        Assert.Equal("A", System.Text.Encoding.UTF8.GetString(sftp.Files["/home/user/a.txt"]));
        Assert.Equal("B", System.Text.Encoding.UTF8.GetString(sftp.Files["/home/user/b.txt"]));
    }

    [Fact]
    public async Task EnqueueAsync_AutoCreatesMissingParentDirectories()
    {
        var sftp = new FakeSftpSession();
        await using var orch = NewOrchestrator(sftp);
        File.WriteAllText(Path.Combine(_localRoot, "leaf.txt"), "leaf");

        var request = new TransferRequest(
            TransferDirection.LocalToRemote,
            "/home/user/deep/nested",
            new[] { new TransferItem(Path.Combine(_localRoot, "leaf.txt"), "leaf.txt", false) });
        await orch.EnqueueAsync(request, NeverPrompted, CancellationToken.None);

        Assert.True(sftp.Directories.ContainsKey("/home/user/deep"));
        Assert.True(sftp.Directories.ContainsKey("/home/user/deep/nested"));
        Assert.True(sftp.Files.ContainsKey("/home/user/deep/nested/leaf.txt"));
    }

    [Fact]
    public async Task EnqueueAsync_SerializesSftpCalls()
    {
        var sftp = new FakeSftpSession();
        await using var orch = NewOrchestrator(sftp);

        // Build a batch of upload items and run them in two parallel batches; the
        // semaphore inside the orchestrator must keep MaxConcurrency at 1 even though
        // the test fires two EnqueueAsync calls concurrently.
        TransferRequest Build(int n)
        {
            var items = Enumerable.Range(0, 5).Select(i =>
            {
                var p = Path.Combine(_localRoot, $"batch{n}-{i}.bin");
                File.WriteAllBytes(p, new byte[] { (byte)i });
                return new TransferItem(p, $"batch{n}-{i}.bin", false);
            }).ToList();
            return new TransferRequest(TransferDirection.LocalToRemote, "/home/user", items);
        }

        var task1 = orch.EnqueueAsync(Build(1), NeverPrompted, CancellationToken.None);
        var task2 = orch.EnqueueAsync(Build(2), NeverPrompted, CancellationToken.None);
        await Task.WhenAll(task1, task2);

        Assert.Equal(1, sftp.MaxConcurrency);
    }

    [Fact]
    public async Task DisposeAsync_DisposesSession()
    {
        var sftp = new FakeSftpSession();
        var orch = NewOrchestrator(sftp);

        await orch.DisposeAsync();

        Assert.Equal(1, sftp.DisposeCount);
    }

    // === regression: WalkRemoteAsync used to deadlock on nested remote dirs ===
    [Fact]
    public async Task EnqueueAsync_RemoteToLocal_DirectoryWithNestedSubdir_DoesNotDeadlock()
    {
        var sftp = new FakeSftpSession();
        // /home/user/root/{a.txt, sub/{b.txt, sub2/{c.txt}}}
        sftp.Directories["/home/user/root"] = true;
        sftp.Files["/home/user/root/a.txt"] = new byte[] { 1 };
        sftp.Directories["/home/user/root/sub"] = true;
        sftp.Files["/home/user/root/sub/b.txt"] = new byte[] { 2 };
        sftp.Directories["/home/user/root/sub/sub2"] = true;
        sftp.Files["/home/user/root/sub/sub2/c.txt"] = new byte[] { 3 };
        await using var orch = NewOrchestrator(sftp);

        var request = new TransferRequest(
            TransferDirection.RemoteToLocal,
            _localRoot,
            new[] { new TransferItem("/home/user/root", "root", true) });

        // If the orchestrator's WalkRemoteAsync still wrapped recursion inside
        // RunSerializedAsync, this task would hang forever on the inner WaitAsync.
        // Bound with WaitAsync(timeout) so the test fails fast on regression.
        await orch.EnqueueAsync(request, NeverPrompted, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(File.Exists(Path.Combine(_localRoot, "root", "a.txt")));
        Assert.True(File.Exists(Path.Combine(_localRoot, "root", "sub", "b.txt")));
        Assert.True(File.Exists(Path.Combine(_localRoot, "root", "sub", "sub2", "c.txt")));
    }

    // === regression: malicious server filename must not escape destination ===
    [Fact]
    public async Task EnqueueAsync_SkipsRemoteEntryWithUnsafeName()
    {
        var sftp = new FakeSftpSession();
        // FakeSftpSession returns its files verbatim. Inject one with a backslash in
        // the name — the orchestrator's IsSafeRemoteName check should filter it.
        sftp.Directories["/home/user/payload"] = true;
        sftp.Files["/home/user/payload/..\\evil.txt"] = new byte[] { 0xBA, 0xD };
        sftp.Files["/home/user/payload/safe.txt"] = new byte[] { 1 };
        await using var orch = NewOrchestrator(sftp);

        var request = new TransferRequest(
            TransferDirection.RemoteToLocal,
            _localRoot,
            new[] { new TransferItem("/home/user/payload", "payload", true) });
        await orch.EnqueueAsync(request, NeverPrompted, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        // The safe file landed; the unsafe one was filtered, NOT written outside _localRoot.
        Assert.True(File.Exists(Path.Combine(_localRoot, "payload", "safe.txt")));
        Assert.False(File.Exists(Path.Combine(_localRoot, "evil.txt")));
        Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(_localRoot)!, "evil.txt")));
    }

    // === regression: empty subtrees must survive directory transfers ==========
    //
    // Pre-fix, FlattenAsync only emitted files (EnumerateFiles / WalkRemoteAsync
    // file branch), so a directory containing zero files anywhere in its subtree
    // produced an empty plan and the destination ended up missing the folder.

    [Fact]
    public async Task EnqueueAsync_LocalToRemote_PreservesEmptyDirectories()
    {
        var sourceDir = Path.Combine(_localRoot, "payload");
        Directory.CreateDirectory(Path.Combine(sourceDir, "empty_dir"));

        var sftp = new FakeSftpSession();
        sftp.Directories["/home/user"] = true;
        await using var orch = NewOrchestrator(sftp);

        var request = new TransferRequest(
            TransferDirection.LocalToRemote,
            "/home/user",
            new[] { new TransferItem(sourceDir, "payload", true) });
        await orch.EnqueueAsync(request, NeverPrompted, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(sftp.Directories.ContainsKey("/home/user/payload"));
        Assert.True(sftp.Directories.ContainsKey("/home/user/payload/empty_dir"));
    }

    [Fact]
    public async Task EnqueueAsync_RemoteToLocal_PreservesEmptyDirectories()
    {
        var sftp = new FakeSftpSession();
        sftp.Directories["/home/user/payload"] = true;
        sftp.Directories["/home/user/payload/empty_dir"] = true;
        await using var orch = NewOrchestrator(sftp);

        var request = new TransferRequest(
            TransferDirection.RemoteToLocal,
            _localRoot,
            new[] { new TransferItem("/home/user/payload", "payload", true) });
        await orch.EnqueueAsync(request, NeverPrompted, CancellationToken.None)
            .WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(Directory.Exists(Path.Combine(_localRoot, "payload")));
        Assert.True(Directory.Exists(Path.Combine(_localRoot, "payload", "empty_dir")));
    }

    private static FileTransferOrchestrator NewOrchestrator(FakeSftpSession sftp) =>
        new(sftp, NullLogger<FileTransferOrchestrator>.Instance);

    // Default resolver used when the test does not expect any conflict — fails the
    // test if invoked, so a regression that surfaces a spurious prompt is caught.
    private static Task<(ConflictDecision Decision, bool ApplyToAll)> NeverPrompted(ConflictContext _, CancellationToken __) =>
        throw new Xunit.Sdk.XunitException("Conflict resolver was unexpectedly invoked.");
}
