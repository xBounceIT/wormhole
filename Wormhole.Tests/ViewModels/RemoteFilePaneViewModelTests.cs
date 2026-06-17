using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels.Sessions.Transfer;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class RemoteFilePaneViewModelTests
{
    [Fact]
    public async Task LoadAsync_ListsDirectoriesFirst()
    {
        var sftp = new FakeSftpSession();
        sftp.Directories["/home/user/sub"] = true;
        sftp.Files["/home/user/a.txt"] = new byte[] { 1, 2, 3 };

        var pane = new RemoteFilePaneViewModel(sftp, RunDirect);
        await pane.LoadAsync("/home/user");

        Assert.Collection(pane.Entries,
            e => { Assert.Equal("sub", e.Name); Assert.True(e.IsDirectory); },
            e => { Assert.Equal("a.txt", e.Name); Assert.False(e.IsDirectory); Assert.Equal(3, e.Size); });
    }

    [Fact]
    public async Task CreateFolderAsync_AddsDirectoryAndRefreshes()
    {
        var sftp = new FakeSftpSession();
        var pane = new RemoteFilePaneViewModel(sftp, RunDirect);
        await pane.LoadAsync("/home/user");

        await pane.CreateFolderAsync("new");

        Assert.True(sftp.Directories.ContainsKey("/home/user/new"));
        Assert.Contains(pane.Entries, e => e.Name == "new" && e.IsDirectory);
    }

    [Fact]
    public async Task CommitRenameAsync_RenamesFile()
    {
        var sftp = new FakeSftpSession();
        sftp.Files["/home/user/old.txt"] = new byte[] { 1 };
        var pane = new RemoteFilePaneViewModel(sftp, RunDirect);
        await pane.LoadAsync("/home/user");
        var entry = pane.Entries[0];

        await pane.CommitRenameAsync(entry, "new.txt");

        Assert.False(sftp.Files.ContainsKey("/home/user/old.txt"));
        Assert.True(sftp.Files.ContainsKey("/home/user/new.txt"));
    }

    [Fact]
    public async Task DeleteSelectedAsync_HandlesFilesAndRecursiveDirs()
    {
        var sftp = new FakeSftpSession();
        sftp.Files["/home/user/a.txt"] = new byte[] { 1 };
        sftp.Directories["/home/user/d"] = true;
        sftp.Files["/home/user/d/inner.txt"] = new byte[] { 2 };

        var pane = new RemoteFilePaneViewModel(sftp, RunDirect);
        await pane.LoadAsync("/home/user");
        foreach (var e in pane.Entries) pane.SelectedEntries.Add(e);

        await pane.DeleteSelectedAsync();

        Assert.False(sftp.Files.ContainsKey("/home/user/a.txt"));
        Assert.False(sftp.Directories.ContainsKey("/home/user/d"));
        Assert.False(sftp.Files.ContainsKey("/home/user/d/inner.txt"));
    }

    [Fact]
    public async Task GoUpAsync_NavigatesUsingRemotePath()
    {
        var sftp = new FakeSftpSession();
        sftp.Directories["/home/user/nested"] = true;
        var pane = new RemoteFilePaneViewModel(sftp, RunDirect);
        await pane.LoadAsync("/home/user/nested");

        await pane.GoUpAsync();

        Assert.Equal("/home/user", pane.CurrentPath);
    }

    [Fact]
    public async Task SearchAndSort_FilterLoadedRemoteEntries_WithoutRelisting()
    {
        var sftp = new CountingSftpSession(
        [
            new SftpEntry("alpha.txt", "/home/user/alpha.txt", false, false, 3, DateTime.UtcNow, 0),
            new SftpEntry("beta.txt", "/home/user/beta.txt", false, false, 1, DateTime.UtcNow, 0),
        ]);
        var pane = new RemoteFilePaneViewModel(sftp, RunDirect);
        await pane.LoadAsync("/home/user");

        pane.SearchText = "ALP";
        pane.ToggleSort(FilePaneSortColumn.Size);

        Assert.Equal(1, sftp.ListDirectoryCallCount);
        var entry = Assert.Single(pane.Entries);
        Assert.Equal("alpha.txt", entry.Name);
    }

    // Test serializer that doesn't actually serialize — sufficient since the fake is
    // already thread-safe. The serializer is exercised separately in FileTransferOrchestratorTests.
    private static Task RunDirect(Func<Task> action) => action();

    private sealed class CountingSftpSession : ISftpSession
    {
        private readonly IReadOnlyList<SftpEntry> _entries;

        public CountingSftpSession(IReadOnlyList<SftpEntry> entries)
        {
            _entries = entries;
        }

        public int ListDirectoryCallCount { get; private set; }
        public string WorkingDirectory => "/home/user";
        public string? HostFingerprint => "SHA256:fake";
        public bool IsConnected => true;

        public Task<IReadOnlyList<SftpEntry>> ListDirectoryAsync(string path, CancellationToken cancellationToken = default)
        {
            ListDirectoryCallCount++;
            return Task.FromResult(_entries);
        }

        public Task<SftpEntry?> GetAttributesAsync(string path, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<bool> ExistsAsync(string path, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task UploadAsync(Stream source, string remotePath, IProgress<long>? progress, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DownloadAsync(string remotePath, Stream destination, IProgress<long>? progress, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task CreateDirectoryAsync(string remotePath, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task CreateEmptyFileAsync(string remotePath, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteFileAsync(string remotePath, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task DeleteDirectoryAsync(string remotePath, bool recursive, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
