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

    // Test serializer that doesn't actually serialize — sufficient since the fake is
    // already thread-safe. The serializer is exercised separately in FileTransferOrchestratorTests.
    private static Task RunDirect(Func<Task> action) => action();
}
