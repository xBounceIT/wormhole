using System.IO;
using Wormhole.ViewModels.Sessions.Transfer;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class LocalFilePaneViewModelTests : IDisposable
{
    private readonly string _root;

    public LocalFilePaneViewModelTests()
    {
        _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "wormhole-tests-" + Guid.NewGuid().ToString("N"))).FullName;
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public async Task LoadAsync_PopulatesEntries_FromTempDirectory()
    {
        File.WriteAllText(Path.Combine(_root, "a.txt"), "hello");
        Directory.CreateDirectory(Path.Combine(_root, "subdir"));

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        // Order: directories first, then files (per FilePaneViewModel.LoadAsync's sort).
        Assert.Collection(pane.Entries,
            e => { Assert.Equal("subdir", e.Name); Assert.True(e.IsDirectory); },
            e => { Assert.Equal("a.txt", e.Name); Assert.False(e.IsDirectory); Assert.Equal(5, e.Size); });
        Assert.Equal(_root, pane.CurrentPath);
        Assert.Null(pane.ErrorMessage);
    }

    [Fact]
    public async Task CreateFolderAsync_CreatesAndRefreshes()
    {
        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        await pane.CreateFolderAsync("new-folder");

        Assert.True(Directory.Exists(Path.Combine(_root, "new-folder")));
        Assert.Contains(pane.Entries, e => e.Name == "new-folder" && e.IsDirectory);
    }

    [Fact]
    public async Task CreateFileAsync_CreatesEmptyFile()
    {
        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        await pane.CreateFileAsync("blank.txt");

        var path = Path.Combine(_root, "blank.txt");
        Assert.True(File.Exists(path));
        Assert.Equal(0, new FileInfo(path).Length);
    }

    [Fact]
    public async Task CreateFileAsync_TwiceInSamePane_ReportsErrorOnConflict()
    {
        File.WriteAllText(Path.Combine(_root, "existing.txt"), "stuff");
        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        await pane.CreateFileAsync("existing.txt");

        // The pane uses CreateNew so an existing file surfaces an IOException; the
        // FilePaneViewModel base catches and stashes the message on ErrorMessage.
        Assert.NotNull(pane.ErrorMessage);
    }

    [Fact]
    public async Task CommitRenameAsync_RenamesFile()
    {
        File.WriteAllText(Path.Combine(_root, "old.txt"), "x");
        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        var entry = Assert.Single(pane.Entries);
        await pane.CommitRenameAsync(entry, "new.txt");

        Assert.True(File.Exists(Path.Combine(_root, "new.txt")));
        Assert.False(File.Exists(Path.Combine(_root, "old.txt")));
    }

    [Fact]
    public async Task CommitRenameAsync_EmptyOrSameName_NoOp()
    {
        File.WriteAllText(Path.Combine(_root, "x.txt"), "x");
        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);
        var entry = pane.Entries[0];
        entry.IsEditing = true;

        await pane.CommitRenameAsync(entry, "x.txt"); // same
        Assert.False(entry.IsEditing); // exited edit mode

        await pane.CommitRenameAsync(entry, "   ");  // whitespace
        Assert.True(File.Exists(Path.Combine(_root, "x.txt")));
    }

    [Fact]
    public async Task DeleteSelectedAsync_RemovesFilesAndDirectories()
    {
        File.WriteAllText(Path.Combine(_root, "a.txt"), "x");
        Directory.CreateDirectory(Path.Combine(_root, "d"));
        File.WriteAllText(Path.Combine(_root, "d", "inner.txt"), "y");

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);
        foreach (var e in pane.Entries) pane.SelectedEntries.Add(e);

        await pane.DeleteSelectedAsync();

        Assert.False(File.Exists(Path.Combine(_root, "a.txt")));
        // Directory was non-empty — verifies the pane uses recursive delete.
        Assert.False(Directory.Exists(Path.Combine(_root, "d")));
    }

    [Fact]
    public async Task GoUpAsync_NavigatesToParent()
    {
        var sub = Directory.CreateDirectory(Path.Combine(_root, "child")).FullName;
        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(sub);

        await pane.GoUpAsync();

        Assert.Equal(_root, pane.CurrentPath);
    }

    // === path traversal regressions ==========================================

    [Theory]
    [InlineData("..\\foo")]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("sub\\foo")]
    [InlineData("sub/foo")]
    [InlineData("C:\\absolute.txt")]
    [InlineData("")]
    [InlineData("   ")]
    public async Task CreateFolderAsync_RejectsTraversalAndInvalidNames(string badName)
    {
        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);
        int countBefore = pane.Entries.Count;

        await pane.CreateFolderAsync(badName);

        // No directory should have been created anywhere — sanitizer caught it.
        Assert.Equal(countBefore, pane.Entries.Count);
        Assert.False(Directory.Exists(Path.Combine(_root, "..", "foo")));
        Assert.False(Directory.Exists(Path.Combine(_root, "sub")));
    }

    [Theory]
    [InlineData("..\\evil.txt")]
    [InlineData("sub/evil.txt")]
    [InlineData("C:\\absolute.txt")]
    public async Task CommitRenameAsync_RejectsTraversal_RevertsSilently(string badName)
    {
        File.WriteAllText(Path.Combine(_root, "original.txt"), "x");
        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);
        var entry = pane.Entries[0];
        entry.IsEditing = true;

        await pane.CommitRenameAsync(entry, badName);

        // Original file untouched; bad target not created anywhere.
        Assert.True(File.Exists(Path.Combine(_root, "original.txt")));
        Assert.False(entry.IsEditing);
        Assert.False(File.Exists(Path.Combine(_root, "evil.txt")));
    }

    [Fact]
    public async Task LoadAsync_ConcurrentCallers_OnlyOneProceeds()
    {
        // Race regression: without the Interlocked guard both LoadAsync calls would
        // pass the IsBusy check, race on Entries.Clear/Add, and produce duplicates.
        // The original count-only assertion is weak (count==5 holds whether both ran
        // serially or only one ran); a counting subclass with an explicit gate keeps the
        // first load in-flight until the second caller has attempted entry.
        for (int i = 0; i < 5; i++) File.WriteAllText(Path.Combine(_root, $"f{i}.txt"), "x");
        var pane = new CountingLocalPane(_root);

        var t1 = pane.LoadAsync(_root);
        await pane.ListStarted;
        var t2 = pane.LoadAsync(_root);
        pane.ReleaseList();
        await Task.WhenAll(t1, t2);

        // Exactly one ListAsync invocation; the other caller hit the Interlocked guard
        // and returned without listing.
        Assert.Equal(1, pane.ListCallCount);
        Assert.Equal(5, pane.Entries.Count);
    }

    /// <summary>
    /// Subclass that counts ListAsync invocations and holds the first call open before
    /// doing the work, opening a deterministic race window for a second caller to
    /// attempt entry. If the Interlocked guard is removed, both callers list and
    /// ListCallCount == 2.
    /// </summary>
    private sealed class CountingLocalPane : LocalFilePaneViewModel
    {
        private readonly TaskCompletionSource<object?> _listStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<object?> _releaseList = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int ListCallCount { get; private set; }
        public Task ListStarted => _listStarted.Task;
        private readonly string _root;
        public CountingLocalPane(string root) { _root = root; }

        public void ReleaseList() => _releaseList.TrySetResult(null);

        protected override async Task<IReadOnlyList<FileEntryViewModel>> ListAsync(string path, CancellationToken cancellationToken)
        {
            ListCallCount++;
            _listStarted.TrySetResult(null);
            await _releaseList.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return await base.ListAsync(path, cancellationToken).ConfigureAwait(false);
        }
    }
}
