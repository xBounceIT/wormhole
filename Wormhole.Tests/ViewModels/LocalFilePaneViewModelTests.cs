using System.Collections.Specialized;
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
    public async Task LoadAsync_SortsDirectoriesThenFilesByName()
    {
        File.WriteAllText(Path.Combine(_root, "z-file.txt"), "z");
        File.WriteAllText(Path.Combine(_root, "A-file.txt"), "a");
        Directory.CreateDirectory(Path.Combine(_root, "z-dir"));
        Directory.CreateDirectory(Path.Combine(_root, "A-dir"));

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        Assert.Collection(pane.Entries,
            e => { Assert.Equal("A-dir", e.Name); Assert.True(e.IsDirectory); },
            e => { Assert.Equal("z-dir", e.Name); Assert.True(e.IsDirectory); },
            e => { Assert.Equal("A-file.txt", e.Name); Assert.False(e.IsDirectory); },
            e => { Assert.Equal("z-file.txt", e.Name); Assert.False(e.IsDirectory); });
    }

    [Fact]
    public async Task ToggleSort_Name_ReversesWithinDirectoryAndFileGroups()
    {
        File.WriteAllText(Path.Combine(_root, "a-file.txt"), "a");
        File.WriteAllText(Path.Combine(_root, "z-file.txt"), "z");
        Directory.CreateDirectory(Path.Combine(_root, "a-dir"));
        Directory.CreateDirectory(Path.Combine(_root, "z-dir"));

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        pane.ToggleSort(FilePaneSortColumn.Name);

        Assert.Collection(pane.Entries,
            e => Assert.Equal("z-dir", e.Name),
            e => Assert.Equal("a-dir", e.Name),
            e => Assert.Equal("z-file.txt", e.Name),
            e => Assert.Equal("a-file.txt", e.Name));
        Assert.Equal(FilePaneSortColumn.Name, pane.SortColumn);
        Assert.False(pane.SortAscending);
    }

    [Fact]
    public async Task ToggleSort_Size_SortsAscendingThenDescending()
    {
        File.WriteAllText(Path.Combine(_root, "small.txt"), "x");
        File.WriteAllText(Path.Combine(_root, "large.txt"), "xxxx");
        Directory.CreateDirectory(Path.Combine(_root, "dir"));

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        pane.ToggleSort(FilePaneSortColumn.Size);
        Assert.Collection(pane.Entries,
            e => Assert.Equal("dir", e.Name),
            e => Assert.Equal("small.txt", e.Name),
            e => Assert.Equal("large.txt", e.Name));

        pane.ToggleSort(FilePaneSortColumn.Size);
        Assert.Collection(pane.Entries,
            e => Assert.Equal("dir", e.Name),
            e => Assert.Equal("large.txt", e.Name),
            e => Assert.Equal("small.txt", e.Name));
    }

    [Fact]
    public async Task ToggleSort_Modified_SortsAscendingThenDescending()
    {
        var older = Path.Combine(_root, "older.txt");
        var newer = Path.Combine(_root, "newer.txt");
        File.WriteAllText(older, "x");
        File.WriteAllText(newer, "x");
        File.SetLastWriteTimeUtc(older, new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        File.SetLastWriteTimeUtc(newer, new DateTime(2024, 2, 1, 0, 0, 0, DateTimeKind.Utc));

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        pane.ToggleSort(FilePaneSortColumn.Modified);
        Assert.Collection(pane.Entries,
            e => Assert.Equal("older.txt", e.Name),
            e => Assert.Equal("newer.txt", e.Name));

        pane.ToggleSort(FilePaneSortColumn.Modified);
        Assert.Collection(pane.Entries,
            e => Assert.Equal("newer.txt", e.Name),
            e => Assert.Equal("older.txt", e.Name));
    }

    [Fact]
    public async Task SearchText_FiltersCurrentFolderByName_CaseInsensitive()
    {
        File.WriteAllText(Path.Combine(_root, "Alpha.txt"), "a");
        File.WriteAllText(Path.Combine(_root, "beta.txt"), "b");
        Directory.CreateDirectory(Path.Combine(_root, "Reports"));

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        pane.SearchText = "alp";

        var entry = Assert.Single(pane.Entries);
        Assert.Equal("Alpha.txt", entry.Name);
        Assert.True(pane.HasMatches);
        Assert.False(pane.HasNoMatches);
    }

    [Fact]
    public async Task RefreshAsync_ReappliesActiveSearchAndSort()
    {
        File.WriteAllText(Path.Combine(_root, "small.txt"), "x");
        File.WriteAllText(Path.Combine(_root, "large.txt"), "xxxx");

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);
        pane.SearchText = ".txt";
        pane.ToggleSort(FilePaneSortColumn.Size);

        File.WriteAllText(Path.Combine(_root, "middle.txt"), "xx");
        File.WriteAllText(Path.Combine(_root, "ignore.bin"), "xxxxx");
        await pane.RefreshAsync();

        Assert.Collection(pane.Entries,
            e => Assert.Equal("small.txt", e.Name),
            e => Assert.Equal("middle.txt", e.Name),
            e => Assert.Equal("large.txt", e.Name));
    }

    [Fact]
    public async Task SearchText_NoMatches_UpdatesNoMatchState()
    {
        File.WriteAllText(Path.Combine(_root, "alpha.txt"), "a");

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        pane.SearchText = "zzz";

        Assert.Empty(pane.Entries);
        Assert.False(pane.HasMatches);
        Assert.True(pane.HasNoMatches);
    }

    [Fact]
    public async Task SearchText_PrunesSelectionToVisibleEntries()
    {
        File.WriteAllText(Path.Combine(_root, "alpha.txt"), "a");
        File.WriteAllText(Path.Combine(_root, "beta.txt"), "b");

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);
        foreach (var entry in pane.Entries)
        {
            pane.SelectedEntries.Add(entry);
        }

        pane.SearchText = "alpha";

        var selected = Assert.Single(pane.SelectedEntries);
        Assert.Equal("alpha.txt", selected.Name);
    }

    [Fact]
    public async Task SearchText_LargeFolder_RebuildsAsynchronouslyUsingLatestQuery()
    {
        for (var i = 0; i < 300; i++)
        {
            File.WriteAllText(Path.Combine(_root, $"file-{i:D3}.txt"), "x");
        }

        File.WriteAllText(Path.Combine(_root, "target.txt"), "x");

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        pane.SearchText = "file-";
        pane.SearchText = "target";

        await WaitForConditionAsync(() => pane.Entries.Count == 1 && pane.Entries[0].Name == "target.txt");
    }

    [Fact]
    public async Task ToggleSort_LargeFolder_RebuildsAsynchronouslyUsingLatestDirection()
    {
        for (var i = 0; i < 300; i++)
        {
            File.WriteAllText(Path.Combine(_root, $"middle-{i:D3}.txt"), "xx");
        }

        File.WriteAllText(Path.Combine(_root, "small.txt"), "x");
        File.WriteAllText(Path.Combine(_root, "large.txt"), "xxxx");

        var pane = new LocalFilePaneViewModel();
        await pane.LoadAsync(_root);

        pane.ToggleSort(FilePaneSortColumn.Size);
        await WaitForConditionAsync(() => pane.Entries.Count > 0 && pane.Entries[0].Name == "small.txt");

        pane.ToggleSort(FilePaneSortColumn.Size);
        await WaitForConditionAsync(() => pane.Entries.Count > 0 && pane.Entries[0].Name == "large.txt");
    }

    [Fact]
    public async Task LoadAsync_ReplacesEntriesWithSingleReset()
    {
        File.WriteAllText(Path.Combine(_root, "a.txt"), "hello");
        File.WriteAllText(Path.Combine(_root, "b.txt"), "hello");
        Directory.CreateDirectory(Path.Combine(_root, "subdir"));

        var pane = new LocalFilePaneViewModel();
        var addEvents = 0;
        var resetEvents = 0;
        pane.Entries.CollectionChanged += (_, args) =>
        {
            if (args.Action == NotifyCollectionChangedAction.Add) addEvents++;
            if (args.Action == NotifyCollectionChangedAction.Reset) resetEvents++;
        };

        await pane.LoadAsync(_root);

        Assert.Equal(3, pane.Entries.Count);
        Assert.Equal(0, addEvents);
        Assert.Equal(1, resetEvents);
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

    private static async Task WaitForConditionAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        Assert.True(condition(), "Timed out waiting for asynchronous file-pane projection.");
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
