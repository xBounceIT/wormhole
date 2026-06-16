using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wormhole.ViewModels;

namespace Wormhole.ViewModels.Sessions.Transfer;

public enum FilePaneSortColumn
{
    Name,
    Size,
    Modified,
}

/// <summary>
/// Base class for one pane in the file transfer dialog. Subclasses provide the
/// filesystem operations; the base supplies common state (current path, entries,
/// selection, error surface) and command plumbing the toolbar can bind to.
/// </summary>
public abstract partial class FilePaneViewModel : ObservableObject
{
    private static readonly TimeSpan ProjectionRebuildDebounce = TimeSpan.FromMilliseconds(75);
    private const int AsyncProjectionThreshold = 256;

    // Interlocked-backed sentinel for the load-in-progress flag. Using a plain bool
    // here would race: two callers (e.g. concurrent RefreshAsync + LoadInitialAsync)
    // could both observe IsBusy=false before either has set IsBusy=true, then both
    // proceed to Clear/refill Entries — duplicates, missing entries, or stomped
    // SelectedEntries.Clear() depending on interleaving.
    private int _loadInFlight;
    private FileEntryViewModel[] _loadedEntries = Array.Empty<FileEntryViewModel>();
    private bool _deferProjectionRebuild;
    private readonly object _projectionRebuildGate = new();
    private CancellationTokenSource? _projectionRebuildCts;

    private readonly record struct EntryProjection(
        FileEntryViewModel[] Entries,
        string Query,
        FilePaneSortColumn SortColumn,
        bool SortAscending);

    /// <summary>Visible entries after applying the current search and sort settings.</summary>
    public BulkObservableCollection<FileEntryViewModel> Entries { get; } = new();

    /// <summary>Selection is two-way bound from the ListView's SelectedItems. The
    /// view layer mirrors selection changes here; toolbar commands read it directly.</summary>
    public BulkObservableCollection<FileEntryViewModel> SelectedEntries { get; } = new();

    [ObservableProperty]
    private string currentPath = string.Empty;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isBusy;

    [ObservableProperty]
    private string searchText = string.Empty;

    [ObservableProperty]
    private FilePaneSortColumn sortColumn = FilePaneSortColumn.Name;

    [ObservableProperty]
    private bool sortAscending = true;

    /// <summary>Distinguishes the two sides in drag-and-drop handlers without forcing
    /// runtime type checks. Set once in the subclass constructor.</summary>
    public abstract bool IsLocal { get; }

    public abstract string Title { get; }

    public bool IsEmpty => _loadedEntries.Length == 0;

    public bool HasMatches => Entries.Count > 0;

    public bool HasNoMatches => !IsEmpty && Entries.Count == 0;

    public string NameSortGlyph => SortGlyphFor(FilePaneSortColumn.Name);

    public string SizeSortGlyph => SortGlyphFor(FilePaneSortColumn.Size);

    public string ModifiedSortGlyph => SortGlyphFor(FilePaneSortColumn.Modified);

    protected FilePaneViewModel()
    {
        Entries.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(HasMatches));
            OnPropertyChanged(nameof(HasNoMatches));
        };
    }

    public async Task LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        // Atomically claim the load slot: only one LoadAsync runs at a time per pane.
        // CompareExchange returns the original value, so non-zero means already in flight.
        if (Interlocked.CompareExchange(ref _loadInFlight, 1, 0) != 0) return;
        CancelPendingProjectionRebuild();
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var entries = await ListAsync(path, cancellationToken).ConfigureAwait(true);
            var loadedEntries = await CopyEntriesAsync(entries, cancellationToken).ConfigureAwait(true);
            var projection = CreateProjection(loadedEntries);
            var visibleEntries = await BuildVisibleEntriesAsync(projection, cancellationToken).ConfigureAwait(true);
            _loadedEntries = loadedEntries;
            CurrentPath = path;
            if (ProjectionStateMatches(projection))
            {
                ReplaceVisibleEntries(visibleEntries);
            }
            else
            {
                RebuildEntries();
            }
            SelectedEntries.Clear();
            NotifyLoadedEntryStateChanged();
        }
        catch (OperationCanceledException) { /* swallow on cancel */ }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            // Release the load slot BEFORE flipping IsBusy so a binding subscriber that
            // observes IsBusy=false and immediately calls LoadAsync sees _loadInFlight=0
            // and is allowed to proceed. The reverse order would cause that subscriber's
            // CompareExchange to lose against the slot-holder that's about to clear it.
            Interlocked.Exchange(ref _loadInFlight, 0);
            IsBusy = false;
        }
    }

    [RelayCommand]
    public Task RefreshAsync() => LoadAsync(CurrentPath);

    [RelayCommand]
    public Task GoUpAsync()
    {
        var parent = ParentOf(CurrentPath);
        return parent == CurrentPath ? Task.CompletedTask : LoadAsync(parent);
    }

    [RelayCommand]
    public async Task OpenAsync(FileEntryViewModel entry)
    {
        if (entry is null || !entry.IsDirectory) return;
        await LoadAsync(entry.FullPath).ConfigureAwait(true);
    }

    public async Task CreateFolderAsync(string name, CancellationToken cancellationToken = default)
    {
        var trimmed = SanitizeNameOrNull(name);
        if (trimmed is null) { ErrorMessage = "Invalid folder name."; return; }
        try
        {
            await CreateFolderCoreAsync(Join(CurrentPath, trimmed), cancellationToken).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    public async Task CreateFileAsync(string name, CancellationToken cancellationToken = default)
    {
        var trimmed = SanitizeNameOrNull(name);
        if (trimmed is null) { ErrorMessage = "Invalid file name."; return; }
        try
        {
            await CreateFileCoreAsync(Join(CurrentPath, trimmed), cancellationToken).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    /// <summary>
    /// Trims and validates a user-typed leaf name. Returns null if the name is empty,
    /// whitespace-only, contains path separators ('/' or '\'), is "." or "..", or
    /// includes a colon (drive separator on Windows). Used by CreateFolder/CreateFile/
    /// Rename to prevent path traversal — without this, typing `..\..\foo` in the
    /// rename TextBox would let Move/Copy/Mkdir operate outside CurrentPath.
    /// </summary>
    protected static string? SanitizeNameOrNull(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var trimmed = name.Trim();
        if (trimmed == "." || trimmed == "..") return null;
        foreach (var c in trimmed)
        {
            if (c == '/' || c == '\\' || c == ':' || c == '\0') return null;
        }
        return trimmed;
    }

    public async Task DeleteSelectedAsync(CancellationToken cancellationToken = default)
    {
        // Snapshot first: SelectedEntries is rebuilt by the ListView when the underlying
        // collection mutates, so iterating live would skip every other item.
        var snapshot = SelectedEntries.ToArray();
        if (snapshot.Length == 0) return;
        foreach (var item in snapshot)
        {
            try
            {
                await DeleteCoreAsync(item, cancellationToken).ConfigureAwait(true);
            }
            catch (Exception ex) { ErrorMessage = ex.Message; }
        }
        await RefreshAsync().ConfigureAwait(true);
    }

    public async Task CommitRenameAsync(FileEntryViewModel entry, string newName, CancellationToken cancellationToken = default)
    {
        if (entry is null) return;
        var sanitized = SanitizeNameOrNull(newName);
        if (sanitized is null || sanitized == entry.Name)
        {
            // Empty/whitespace/unchanged/traversal-attempt input: revert and exit edit
            // mode silently. Surfacing an error for "unchanged" would be annoying; the
            // traversal case is rare enough that the silent revert is acceptable UX.
            entry.EditingName = entry.Name;
            entry.IsEditing = false;
            return;
        }

        try
        {
            await RenameCoreAsync(entry, sanitized, cancellationToken).ConfigureAwait(true);
            entry.IsEditing = false;
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            entry.EditingName = entry.Name;
            entry.IsEditing = false;
        }
    }

    public static void CancelRename(FileEntryViewModel entry)
    {
        if (entry is null) return;
        entry.EditingName = entry.Name;
        entry.IsEditing = false;
    }

    public static void BeginRename(FileEntryViewModel entry)
    {
        if (entry is null) return;
        entry.EditingName = entry.Name;
        entry.IsEditing = true;
    }

    public void ToggleSort(FilePaneSortColumn column)
    {
        if (SortColumn == column)
        {
            SortAscending = !SortAscending;
            return;
        }

        _deferProjectionRebuild = true;
        SortColumn = column;
        SortAscending = true;
        _deferProjectionRebuild = false;
        NotifySortGlyphsChanged();
        RebuildEntries();
    }

    partial void OnSearchTextChanged(string value) => RebuildEntries();

    partial void OnSortColumnChanged(FilePaneSortColumn value) => OnSortStateChanged();

    partial void OnSortAscendingChanged(bool value) => OnSortStateChanged();

    protected abstract Task<IReadOnlyList<FileEntryViewModel>> ListAsync(string path, CancellationToken cancellationToken);
    protected abstract Task CreateFolderCoreAsync(string fullPath, CancellationToken cancellationToken);
    protected abstract Task CreateFileCoreAsync(string fullPath, CancellationToken cancellationToken);
    protected abstract Task DeleteCoreAsync(FileEntryViewModel entry, CancellationToken cancellationToken);
    protected abstract Task RenameCoreAsync(FileEntryViewModel entry, string newName, CancellationToken cancellationToken);
    protected abstract string ParentOf(string path);
    protected abstract string Join(string parent, string name);

    private void OnSortStateChanged()
    {
        if (_deferProjectionRebuild) return;

        NotifySortGlyphsChanged();
        RebuildEntries();
    }

    private void NotifySortGlyphsChanged()
    {
        OnPropertyChanged(nameof(NameSortGlyph));
        OnPropertyChanged(nameof(SizeSortGlyph));
        OnPropertyChanged(nameof(ModifiedSortGlyph));
    }

    private string SortGlyphFor(FilePaneSortColumn column) =>
        SortColumn == column
            ? SortAscending ? "\uE70E" : "\uE70D"
            : string.Empty;

    private static Task<FileEntryViewModel[]> CopyEntriesAsync(
        IReadOnlyList<FileEntryViewModel> entries,
        CancellationToken cancellationToken)
    {
        if (entries.Count < AsyncProjectionThreshold)
        {
            return Task.FromResult(CopyEntries(entries, cancellationToken));
        }

        return Task.Run(() => CopyEntries(entries, cancellationToken), cancellationToken);
    }

    private static FileEntryViewModel[] CopyEntries(
        IReadOnlyList<FileEntryViewModel> entries,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var copy = new FileEntryViewModel[entries.Count];
        for (var i = 0; i < entries.Count; i++)
        {
            copy[i] = entries[i];
        }

        cancellationToken.ThrowIfCancellationRequested();
        return copy;
    }

    private void RebuildEntries()
    {
        var snapshot = CreateProjection();
        if (snapshot.Entries.Length >= AsyncProjectionThreshold)
        {
            QueueProjectionRebuild(snapshot);
            return;
        }

        CancelPendingProjectionRebuild();
        ReplaceVisibleEntries(BuildVisibleEntries(snapshot, CancellationToken.None));
        PruneSelectionToVisibleEntries();
    }

    private static Task<FileEntryViewModel[]> BuildVisibleEntriesAsync(
        EntryProjection snapshot,
        CancellationToken cancellationToken)
    {
        if (snapshot.Entries.Length < AsyncProjectionThreshold)
        {
            return Task.FromResult(BuildVisibleEntries(snapshot, cancellationToken));
        }

        return Task.Run(() => BuildVisibleEntries(snapshot, cancellationToken), cancellationToken);
    }

    private EntryProjection CreateProjection() =>
        CreateProjection(_loadedEntries);

    private EntryProjection CreateProjection(
        FileEntryViewModel[] entries) =>
        new(entries, SearchText.Trim(), SortColumn, SortAscending);

    private bool ProjectionStateMatches(EntryProjection snapshot) =>
        ReferenceEquals(_loadedEntries, snapshot.Entries) &&
        string.Equals(SearchText.Trim(), snapshot.Query, StringComparison.Ordinal) &&
        SortColumn == snapshot.SortColumn &&
        SortAscending == snapshot.SortAscending;

    private void QueueProjectionRebuild(EntryProjection snapshot)
    {
        var cts = new CancellationTokenSource();
        CancellationTokenSource? previous;
        lock (_projectionRebuildGate)
        {
            previous = _projectionRebuildCts;
            _projectionRebuildCts = cts;
        }

        previous?.Cancel();
        _ = RebuildEntriesAsync(snapshot, cts);
    }

    private async Task RebuildEntriesAsync(EntryProjection snapshot, CancellationTokenSource cts)
    {
        try
        {
            var cancellationToken = cts.Token;
            await Task.Delay(ProjectionRebuildDebounce, cancellationToken).ConfigureAwait(true);
            var visibleEntries = await BuildVisibleEntriesAsync(snapshot, cancellationToken).ConfigureAwait(true);
            if (!ProjectionStateMatches(snapshot)) return;

            ReplaceVisibleEntries(visibleEntries);
            PruneSelectionToVisibleEntries();
        }
        catch (OperationCanceledException) { /* superseded by a newer search/sort/load */ }
        finally
        {
            lock (_projectionRebuildGate)
            {
                if (ReferenceEquals(_projectionRebuildCts, cts))
                {
                    _projectionRebuildCts = null;
                }
            }

            cts.Dispose();
        }
    }

    private void CancelPendingProjectionRebuild()
    {
        CancellationTokenSource? pending;
        lock (_projectionRebuildGate)
        {
            pending = _projectionRebuildCts;
            _projectionRebuildCts = null;
        }

        pending?.Cancel();
    }

    private static FileEntryViewModel[] BuildVisibleEntries(
        EntryProjection snapshot,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var hasQuery = snapshot.Query.Length > 0;
        FileEntryViewModel[] visible;

        if (!hasQuery)
        {
            visible = (FileEntryViewModel[])snapshot.Entries.Clone();
        }
        else
        {
            var matches = new List<FileEntryViewModel>(snapshot.Entries.Length);
            foreach (var entry in snapshot.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (entry.Name.Contains(snapshot.Query, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add(entry);
                }
            }

            visible = matches.ToArray();
        }

        if (visible.Length > 1)
        {
            Array.Sort(visible, (x, y) => CompareEntries(x, y, snapshot.SortColumn, snapshot.SortAscending));
        }

        cancellationToken.ThrowIfCancellationRequested();
        return visible;
    }

    private void ReplaceVisibleEntries(FileEntryViewModel[] visibleEntries) =>
        Entries.ReplaceAllIfChanged(visibleEntries);

    private void PruneSelectionToVisibleEntries()
    {
        if (SelectedEntries.Count == 0) return;

        var visible = new HashSet<FileEntryViewModel>(Entries);
        var next = new List<FileEntryViewModel>(SelectedEntries.Count);
        foreach (var selected in SelectedEntries)
        {
            if (visible.Contains(selected))
            {
                next.Add(selected);
            }
        }

        if (next.Count != SelectedEntries.Count)
        {
            SelectedEntries.ReplaceAll(next);
        }
    }

    private void NotifyLoadedEntryStateChanged()
    {
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HasMatches));
        OnPropertyChanged(nameof(HasNoMatches));
    }

    private static int CompareEntries(
        FileEntryViewModel? x,
        FileEntryViewModel? y,
        FilePaneSortColumn sortColumn,
        bool sortAscending)
    {
        if (ReferenceEquals(x, y)) return 0;
        if (x is null) return -1;
        if (y is null) return 1;

        var kind = x.SortKind.CompareTo(y.SortKind);
        if (kind != 0) return kind;

        var primary = sortColumn switch
        {
            FilePaneSortColumn.Size => x.Size.CompareTo(y.Size),
            FilePaneSortColumn.Modified => x.LastModifiedUtc.CompareTo(y.LastModifiedUtc),
            _ => CompareNames(x, y),
        };

        if (primary != 0)
        {
            return sortAscending ? primary : -primary;
        }

        return CompareNames(x, y);
    }

    private static int CompareNames(FileEntryViewModel x, FileEntryViewModel y)
    {
        var name = StringComparer.OrdinalIgnoreCase.Compare(x.Name, y.Name);
        return name != 0
            ? name
            : StringComparer.Ordinal.Compare(x.Name, y.Name);
    }
}
