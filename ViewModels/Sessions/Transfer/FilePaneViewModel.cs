using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Wormhole.ViewModels.Sessions.Transfer;

/// <summary>
/// Base class for one pane in the file transfer dialog. Subclasses provide the
/// filesystem operations; the base supplies common state (current path, entries,
/// selection, error surface) and command plumbing the toolbar can bind to.
/// </summary>
public abstract partial class FilePaneViewModel : ObservableObject
{
    // Interlocked-backed sentinel for the load-in-progress flag. Using a plain bool
    // here would race: two callers (e.g. concurrent RefreshAsync + LoadInitialAsync)
    // could both observe IsBusy=false before either has set IsBusy=true, then both
    // proceed to Clear/refill Entries — duplicates, missing entries, or stomped
    // SelectedEntries.Clear() depending on interleaving.
    private int _loadInFlight;

    public ObservableCollection<FileEntryViewModel> Entries { get; } = new();

    /// <summary>Selection is two-way bound from the ListView's SelectedItems. The
    /// view layer mirrors selection changes here; toolbar commands read it directly.</summary>
    public ObservableCollection<FileEntryViewModel> SelectedEntries { get; } = new();

    [ObservableProperty]
    private string currentPath = string.Empty;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private bool isBusy;

    /// <summary>Distinguishes the two sides in drag-and-drop handlers without forcing
    /// runtime type checks. Set once in the subclass constructor.</summary>
    public abstract bool IsLocal { get; }

    public abstract string Title { get; }

    public async Task LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        // Atomically claim the load slot: only one LoadAsync runs at a time per pane.
        // CompareExchange returns the original value, so non-zero means already in flight.
        if (Interlocked.CompareExchange(ref _loadInFlight, 1, 0) != 0) return;
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var entries = await ListAsync(path, cancellationToken).ConfigureAwait(true);
            CurrentPath = path;
            Entries.Clear();
            foreach (var e in entries.OrderBy(e => e.SortKind).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
            {
                Entries.Add(e);
            }
            SelectedEntries.Clear();
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

    public void CancelRename(FileEntryViewModel entry)
    {
        if (entry is null) return;
        entry.EditingName = entry.Name;
        entry.IsEditing = false;
    }

    public void BeginRename(FileEntryViewModel entry)
    {
        if (entry is null) return;
        entry.EditingName = entry.Name;
        entry.IsEditing = true;
    }

    protected abstract Task<IReadOnlyList<FileEntryViewModel>> ListAsync(string path, CancellationToken cancellationToken);
    protected abstract Task CreateFolderCoreAsync(string fullPath, CancellationToken cancellationToken);
    protected abstract Task CreateFileCoreAsync(string fullPath, CancellationToken cancellationToken);
    protected abstract Task DeleteCoreAsync(FileEntryViewModel entry, CancellationToken cancellationToken);
    protected abstract Task RenameCoreAsync(FileEntryViewModel entry, string newName, CancellationToken cancellationToken);
    protected abstract string ParentOf(string path);
    protected abstract string Join(string parent, string name);
}
