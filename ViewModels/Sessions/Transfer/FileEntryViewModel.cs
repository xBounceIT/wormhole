using CommunityToolkit.Mvvm.ComponentModel;

namespace Wormhole.ViewModels.Sessions.Transfer;

public sealed partial class FileEntryViewModel : ObservableObject
{
    [ObservableProperty]
    private string name;

    [ObservableProperty]
    private string fullPath;

    [ObservableProperty]
    private bool isDirectory;

    [ObservableProperty]
    private bool isSymbolicLink;

    [ObservableProperty]
    private long size;

    [ObservableProperty]
    private DateTime lastModifiedUtc;

    /// <summary>Toggled on by the pane VM when the user invokes Rename; the row's
    /// DataTemplate swaps a TextBlock for a TextBox bound to <see cref="EditingName"/>.</summary>
    [ObservableProperty]
    private bool isEditing;

    /// <summary>Mutable buffer for the rename TextBox. Reset to <see cref="Name"/> when
    /// the user cancels the edit (Esc / lose focus without commit).</summary>
    [ObservableProperty]
    private string editingName;

    /// <summary>Transient drag-over highlight for folder drop targets. Toggled by
    /// <c>FilePaneControl</c> during cross-pane / Explorer drag-over; never persisted.</summary>
    [ObservableProperty]
    private bool isDropTarget;

    public FileEntryViewModel(string name, string fullPath, bool isDirectory, bool isSymbolicLink, long size, DateTime lastModifiedUtc)
    {
        this.name = name;
        this.fullPath = fullPath;
        this.isDirectory = isDirectory;
        this.isSymbolicLink = isSymbolicLink;
        this.size = size;
        this.lastModifiedUtc = lastModifiedUtc;
        this.editingName = name;
    }

    /// <summary>Three-state sort key for the pane's default order: directories first,
    /// then files, with symlinks (whose targets we don't resolve) interleaved by name.</summary>
    public int SortKind => IsDirectory ? 0 : 1;
}
