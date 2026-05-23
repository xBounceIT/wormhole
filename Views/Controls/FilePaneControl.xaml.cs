using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Wormhole.Models;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Views.Controls;

public sealed partial class FilePaneControl : UserControl
{
    private const string PaneSentinelKey = "wormhole/pane";
    private const string PaneItemsKey = "wormhole/items";

    /// <summary>The FileEntryViewModel whose row was most recently right-clicked.
    /// Captured in <see cref="OnEntriesContextRequested"/> and consumed by the
    /// context-menu Click handlers. Cleared (null) when the right-click lands on
    /// the ListView background rather than a specific row.</summary>
    private FileEntryViewModel? _contextTarget;

    public FilePaneViewModel? ViewModel { get; private set; }

    /// <summary>Caller (the dialog) handles transfer requests originating from this pane's
    /// Drop or DragItemsStarting handlers. Must be set before the control is interacted with.</summary>
    public Func<TransferRequest, Task>? OnTransferRequested { get; set; }

    /// <summary>Stages remote files into a local temp directory for OS-level drag-out.
    /// Only meaningful for the remote pane; the local pane reuses its paths directly.</summary>
    public Func<IReadOnlyList<TransferItem>, CancellationToken, Task<IReadOnlyList<string>>>? OnStageForExport { get; set; }

    public FilePaneControl()
    {
        this.InitializeComponent();
    }

    public void SetViewModel(FilePaneViewModel vm)
    {
        ViewModel = vm;
        Bindings.Update();
    }

    private void OnPathBoxKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != VirtualKey.Enter || ViewModel is null) return;
        e.Handled = true;
        _ = ViewModel.LoadAsync(PathBox.Text);
    }

    private async void OnEntryDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (ViewModel is null) return;
        if (EntriesList.SelectedItem is FileEntryViewModel entry && entry.IsDirectory)
        {
            await ViewModel.OpenAsync(entry);
        }
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ViewModel is null) return;
        ViewModel.SelectedEntries.Clear();
        foreach (var item in EntriesList.SelectedItems)
        {
            if (item is FileEntryViewModel fe) ViewModel.SelectedEntries.Add(fe);
        }
    }

    // === toolbar ==============================================================

    private async void OnNewFolderClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null) return;
        var name = await PromptForNameAsync("New folder", "Folder name", "New folder").ConfigureAwait(true);
        if (!string.IsNullOrEmpty(name)) await ViewModel.CreateFolderAsync(name).ConfigureAwait(true);
    }

    private async void OnNewFileClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null) return;
        var name = await PromptForNameAsync("New file", "File name", "new-file.txt").ConfigureAwait(true);
        if (!string.IsNullOrEmpty(name)) await ViewModel.CreateFileAsync(name).ConfigureAwait(true);
    }

    private async void OnDeleteClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null || ViewModel.SelectedEntries.Count == 0) return;
        var count = ViewModel.SelectedEntries.Count;
        var dialog = new ContentDialog
        {
            Title = "Delete",
            Content = $"Delete {count} item{(count == 1 ? string.Empty : "s")}?",
            PrimaryButtonText = "Delete",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = this.XamlRoot,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;
        await ViewModel.DeleteSelectedAsync().ConfigureAwait(true);
    }

    private async Task<string?> PromptForNameAsync(string title, string label, string placeholder)
    {
        var box = new TextBox { Header = label, PlaceholderText = placeholder, MinWidth = 280 };
        var dialog = new ContentDialog
        {
            Title = title,
            Content = box,
            PrimaryButtonText = "Create",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            IsPrimaryButtonEnabled = false,
            XamlRoot = this.XamlRoot,
        };
        box.TextChanged += (_, _) => dialog.IsPrimaryButtonEnabled = !string.IsNullOrWhiteSpace(box.Text);
        dialog.Opened += (_, _) => box.Focus(FocusState.Programmatic);
        var result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary ? box.Text.Trim() : null;
    }

    // === context menu =========================================================
    //
    // Per-container ContextFlyout (the Files-app canonical pattern). Hooking
    // ContextFlyout / RightTapped / ContextRequested on the ListView itself
    // doesn't work: when those fire on the ListView, args.OriginalSource is
    // typically the ListView/ScrollViewer/ItemsPresenter — an ancestor of
    // ListViewItem — so walking VisualTreeHelper.GetParent upward can never
    // reach the right-clicked row's container. Instead:
    //
    //   1. ContainerContentChanging fires per realized (and recycled) row.
    //      We attach the shared MenuFlyout resource to container.ContextFlyout,
    //      plus per-container RightTapped (pointer) and ContextRequested
    //      (keyboard Menu key, touch press-and-hold) handlers.
    //   2. In those per-container handlers, `sender` IS the ListViewItem, so
    //      `lvi.Content` gives us the FileEntryViewModel directly — no tree
    //      walk needed.
    //   3. We unhook on recycle (InRecycleQueue) to avoid duplicate handlers
    //      after a container is reused for a different row.

    private void OnEntriesContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
    {
        if (args.ItemContainer is not ListViewItem container) return;

        // Unhook unconditionally so we never double-subscribe across recycles.
        container.RightTapped -= OnContainerRightTapped;
        container.ContextRequested -= OnContainerContextRequested;

        if (args.InRecycleQueue) return;

        container.ContextFlyout = (MenuFlyout)Resources["EntryContextFlyout"];
        container.RightTapped += OnContainerRightTapped;
        container.ContextRequested += OnContainerContextRequested;
    }

    private void OnContainerRightTapped(object sender, RightTappedRoutedEventArgs e)
    {
        // Pointer path. sender is the ListViewItem; Content is the bound entry.
        if (sender is ListViewItem lvi && lvi.Content is FileEntryViewModel entry)
        {
            _contextTarget = entry;
            // Explorer behaviour: right-click selects the row if it wasn't already
            // selected, so the visual selection matches the menu's target. Leaves
            // existing multi-selection intact when the right-clicked row is in it.
            if (!lvi.IsSelected)
            {
                EntriesList.SelectedItem = entry;
            }
        }
    }

    private void OnContainerContextRequested(UIElement sender, ContextRequestedEventArgs args)
    {
        // Non-pointer path (keyboard Menu key, touch press-and-hold). RightTapped
        // doesn't fire for these, but ContextRequested does — fires per container
        // since this handler is attached on the ListViewItem itself.
        if (sender is ListViewItem lvi && lvi.Content is FileEntryViewModel entry)
        {
            _contextTarget = entry;
        }
    }

    private async void OnContextOpenClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null) return;
        if (_contextTarget is { IsDirectory: true } entry)
        {
            await ViewModel.OpenAsync(entry);
        }
    }

    private void OnContextRenameClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null) return;
        if (_contextTarget is { } entry)
        {
            FilePaneViewModel.BeginRename(entry);
        }
    }

    private void OnContextDeleteClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null || _contextTarget is not { } target) return;

        // Explorer semantics: if the right-clicked item isn't part of the current
        // multi-selection, replace the selection with just it before falling
        // through to the toolbar-style Delete (which reads ViewModel.SelectedEntries).
        // If it IS in the selection, leave the multi-select intact so context-Delete
        // operates on all selected rows. Assigning SelectedItem fires SelectionChanged
        // synchronously, which mirrors into ViewModel.SelectedEntries before
        // OnDeleteClick reads it.
        if (!ViewModel.SelectedEntries.Contains(target))
        {
            EntriesList.SelectedItem = target;
        }
        OnDeleteClick(sender, e);
    }

    // === inline rename ========================================================

    private async void OnRenameKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (sender is not TextBox tb || tb.Tag is not FileEntryViewModel entry || ViewModel is null) return;
        if (e.Key == VirtualKey.Enter)
        {
            e.Handled = true;
            await ViewModel.CommitRenameAsync(entry, tb.Text).ConfigureAwait(true);
        }
        else if (e.Key == VirtualKey.Escape)
        {
            e.Handled = true;
            FilePaneViewModel.CancelRename(entry);
        }
    }

    private async void OnRenameLostFocus(object sender, RoutedEventArgs e)
    {
        if (sender is not TextBox tb || tb.Tag is not FileEntryViewModel entry || ViewModel is null) return;
        // LostFocus fires while IsEditing is still true; if the user typed nothing or
        // the value is unchanged, CommitRenameAsync falls through to a no-op + IsEditing=false.
        if (entry.IsEditing)
        {
            await ViewModel.CommitRenameAsync(entry, tb.Text).ConfigureAwait(true);
        }
    }

    private void OnRenameTextBoxLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is not TextBox tb) return;

        // Loaded fires once on visual-tree entry, where Visibility is usually
        // Collapsed (IsEditing=false on row materialisation). When BeginRename
        // flips IsEditing, the x:Bind binding makes the TextBox visible — but
        // Loaded does NOT re-fire, so we'd never auto-focus and the user would
        // see the rename TextBox appear with no cursor and no selection.
        // Register a DP change callback on Visibility to re-run focus +
        // SelectAll on every Collapsed→Visible transition. The callback
        // survives container recycling because the ListView reuses item
        // containers (and their bound TextBoxes) across virtualisation.
        //
        // FocusState.Pointer (vs Programmatic) mirrors the Files-app rename
        // path: Programmatic focus can be intercepted by a LosingFocus handler
        // higher up the tree, whereas Pointer is treated as user-driven and
        // sails through. Either works in most cases, Pointer is more robust.
        tb.RegisterPropertyChangedCallback(UIElement.VisibilityProperty, (s, _) =>
        {
            if (s is TextBox t && t.Visibility == Visibility.Visible)
            {
                t.Focus(FocusState.Pointer);
                t.SelectAll();
            }
        });

        // Cover the case where the row enters the tree already in edit mode
        // (e.g. a recycled container reused on a row whose VM has IsEditing=true).
        if (tb.Visibility == Visibility.Visible)
        {
            tb.Focus(FocusState.Pointer);
            tb.SelectAll();
        }
    }

    // === drag and drop ========================================================

    private async void OnDragItemsStarting(object sender, DragItemsStartingEventArgs e)
    {
        if (ViewModel is null) return;
        var selected = e.Items.OfType<FileEntryViewModel>().ToList();
        if (selected.Count == 0) return;

        var items = selected
            .Select(s => new TransferItem(s.FullPath, s.Name, s.IsDirectory))
            .ToList();

        // In-app sentinel: the matching Drop on the other pane reads this back without
        // staging temp files. The other pane's Drop also handles the typed item list.
        e.Data.Properties[PaneSentinelKey] = ViewModel.IsLocal ? "Local" : "Remote";
        e.Data.Properties[PaneItemsKey] = items;

        if (ViewModel.IsLocal)
        {
            // Local pane: bytes already on disk, so attach StorageFile/StorageFolder
            // directly. Lets the OS treat this as a normal file drag for Explorer drop.
            var storage = new List<Windows.Storage.IStorageItem>();
            foreach (var s in selected)
            {
                try
                {
                    if (s.IsDirectory)
                        storage.Add(await Windows.Storage.StorageFolder.GetFolderFromPathAsync(s.FullPath));
                    else
                        storage.Add(await Windows.Storage.StorageFile.GetFileFromPathAsync(s.FullPath));
                }
                catch { /* skip non-readable entries */ }
            }
            if (storage.Count > 0) e.Data.SetStorageItems(storage);
        }
        else if (OnStageForExport is not null)
        {
            // Remote pane drag-out: WinUI 3's DragItemsStartingEventArgs has no deferral
            // surface (unlike UIElement.DragStarting). Staging files would have to block
            // the UI thread synchronously, which is unacceptable for multi-MB downloads.
            // Instead: kick off staging in the background and let the queue strip show
            // progress. The OS drag has no StorageItems attached, so Explorer drops are
            // a no-op — but cross-pane drag-and-drop (remote -> local) still works via
            // the pane sentinel + items below. Users wanting to send files to Explorer
            // should drop on the local pane first and re-drag from there.
            //
            // Wrap in a ContinueWith so a network drop / SshConnectionException during
            // staging surfaces in logs rather than vanishing as an UnobservedTaskException.
            _ = OnStageForExport(items, CancellationToken.None).ContinueWith(t =>
            {
                if (t.Exception is { } ex)
                {
                    System.Diagnostics.Debug.WriteLine("Remote drag-out staging failed: " + ex.Message);
                }
            }, TaskScheduler.Default);
        }
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (ViewModel is null) return;
        var hasOtherPane = TryGetOtherPaneSource(e.DataView, out _);
        var hasStorage = e.DataView.Contains(StandardDataFormats.StorageItems);
        if (hasOtherPane || hasStorage)
        {
            e.AcceptedOperation = DataPackageOperation.Copy;
        }
    }

    private async void OnDrop(object sender, DragEventArgs e)
    {
        if (ViewModel is null || OnTransferRequested is null) return;
        var deferral = e.GetDeferral();
        try
        {
            // Cross-pane drop has priority — both sentinel and StorageItems may be set
            // when the source is the local pane (which always attaches StorageItems);
            // the sentinel identifies it as an in-app drag and lets the orchestrator
            // route through SFTP rather than treating it as a file copy.
            if (TryGetOtherPaneSource(e.DataView, out var sourceIsLocal))
            {
                if (e.DataView.Properties.TryGetValue(PaneItemsKey, out var raw) && raw is IReadOnlyList<TransferItem> items && items.Count > 0)
                {
                    var direction = sourceIsLocal
                        ? (ViewModel.IsLocal ? TransferDirection.LocalToLocal : TransferDirection.LocalToRemote)
                        : (ViewModel.IsLocal ? TransferDirection.RemoteToLocal : TransferDirection.RemoteToRemote);
                    if (direction == TransferDirection.LocalToLocal || direction == TransferDirection.RemoteToRemote)
                    {
                        // Same-pane drop in v1 is a no-op. Move/copy in place isn't a
                        // common WinSCP workflow; users navigate then rename instead.
                        return;
                    }
                    await OnTransferRequested(new TransferRequest(direction, ViewModel.CurrentPath, items)).ConfigureAwait(true);
                }
                return;
            }

            if (e.DataView.Contains(StandardDataFormats.StorageItems))
            {
                var storage = await e.DataView.GetStorageItemsAsync();
                var items = storage
                    .Select(s => new TransferItem(s.Path, s.Name, s is Windows.Storage.StorageFolder))
                    .ToList();
                if (items.Count == 0) return;
                // Explorer drop: source is always local on Windows. Target direction is
                // determined by THIS pane (the drop receiver).
                var direction = ViewModel.IsLocal ? TransferDirection.LocalToLocal : TransferDirection.LocalToRemote;
                if (direction == TransferDirection.LocalToLocal)
                {
                    // Explorer → local pane: copy files via System.IO. The orchestrator
                    // doesn't run because there's no SFTP work — direct file copy is
                    // faster and avoids spamming the transfer queue for local moves.
                    await CopyLocalAsync(items, ViewModel.CurrentPath).ConfigureAwait(true);
                    await ViewModel.RefreshAsync().ConfigureAwait(true);
                    return;
                }
                await OnTransferRequested(new TransferRequest(direction, ViewModel.CurrentPath, items)).ConfigureAwait(true);
            }
        }
        finally
        {
            deferral.Complete();
        }
    }

    private static bool TryGetOtherPaneSource(DataPackageView view, out bool sourceIsLocal)
    {
        sourceIsLocal = false;
        if (!view.Properties.TryGetValue(PaneSentinelKey, out var raw) || raw is not string tag) return false;
        sourceIsLocal = tag == "Local";
        return true;
    }

    private static Task CopyLocalAsync(IReadOnlyList<TransferItem> items, string destDir) =>
        Task.Run(() =>
        {
            foreach (var item in items)
            {
                var target = Path.Combine(destDir, item.Name);
                if (item.IsDirectory)
                {
                    CopyDirectory(item.SourcePath, target);
                }
                else
                {
                    File.Copy(item.SourcePath, target, overwrite: true);
                }
            }
        });

    private static void CopyDirectory(string source, string dest)
    {
        Directory.CreateDirectory(dest);
        foreach (var file in Directory.EnumerateFiles(source))
        {
            File.Copy(file, Path.Combine(dest, Path.GetFileName(file)), overwrite: true);
        }
        foreach (var dir in Directory.EnumerateDirectories(source))
        {
            CopyDirectory(dir, Path.Combine(dest, Path.GetFileName(dir)));
        }
    }
}
