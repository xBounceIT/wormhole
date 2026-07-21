using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.System;
using Wormhole.Models;
using Wormhole.Services.Sftp;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Views.Controls;

public sealed partial class FilePaneControl : UserControl
{
    private const string PaneSentinelKey = "wormhole/pane";
    private const string PaneItemsKey = "wormhole/items";
    private const string PaneDataFormat = "application/x-wormhole-file-transfer";

    /// <summary>The FileEntryViewModel whose row was most recently right-clicked.
    /// Captured in <see cref="OnEntriesContextRequested"/> and consumed by the
    /// context-menu Click handlers. Cleared (null) when the right-click lands on
    /// the ListView background rather than a specific row.</summary>
    private FileEntryViewModel? _contextTarget;

    /// <summary>Entry currently highlighted as a folder drop target during drag-over.</summary>
    private FileEntryViewModel? _dropHoverEntry;

    private int _dropHoverClearGeneration;

    public FilePaneViewModel? ViewModel { get; private set; }

    /// <summary>Caller (the dialog) handles transfer requests originating from this pane's
    /// Drop or DragItemsStarting handlers. Must be set before the control is interacted with.</summary>
    public Func<TransferRequest, Task>? OnTransferRequested { get; set; }

    public FilePaneControl()
    {
        this.InitializeComponent();
    }

    public void SetViewModel(FilePaneViewModel vm)
    {
        ViewModel = vm;
        Bindings.Update();
    }

    private void OnSortHeaderClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null || sender is not Button { Tag: string rawColumn }) return;
        if (Enum.TryParse<FilePaneSortColumn>(rawColumn, ignoreCase: false, out var column))
        {
            ViewModel.ToggleSort(column);
        }
    }

    /// <summary>
    /// "Open" makes sense in three cases: any local entry (folder navigates, file
    /// launches via OS handler), and remote folders (navigate into them). Remote files
    /// have no defined Open action — there's no local handler to launch them into — so
    /// we hide the menu item for that case only. Called when _contextTarget is set,
    /// just before the MenuFlyout opens.
    /// </summary>
    private void UpdateOpenMenuVisibility()
    {
        var vm = ViewModel;
        var target = _contextTarget;
        bool visible = vm is not null && target is not null && (vm.IsLocal || target.IsDirectory);
        OpenMenuItem.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
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
        if (EntriesList.SelectedItem is FileEntryViewModel entry)
        {
            await OpenEntryAsync(entry);
        }
    }

    /// <summary>
    /// Shared open behavior for both double-click and the context-menu Open item.
    /// Directories navigate in place. Files on the local pane launch with the default
    /// OS handler (Explorer double-click semantics); files on the remote pane do
    /// nothing — there is no local handler to launch a remote file into.
    /// </summary>
    private async Task OpenEntryAsync(FileEntryViewModel entry)
    {
        if (ViewModel is null) return;
        if (entry.IsDirectory)
        {
            await ViewModel.OpenAsync(entry).ConfigureAwait(true);
            return;
        }
        if (!ViewModel.IsLocal) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = entry.FullPath,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            ViewModel.ErrorMessage = ex.Message;
        }
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ViewModel is null) return;
        var selected = new List<FileEntryViewModel>(EntriesList.SelectedItems.Count);
        foreach (var item in EntriesList.SelectedItems)
        {
            if (item is FileEntryViewModel fe) selected.Add(fe);
        }
        ViewModel.SelectedEntries.ReplaceAll(selected);
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

    // Inline confirm/prompt overlays — see FilePaneControl.xaml for the visual layer.
    // The pane lives inside a ContentDialog (FileTransferDialog), and WinUI 3 forbids
    // nested ContentDialogs, so these prompts must not open a new ContentDialog.
    private TaskCompletionSource<bool>? _confirmTcs;
    private TaskCompletionSource<string?>? _promptTcs;

    private async void OnDeleteClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null || ViewModel.SelectedEntries.Count == 0) return;
        var count = ViewModel.SelectedEntries.Count;
        var confirmed = await ShowConfirmAsync(
            title: "Delete",
            message: $"Delete {count} item{(count == 1 ? string.Empty : "s")}?",
            yesLabel: "Delete").ConfigureAwait(true);
        if (!confirmed) return;
        await ViewModel.DeleteSelectedAsync().ConfigureAwait(true);
    }

    private Task<bool> ShowConfirmAsync(string title, string message, string yesLabel)
    {
        // Reentrancy guard: a second click on the toolbar (e.g. via keyboard Tab + Space
        // on an underlying button, or rapid double-click before the first overlay is
        // visible) would otherwise overwrite _confirmTcs and strand the first awaiter
        // forever. Cancel the previous prompt with a No result so its async-void frame
        // unwinds cleanly. Because the TCS uses RunContinuationsAsynchronously, the
        // previous awaiter's CompleteOverlayAsync.finally runs on a later dispatcher
        // message — its hide()/clear() lambdas identity-check the captured tcs (see
        // below) so they don't clobber a freshly-assigned _confirmTcs / Visibility.
        _confirmTcs?.TrySetResult(false);
        // Cross-overlay: if a name-prompt is also open (e.g. user Tabbed past it to the
        // Delete toolbar button), cancel that prompt so only one modal overlay is up
        // at a time. Otherwise both overlays would be Visible and stack their dim
        // backgrounds.
        _promptTcs?.TrySetResult(null);
        ConfirmTitle.Text = title;
        ConfirmMessage.Text = message;
        ConfirmYesButton.Content = yesLabel;
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _confirmTcs = tcs;
        ConfirmOverlay.Visibility = Visibility.Visible;
        // Focus the safe (Cancel) button so Enter is a no-op-equivalent for destructive
        // actions, matching the pre-overlay ContentDialog's DefaultButton=Close.
        // FocusState.Pointer (not Programmatic) so ancestor LosingFocus handlers don't
        // intercept — same rationale documented at OnRenameTextBoxLoaded.
        _ = DispatcherQueue.TryEnqueue(() => ConfirmNoButton.Focus(FocusState.Pointer));
        return CompleteOverlayAsync(tcs.Task,
            () => { if (_confirmTcs == tcs) ConfirmOverlay.Visibility = Visibility.Collapsed; },
            () => { if (_confirmTcs == tcs) _confirmTcs = null; });
    }

    private void OnConfirmYes(object sender, RoutedEventArgs e) => _confirmTcs?.TrySetResult(true);
    private void OnConfirmNo(object sender, RoutedEventArgs e) => _confirmTcs?.TrySetResult(false);

    // Enter = the accented Cancel button (safer than Delete as a default — matches the
    // pre-overlay ContentDialog which had DefaultButton=Close). Escape = Cancel too.
    private void OnConfirmKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter || e.Key == VirtualKey.Escape)
        {
            e.Handled = true;
            _confirmTcs?.TrySetResult(false);
        }
    }

    private Task<string?> PromptForNameAsync(string title, string label, string placeholder)
    {
        // Reentrancy guard — see ShowConfirmAsync for the rationale.
        _promptTcs?.TrySetResult(null);
        // Cross-overlay: cancel a pending confirm prompt so only one modal is up.
        _confirmTcs?.TrySetResult(false);
        PromptTitle.Text = title;
        PromptInput.Header = label;
        PromptInput.PlaceholderText = placeholder;
        PromptInput.Text = string.Empty;
        PromptOkButton.IsEnabled = false;
        var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _promptTcs = tcs;
        PromptOverlay.Visibility = Visibility.Visible;
        // Focus the input after the overlay's container materializes. FocusState.Pointer
        // mirrors the in-row rename pattern at OnRenameTextBoxLoaded — programmatic focus
        // can be intercepted by ancestor LosingFocus handlers, Pointer is treated as
        // user-driven and sails through.
        _ = DispatcherQueue.TryEnqueue(() => PromptInput.Focus(FocusState.Pointer));
        return CompleteOverlayAsync(tcs.Task,
            () => { if (_promptTcs == tcs) PromptOverlay.Visibility = Visibility.Collapsed; },
            () => { if (_promptTcs == tcs) _promptTcs = null; });
    }

    private void OnPromptInputTextChanged(object sender, TextChangedEventArgs e) =>
        PromptOkButton.IsEnabled = !string.IsNullOrWhiteSpace(PromptInput.Text);

    private void OnPromptInputKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter && PromptOkButton.IsEnabled)
        {
            e.Handled = true;
            OnPromptOk(sender, e);
        }
        else if (e.Key == VirtualKey.Escape)
        {
            e.Handled = true;
            OnPromptCancel(sender, e);
        }
    }

    private void OnPromptOk(object sender, RoutedEventArgs e) =>
        _promptTcs?.TrySetResult(string.IsNullOrWhiteSpace(PromptInput.Text) ? null : PromptInput.Text.Trim());

    private void OnPromptCancel(object sender, RoutedEventArgs e) =>
        _promptTcs?.TrySetResult(null);

    // Grid-level handler catches Enter/Escape when focus isn't on the TextBox — e.g. the
    // user has Tabbed onto the Create or Cancel button. Mirrors PromptInput's KeyDown.
    private void OnPromptKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == VirtualKey.Enter && PromptOkButton.IsEnabled)
        {
            e.Handled = true;
            OnPromptOk(sender, e);
        }
        else if (e.Key == VirtualKey.Escape)
        {
            e.Handled = true;
            OnPromptCancel(sender, e);
        }
    }

    private static async Task<T> CompleteOverlayAsync<T>(Task<T> task, Action hide, Action clear)
    {
        try { return await task.ConfigureAwait(true); }
        finally { hide(); clear(); }
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
            UpdateOpenMenuVisibility();
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
            UpdateOpenMenuVisibility();
        }
    }

    private async void OnContextOpenClick(object sender, RoutedEventArgs e)
    {
        if (ViewModel is null || _contextTarget is not { } entry) return;
        await OpenEntryAsync(entry);
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
        if (ViewModel is null)
        {
            e.Cancel = true;
            return;
        }
        var items = new List<TransferItem>(e.Items.Count);
        var selectedLocalItems = ViewModel.IsLocal ? new List<FileEntryViewModel>(e.Items.Count) : null;
        foreach (var rawItem in e.Items)
        {
            if (rawItem is not FileEntryViewModel selected) continue;
            items.Add(new TransferItem(selected.FullPath, selected.Name, selected.IsDirectory));
            selectedLocalItems?.Add(selected);
        }
        if (items.Count == 0)
        {
            e.Cancel = true;
            return;
        }

        var sourceTag = ViewModel.IsLocal ? "Local" : "Remote";

        try
        {
            // Properties are metadata and do not make an otherwise empty DataPackage
            // valid for a drag. Register real in-app content synchronously before the
            // first await so remote drags cannot fail-fast WinUI with E_INVALIDARG.
            e.Data.SetData(PaneDataFormat, sourceTag);
            e.Data.RequestedOperation = DataPackageOperation.Copy;

            // In-app sentinel: the matching Drop on the other pane reads this back
            // without staging temp files and also consumes the typed item list.
            e.Data.Properties[PaneSentinelKey] = sourceTag;
            e.Data.Properties[PaneItemsKey] = items;
        }
        catch (Exception ex)
        {
            e.Cancel = true;
            App.Current.Services.GetService<ILogger<FilePaneControl>>()?.LogWarning(ex, "Could not prepare file drag data.");
            ViewModel.ErrorMessage = ex.Message;
            return;
        }

        if (selectedLocalItems is not null)
        {
            // Local pane: bytes already on disk, so attach StorageFile/StorageFolder
            // directly. Lets the OS treat this as a normal file drag for Explorer drop.
            var storage = new List<Windows.Storage.IStorageItem>(selectedLocalItems.Count);
            foreach (var s in selectedLocalItems)
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
            if (storage.Count > 0)
            {
                try
                {
                    e.Data.SetStorageItems(storage);
                }
                catch (Exception ex)
                {
                    // The in-app payload is already valid. If WinUI has locked the
                    // package after an asynchronous path lookup, only drag-out to
                    // Explorer is unavailable; do not let async-void tear down the app.
                    App.Current.Services.GetService<ILogger<FilePaneControl>>()?.LogWarning(ex, "Could not attach local storage items to file drag data.");
                }
            }
        }
        // Remote pane: only the in-app sentinel + items above are attached. Cross-pane
        // drops (remote → local) read those back in OnDrop. OS-level drag-out to Explorer
        // is intentionally unsupported — WinUI 3 has no DragItemsStarting deferral, so
        // there is no way to attach StorageItems after a background download completes.
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (ViewModel is null) return;
        _dropHoverClearGeneration++;
        var hasOtherPane = TryGetOtherPaneSource(e.DataView, out _);
        var hasStorage = e.DataView.Contains(StandardDataFormats.StorageItems);
        if (!hasOtherPane && !hasStorage)
        {
            ClearDropHover();
            return;
        }

        var targetItem = ResolveDropTargetListViewItem(e);
        var entry = targetItem?.Content as FileEntryViewModel;
        var destination = ResolveDropDestination(entry);
        if (hasOtherPane &&
            e.DataView.Properties.TryGetValue(PaneItemsKey, out var raw) &&
            raw is IReadOnlyList<TransferItem> paneItems &&
            IsInvalidDropDestination(destination, paneItems))
        {
            e.AcceptedOperation = DataPackageOperation.None;
            ClearDropHover();
            return;
        }

        UpdateDropHover(entry);
        e.AcceptedOperation = DataPackageOperation.Copy;
    }

    private void OnDragLeave(object sender, DragEventArgs e)
    {
        // ListView DragLeave also fires when moving between rows (parent→child).
        // Defer the clear so a subsequent DragOver on the next row can cancel it.
        var generation = ++_dropHoverClearGeneration;
        _ = DispatcherQueue.TryEnqueue(() =>
        {
            if (generation != _dropHoverClearGeneration) return;
            ClearDropHover();
        });
    }

    private async void OnDrop(object sender, DragEventArgs e)
    {
        if (ViewModel is null || OnTransferRequested is null) return;
        ClearDropHover();
        var deferral = e.GetDeferral();
        var dropEntry = ResolveDropTargetListViewItem(e)?.Content as FileEntryViewModel;
        var destination = ResolveDropDestination(dropEntry);
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
                    // Fire-and-forget: do NOT await the orchestrator inline. The drag-drop
                    // deferral must be completed promptly so Explorer's "busy" cursor (or
                    // the source pane's drag state) clears as soon as the drop is queued —
                    // not after a multi-MB SFTP transfer has finished bytes. Errors are
                    // logged inside RunTransferAsync; the destination pane refreshes when
                    // the transfer completes.
                    if (IsInvalidDropDestination(destination, items)) return;
                    FireAndForgetTransfer(new TransferRequest(direction, destination, items));
                }
                return;
            }

            if (e.DataView.Contains(StandardDataFormats.StorageItems))
            {
                var storage = await e.DataView.GetStorageItemsAsync();
                var items = new List<TransferItem>(storage.Count);
                foreach (var item in storage)
                {
                    items.Add(new TransferItem(
                        item.Path,
                        item.Name,
                        item is Windows.Storage.StorageFolder));
                }
                if (items.Count == 0) return;
                if (IsInvalidDropDestination(destination, items)) return;
                // Explorer drop: source is always local on Windows. Target direction is
                // determined by THIS pane (the drop receiver).
                var direction = ViewModel.IsLocal ? TransferDirection.LocalToLocal : TransferDirection.LocalToRemote;
                if (direction == TransferDirection.LocalToLocal)
                {
                    // Explorer → local pane: copy files via System.IO. The orchestrator
                    // doesn't run because there's no SFTP work — direct file copy is
                    // faster and avoids spamming the transfer queue for local moves.
                    await CopyLocalAsync(items, destination).ConfigureAwait(true);
                    await ViewModel.RefreshAsync().ConfigureAwait(true);
                    return;
                }
                FireAndForgetTransfer(new TransferRequest(direction, destination, items));
            }
        }
        catch (Exception ex)
        {
            // OnDrop is async void; an unhandled exception (e.g. GetStorageItemsAsync
            // throwing on a vanished source file, File.Copy failing for permissions,
            // CopyDirectory hitting a denied subtree) would otherwise escape to
            // AppDomain.UnhandledException. Surface to the pane's ErrorMessage so the
            // user sees the failure, and log via the standard Serilog sink.
            App.Current?.Services?.GetService<ILogger<FilePaneControl>>()?.LogWarning(ex, "Drop handler failed.");
            if (ViewModel is { } vm) vm.ErrorMessage = ex.Message;
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

    private string ResolveDropDestination(FileEntryViewModel? entry)
    {
        if (ViewModel is null) return string.Empty;
        return TransferDropTarget.ResolveDestinationDirectory(
            ViewModel.CurrentPath,
            entry?.FullPath,
            entry?.IsDirectory == true);
    }

    private bool IsInvalidDropDestination(string destination, IReadOnlyList<TransferItem> items) =>
        ViewModel is { IsLocal: true } && TransferDropTarget.IsInvalidLocalDropDestination(destination, items);

    private ListViewItem? ResolveDropTargetListViewItem(DragEventArgs e)
    {
        // Row templates use a transparent Background so pointer hits span the full
        // realized height. Walk only the visual tree — realized containers only —
        // instead of enumerating every bound item on each DragOver.
        if (e.OriginalSource is DependencyObject source)
        {
            var fromSource = FindOwningListViewItem(source);
            if (fromSource is not null) return fromSource;
        }

        var point = e.GetPosition(EntriesList);
        foreach (var element in VisualTreeHelper.FindElementsInHostCoordinates(point, EntriesList, includeAllElements: true))
        {
            if (element is ListViewItem item) return item;
            var owner = FindOwningListViewItem(element);
            if (owner is not null) return owner;
        }

        return null;
    }

    private static ListViewItem? FindOwningListViewItem(DependencyObject source)
    {
        var current = source;
        while (current is not null)
        {
            if (current is ListViewItem item) return item;
            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private void UpdateDropHover(FileEntryViewModel? entry)
    {
        var hoverEntry = entry is { IsDirectory: true } ? entry : null;
        if (ReferenceEquals(_dropHoverEntry, hoverEntry)) return;

        ClearDropHover();
        if (hoverEntry is null) return;

        _dropHoverEntry = hoverEntry;
        hoverEntry.IsDropTarget = true;
    }

    private void ClearDropHover()
    {
        _dropHoverClearGeneration++;
        if (_dropHoverEntry is null) return;
        _dropHoverEntry.IsDropTarget = false;
        _dropHoverEntry = null;
    }

    /// <summary>
    /// Kick off a transfer + post-transfer pane refresh without awaiting in the caller's
    /// frame. Used by OnDrop so the drag-drop deferral can complete promptly instead of
    /// pinning the source application's drag cursor for the entire SFTP batch. Per-row
    /// errors surface through the transfer queue strip's ErrorMessage tooltip; an
    /// orchestrator-level fault that escapes EnqueueAsync (or a RefreshAsync that throws
    /// on a torn-down VM) goes to the standard Serilog sink under
    /// %LOCALAPPDATA%\Wormhole\logs\ — Debug.WriteLine would be elided in Release.
    /// </summary>
    private void FireAndForgetTransfer(TransferRequest request)
    {
        var vm = ViewModel;
        var requested = OnTransferRequested;
        if (vm is null || requested is null) return;
        var logger = App.Current.Services.GetService<ILogger<FilePaneControl>>();
        _ = RunTransferAsync(requested, vm, request, logger);
    }

    private static async Task RunTransferAsync(Func<TransferRequest, Task> requested, FilePaneViewModel vm, TransferRequest request, ILogger? logger)
    {
        try
        {
            await requested(request).ConfigureAwait(true);
            await vm.RefreshAsync().ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            // User closed the dialog mid-transfer or cancelled an individual row — the
            // orchestrator's _shutdown.Token surfaces here as OCE. Not a failure.
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "Background transfer failed.");
        }
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
        foreach (var entry in new DirectoryInfo(source).EnumerateFileSystemInfos())
        {
            var target = Path.Combine(dest, entry.Name);
            if (entry is DirectoryInfo directory)
            {
                CopyDirectory(directory.FullName, target);
            }
            else if (entry is FileInfo file)
            {
                file.CopyTo(target, overwrite: true);
            }
        }
    }
}
