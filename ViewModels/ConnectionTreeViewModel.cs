using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class ConnectionTreeViewModel : ObservableObject
{
    private readonly IConnectionRepository _repository;
    private readonly InheritanceResolver _inheritanceResolver;
    private readonly ISessionTabFactory _tabFactory;
    private readonly IDialogService _dialog;
    private readonly ILogger<ConnectionTreeViewModel> _logger;
    private IReadOnlyList<ConnectionNode> _lastSnapshot = Array.Empty<ConnectionNode>();
    private Dictionary<Guid, ConnectionNode> _lastSnapshotById = new();
    private bool _isLoading;

    public BulkObservableCollection<TreeNodeViewModel> Roots { get; } = new();

    [ObservableProperty]
    private TreeNodeViewModel? selectedNode;

    [ObservableProperty]
    private string searchText = string.Empty;

    // Captured the moment a filter starts so clearing the search restores the tree
    // to exactly how the user had it expanded before they typed.
    private Dictionary<Guid, bool>? _expandStateBeforeFilter;

    // Coalesces rapid keystrokes — the AutoSuggestBox binds with
    // UpdateSourceTrigger=PropertyChanged, so without this every character would walk
    // the entire tree (O(n) with property writes per node). Tests override to zero so
    // assertions remain synchronous after a SearchText assignment.
    internal TimeSpan SearchDebounceDelay { get; set; } = TimeSpan.FromMilliseconds(120);

    private CancellationTokenSource? _filterDebounceCts;

    partial void OnSearchTextChanged(string? oldValue, string newValue)
    {
        var wasFiltering = !string.IsNullOrWhiteSpace(oldValue);
        var isFiltering = !string.IsNullOrWhiteSpace(newValue);

        // Snapshot on the leading edge — even when the filter walk is deferred — so the
        // restore-on-clear path captures the pre-filter expansion regardless of how the
        // user's keystrokes get batched.
        if (!wasFiltering && isFiltering)
        {
            _expandStateBeforeFilter = SnapshotExpandState(Roots);
        }

        // Cancel any in-flight debounce so the latest keystroke supersedes prior ones.
        var prior = _filterDebounceCts;
        _filterDebounceCts = null;
        if (prior is not null)
        {
            try { prior.Cancel(); } catch (ObjectDisposedException) { }
            prior.Dispose();
        }

        if (SearchDebounceDelay <= TimeSpan.Zero)
        {
            ApplyFilterAndMaybeRestore(newValue, wasFiltering, isFiltering);
            return;
        }

        var cts = new CancellationTokenSource();
        _filterDebounceCts = cts;
        _ = DebouncedApplyFilterAsync(newValue, wasFiltering, isFiltering, cts);
    }

    private async Task DebouncedApplyFilterAsync(
        string newValue,
        bool wasFiltering,
        bool isFiltering,
        CancellationTokenSource cts)
    {
        try
        {
            // ConfigureAwait(true) keeps the continuation on the captured SyncContext —
            // the WinUI UI thread in production — so ApplyFilter's property writes don't
            // race the UI thread's tree-render pass.
            await Task.Delay(SearchDebounceDelay, cts.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        finally
        {
            // Only dispose the CTS we own; a follow-on keystroke may have already
            // replaced _filterDebounceCts with a fresher one.
            if (ReferenceEquals(_filterDebounceCts, cts))
            {
                _filterDebounceCts = null;
            }
            cts.Dispose();
        }

        // Freshness guard: if Task.Delay completed *normally* (cancel-race lost) but a
        // newer keystroke already replaced _filterDebounceCts between our delay and this
        // point, our newValue is stale. The finally above nulls _filterDebounceCts only
        // when we still own the slot — a non-null read here means a fresher task is
        // pending and will run its own ApplyFilterAndMaybeRestore at its own deadline.
        // Without this guard, the user briefly sees an older filter over their current
        // input during fast typing.
        if (_filterDebounceCts is not null) return;

        ApplyFilterAndMaybeRestore(newValue, wasFiltering, isFiltering);
    }

    private void ApplyFilterAndMaybeRestore(string newValue, bool wasFiltering, bool isFiltering)
    {
        ApplyFilter(newValue);

        if (wasFiltering && !isFiltering && _expandStateBeforeFilter is not null)
        {
            RestoreExpandState(Roots, _expandStateBeforeFilter);
            _expandStateBeforeFilter = null;
        }
    }

    public ConnectionTreeViewModel(
        IConnectionRepository repository,
        InheritanceResolver inheritanceResolver,
        ISessionTabFactory tabFactory,
        IDialogService dialog,
        ILogger<ConnectionTreeViewModel> logger)
    {
        _repository = repository;
        _inheritanceResolver = inheritanceResolver;
        _tabFactory = tabFactory;
        _dialog = dialog;
        _logger = logger;
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        if (_isLoading) return;
        _isLoading = true;
        try
        {
            await LoadAsync();
        }
        finally
        {
            _isLoading = false;
        }
    }

    [RelayCommand]
    public async Task OpenConnectionAsync(TreeNodeViewModel? vm)
    {
        if (vm is null || vm.Kind != NodeKind.Connection) return;

        try
        {
            if (!_lastSnapshotById.TryGetValue(vm.Node.Id, out var node))
            {
                await RefreshAsync();
                if (!_lastSnapshotById.TryGetValue(vm.Node.Id, out node)) return;
            }

            var profile = _inheritanceResolver.Resolve(node, _lastSnapshotById);
            // Factory dispatches by protocol: SSH gets the real terminal, RDP/SFTP get
            // placeholder tabs whose DataTemplate renders the "not implemented yet" notice.
            _tabFactory.Open(profile);
        }
        catch (Exception ex)
        {
            // Mirror the add/edit/delete error-path convention: log and surface the
            // failure via a dialog instead of letting the exception escape as an
            // unhandled RelayCommand failure.
            _logger.LogError(ex, "Failed to open connection '{Name}'", vm.Name);
            await _dialog.ShowMessageAsync("Couldn't open connection", ex.Message);
        }
    }

    [RelayCommand]
    private async Task AddFolder(TreeNodeViewModel? clicked)
    {
        var parentId = ResolveParentId(clicked);
        var seed = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            ParentId = parentId,
            SortOrder = NextSortOrder(parentId),
        };
        var edited = await _dialog.EditFolderAsync(seed, isNew: true);
        if (edited is null) return;
        await SafeAddAsync(edited);
    }

    [RelayCommand]
    private async Task AddConnection(TreeNodeViewModel? clicked)
    {
        var parentId = ResolveParentId(clicked);
        var seed = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            ParentId = parentId,
            SortOrder = NextSortOrder(parentId),
            Protocol = ProtocolType.Ssh,
        };
        var edited = await _dialog.EditConnectionAsync(seed, isNew: true);
        if (edited is null) return;
        await SafeAddAsync(edited);
    }

    [RelayCommand]
    private async Task Edit(TreeNodeViewModel? clicked)
    {
        if (clicked is null) return;
        var node = clicked.Node;

        if (node.Kind == NodeKind.Folder)
        {
            var editedFolder = await _dialog.EditFolderAsync(node, isNew: false);
            if (editedFolder is null) return;
            await SafeUpdateAsync(editedFolder);
            return;
        }

        var edited = await _dialog.EditConnectionAsync(node, isNew: false);
        if (edited is null) return;
        await SafeUpdateAsync(edited);
    }

    [RelayCommand]
    private void ExpandAll() => SetExpandedRecursive(Roots, true);

    [RelayCommand]
    private void CollapseAll() => SetExpandedRecursive(Roots, false);

    private static void SetExpandedRecursive(IEnumerable<TreeNodeViewModel> level, bool expanded)
    {
        foreach (var node in level)
        {
            if (node.Kind == NodeKind.Folder)
            {
                node.IsExpanded = expanded;
            }
            SetExpandedRecursive(node.Children, expanded);
        }
    }

    [RelayCommand]
    private async Task ImportFromMRemoteNg()
    {
        try
        {
            var result = await _dialog.PromptForMRemoteNgImportAsync();
            if (result is not null)
            {
                // Result is non-null only when CommitAsync succeeded; refresh the tree so the
                // newly persisted folders/connections appear without requiring a restart.
                await RefreshAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to open mRemoteNG import dialog");
            await _dialog.ShowMessageAsync("Couldn't import", ex.Message);
        }
    }

    [RelayCommand]
    private async Task Delete(TreeNodeViewModel? clicked)
    {
        if (clicked is null) return;
        var node = clicked.Node;

        var descendantCount = CountDescendants(clicked);
        var message = descendantCount == 0
            ? $"Delete '{node.Name}'? This cannot be undone."
            : $"Delete '{node.Name}' and its {descendantCount} nested item{(descendantCount == 1 ? "" : "s")}? This cannot be undone.";

        var confirmed = await _dialog.ConfirmAsync("Delete", message, primaryText: "Delete", closeText: "Cancel");
        if (!confirmed) return;

        try
        {
            await _repository.DeleteAsync(node.Id);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete {Kind} '{Name}'", node.Kind, node.Name);
            await _dialog.ShowMessageAsync("Couldn't delete", ex.Message);
        }
    }

    private async Task SafeUpdateAsync(ConnectionNode node)
    {
        try
        {
            await _repository.UpdateAsync(node);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update {Kind} '{Name}'", node.Kind, node.Name);
            await _dialog.ShowMessageAsync("Couldn't save", ex.Message);
            // PersistTreeStructureAsync mutates ParentId/SortOrder on the live nodes before
            // calling here (see ApplyAndCollectChangedNodes), so on failure the in-memory
            // tree is ahead of the DB. Reload so the tree reflects what was actually
            // committed, not the unsaved draft. (Edit-flow callers pass a fresh clone and
            // don't touch the original node, so this reload is a no-op for them.)
            await RefreshAsync();
        }
    }

    private static int CountDescendants(TreeNodeViewModel node)
    {
        var count = 0;
        foreach (var child in node.Children)
        {
            count++;
            count += CountDescendants(child);
        }
        return count;
    }

    public async Task PersistTreeStructureAsync()
    {
        // The TreeView has already mutated Roots/Children to reflect the drop. Validate
        // the new shape, then write back any node whose ParentId or SortOrder changed.
        // A folder dropped onto its own descendant can disappear from Roots (TreeView removes
        // it from the old parent, attaches it under the descendant), so the cycle ends up
        // disconnected from this walk. seen.Count < _lastSnapshot.Count catches that orphan
        // case alongside ordinary cycles and invalid connection parents.
        var seen = new HashSet<Guid>();
        var structurallyInvalid = HasCycleOrInvalidParent(Roots, seen);
        if (structurallyInvalid || seen.Count != _lastSnapshot.Count)
        {
            _logger.LogWarning("Rejected drag-drop: result would create a cycle or place a child under a connection.");
            await _dialog.ShowMessageAsync(
                "Move not allowed",
                "Connections can't contain children, and folders can't be moved inside themselves.");
            await RefreshAsync();
            return;
        }

        var updates = new List<ConnectionNode>();
        ApplyAndCollectChangedNodes(Roots, parentId: null, updates);
        if (updates.Count == 0) return;

        try
        {
            await _repository.UpdateManyAsync(updates);
            SetSnapshot(await _repository.GetAllAsync());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist drag-drop reorder");
            await _dialog.ShowMessageAsync("Couldn't save", ex.Message);
            await RefreshAsync();
        }
    }

    private static bool HasCycleOrInvalidParent(IList<TreeNodeViewModel> level, HashSet<Guid> seen)
    {
        foreach (var n in level)
        {
            if (!seen.Add(n.Node.Id)) return true;
            if (n.Kind == NodeKind.Connection && n.Children.Count > 0) return true;
            if (HasCycleOrInvalidParent(n.Children, seen)) return true;
        }
        return false;
    }

    // Walks the tree, rewriting ParentId/SortOrder on any node whose position changed
    // and collecting those mutated entities for the caller to persist.
    // CA1859 nudges ObservableCollection<T> here, but Collection<T>.this[int] and Count
    // are virtual — no devirtualization win, and the interface is less coupling.
#pragma warning disable CA1859
    private static void ApplyAndCollectChangedNodes(
        IList<TreeNodeViewModel> level,
        Guid? parentId,
        List<ConnectionNode> updates)
#pragma warning restore CA1859
    {
        for (var i = 0; i < level.Count; i++)
        {
            var n = level[i];
            if (n.Node.ParentId != parentId || n.Node.SortOrder != i)
            {
                n.Node.ParentId = parentId;
                n.Node.SortOrder = i;
                updates.Add(n.Node);
            }
            ApplyAndCollectChangedNodes(n.Children, n.Node.Id, updates);
        }
    }

    private static Guid? ResolveParentId(TreeNodeViewModel? clicked) =>
        clicked is null ? null
      : clicked.Kind == NodeKind.Folder ? clicked.Node.Id
      : clicked.Node.ParentId;

    private int NextSortOrder(Guid? parentId)
    {
        var max = -1;
        foreach (var node in _lastSnapshot)
        {
            if (node.ParentId == parentId && node.SortOrder > max)
            {
                max = node.SortOrder;
            }
        }
        return max + 1;
    }

    private async Task SafeAddAsync(ConnectionNode node)
    {
        try
        {
            await _repository.AddAsync(node);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add {Kind} '{Name}'", node.Kind, node.Name);
            await _dialog.ShowMessageAsync("Couldn't save", ex.Message);
        }
    }

    private async Task LoadAsync()
    {
        var all = await _repository.GetAllAsync();
        SetSnapshot(all);

        var byParent = new Dictionary<Guid, List<ConnectionNode>>();
        var topLevel = new List<ConnectionNode>();
        foreach (var node in all)
        {
            if (node.ParentId is null)
            {
                topLevel.Add(node);
                continue;
            }
            if (!byParent.TryGetValue(node.ParentId.Value, out var list))
            {
                list = new List<ConnectionNode>();
                byParent[node.ParentId.Value] = list;
            }
            list.Add(node);
        }

        Reconcile(Roots, topLevel, byParent);

        if (SelectedNode is not null && !_lastSnapshotById.ContainsKey(SelectedNode.Node.Id))
        {
            SelectedNode = null;
        }

        // New nodes default to IsVisible=true, so skip the rewalk when no filter is
        // active — Reconcile already produced the correct state.
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            ApplyFilter(SearchText);
        }
    }

    private void ApplyFilter(string query)
    {
        var trimmed = query.Trim();
        if (trimmed.Length == 0)
        {
            MarkAllVisible(Roots);
            return;
        }

        EvaluateFilter(Roots, trimmed);
    }

    private static void MarkAllVisible(IEnumerable<TreeNodeViewModel> level)
    {
        foreach (var node in level)
        {
            node.IsVisible = true;
            MarkAllVisible(node.Children);
        }
    }

    private static bool EvaluateFilter(IEnumerable<TreeNodeViewModel> level, string query)
    {
        var anyVisible = false;
        foreach (var node in level)
        {
            var nameMatches = node.Name.Contains(query, StringComparison.OrdinalIgnoreCase);

            if (node.Kind == NodeKind.Folder)
            {
                if (nameMatches)
                {
                    // Folder name matched — show the folder and everything beneath it,
                    // and expand it so the contents the user searched for are actually
                    // visible. The pre-filter IsExpanded value is in the snapshot, so
                    // clearing the search will restore the original collapsed state.
                    node.IsVisible = true;
                    node.IsExpanded = true;
                    MarkAllVisible(node.Children);
                }
                else
                {
                    var hasVisibleChild = EvaluateFilter(node.Children, query);
                    node.IsVisible = hasVisibleChild;
                    // Auto-expand non-matching folders that contain a match so the
                    // matching descendant is actually rendered.
                    if (hasVisibleChild) node.IsExpanded = true;
                }
            }
            else
            {
                node.IsVisible = nameMatches;
            }

            if (node.IsVisible) anyVisible = true;
        }
        return anyVisible;
    }

    private static Dictionary<Guid, bool> SnapshotExpandState(IEnumerable<TreeNodeViewModel> level)
    {
        var snapshot = new Dictionary<Guid, bool>();
        CollectExpandState(level, snapshot);
        return snapshot;
    }

    private static void CollectExpandState(IEnumerable<TreeNodeViewModel> level, Dictionary<Guid, bool> snapshot)
    {
        foreach (var node in level)
        {
            if (node.Kind == NodeKind.Folder)
            {
                snapshot[node.Node.Id] = node.IsExpanded;
            }
            CollectExpandState(node.Children, snapshot);
        }
    }

    private static void RestoreExpandState(IEnumerable<TreeNodeViewModel> level, IReadOnlyDictionary<Guid, bool> snapshot)
    {
        foreach (var node in level)
        {
            if (node.Kind == NodeKind.Folder && snapshot.TryGetValue(node.Node.Id, out var wasExpanded))
            {
                node.IsExpanded = wasExpanded;
            }
            RestoreExpandState(node.Children, snapshot);
        }
    }

    // Mutates `current` in place to match `target` (and recursively each node's children),
    // reusing existing TreeNodeViewModel instances by Id so the TreeView's container
    // tree — and therefore selection, expansion, focus — survives the refresh.
    private static void Reconcile(
        BulkObservableCollection<TreeNodeViewModel> current,
        IReadOnlyList<ConnectionNode> target,
        IReadOnlyDictionary<Guid, List<ConnectionNode>> byParent)
    {
        if (current.Count == 0)
        {
            if (target.Count == 0) return;

            var next = new List<TreeNodeViewModel>(target.Count);
            foreach (var node in target)
            {
                var vm = new TreeNodeViewModel(node);
                byParent.TryGetValue(node.Id, out var children);
                Reconcile(vm.Children, children ?? (IReadOnlyList<ConnectionNode>)Array.Empty<ConnectionNode>(), byParent);
                next.Add(vm);
            }

            current.ReplaceAll(next);
            return;
        }

        var targetIds = new HashSet<Guid>(target.Count);
        foreach (var n in target) targetIds.Add(n.Id);

        for (var i = current.Count - 1; i >= 0; i--)
        {
            if (!targetIds.Contains(current[i].Node.Id))
            {
                current.RemoveAt(i);
            }
        }

        var existingById = new Dictionary<Guid, TreeNodeViewModel>(current.Count);
        var currentIndexById = new Dictionary<Guid, int>(current.Count);
        for (var i = 0; i < current.Count; i++)
        {
            var vm = current[i];
            existingById[vm.Node.Id] = vm;
            currentIndexById[vm.Node.Id] = i;
        }

        for (var i = 0; i < target.Count; i++)
        {
            var node = target[i];
            TreeNodeViewModel vm;
            if (!existingById.TryGetValue(node.Id, out var existing))
            {
                vm = new TreeNodeViewModel(node);
                current.Insert(i, vm);
                existingById[node.Id] = vm;
                RefreshIndexMap(current, currentIndexById, start: i, endInclusive: current.Count - 1);
            }
            else
            {
                vm = existing;
                vm.Node = node;
                if (i >= current.Count || !ReferenceEquals(current[i], vm))
                {
                    if (currentIndexById.TryGetValue(node.Id, out var existingIdx) && existingIdx != i)
                    {
                        current.Move(existingIdx, i);
                        RefreshIndexMap(
                            current,
                            currentIndexById,
                            start: Math.Min(existingIdx, i),
                            endInclusive: Math.Max(existingIdx, i));
                    }
                }
            }

            byParent.TryGetValue(node.Id, out var children);
            Reconcile(vm.Children, children ?? (IReadOnlyList<ConnectionNode>)Array.Empty<ConnectionNode>(), byParent);
        }
    }

    private static void RefreshIndexMap(
        BulkObservableCollection<TreeNodeViewModel> current,
        Dictionary<Guid, int> currentIndexById,
        int start,
        int endInclusive)
    {
        for (var i = start; i <= endInclusive; i++)
        {
            currentIndexById[current[i].Node.Id] = i;
        }
    }

    private void SetSnapshot(IReadOnlyList<ConnectionNode> snapshot)
    {
        _lastSnapshot = snapshot;
        var byId = new Dictionary<Guid, ConnectionNode>(snapshot.Count);
        foreach (var node in snapshot)
        {
            byId[node.Id] = node;
        }
        _lastSnapshotById = byId;
    }
}

public sealed partial class TreeNodeViewModel : ObservableObject
{
    public TreeNodeViewModel(ConnectionNode node)
    {
        this.node = node;
    }

    [ObservableProperty]
    private ConnectionNode node = null!;

    public BulkObservableCollection<TreeNodeViewModel> Children { get; } = new();
    public string Name => Node.Name;
    public NodeKind Kind => Node.Kind;

    [ObservableProperty]
    private bool isExpanded;

    // Drives the per-row Visibility binding when a search filter is active.
    // Default true so unfiltered loads render the whole tree.
    [ObservableProperty]
    private bool isVisible = true;

    public string Glyph => Kind == NodeKind.Folder
        ? Glyphs.Folder
        : Node.Protocol switch
        {
            ProtocolType.Ssh => Glyphs.Ssh,
            ProtocolType.Rdp => Glyphs.Rdp,
            ProtocolType.Sftp => Glyphs.Sftp,
            _ => Glyphs.Generic,
        };

    partial void OnNodeChanged(ConnectionNode value)
    {
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Kind));
        OnPropertyChanged(nameof(Glyph));
    }
}
