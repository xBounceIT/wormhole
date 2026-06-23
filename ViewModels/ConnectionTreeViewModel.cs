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
    private readonly ICredentialService _credentialService;
    private readonly ICredentialRepository _credentialRepository;
    private readonly ILogger<ConnectionTreeViewModel> _logger;
    private IReadOnlyList<ConnectionNode> _lastSnapshot = Array.Empty<ConnectionNode>();
    private Dictionary<Guid, ConnectionNode> _lastSnapshotById = new();
    private bool _isLoading;

    public BulkObservableCollection<TreeNodeViewModel> Roots { get; } = new();
    public BulkObservableCollection<TreeNodeViewModel> SelectedNodes { get; } = new();

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
        ICredentialService credentialService,
        ICredentialRepository credentialRepository,
        ILogger<ConnectionTreeViewModel> logger)
    {
        _repository = repository;
        _inheritanceResolver = inheritanceResolver;
        _tabFactory = tabFactory;
        _dialog = dialog;
        _credentialService = credentialService;
        _credentialRepository = credentialRepository;
        _logger = logger;
    }

    public void SetSelectedNodes(IEnumerable<TreeNodeViewModel> nodes)
    {
        var selected = new List<TreeNodeViewModel>();
        var seen = new HashSet<Guid>();
        foreach (var node in nodes)
        {
            if (!seen.Add(node.Node.Id)) continue;
            selected.Add(node);
        }

        SelectedNodes.ReplaceAll(selected);
        SelectedNode = selected.Count == 0 ? null : selected[^1];
    }

    public bool ShouldRejectDragSelection(IEnumerable<TreeNodeViewModel> draggedNodes)
    {
        var draggedIds = new HashSet<Guid>();
        foreach (var node in draggedNodes)
        {
            draggedIds.Add(node.Node.Id);
        }

        if (draggedIds.Count < 2) return false;

        var stack = new Stack<(TreeNodeViewModel Node, bool AncestorDragged)>();
        for (var i = Roots.Count - 1; i >= 0; i--)
        {
            stack.Push((Roots[i], false));
        }

        while (stack.Count > 0)
        {
            var (node, ancestorDragged) = stack.Pop();
            var isDragged = draggedIds.Contains(node.Node.Id);
            if (isDragged && ancestorDragged) return true;

            var childAncestorDragged = ancestorDragged || isDragged;
            for (var i = node.Children.Count - 1; i >= 0; i--)
            {
                stack.Push((node.Children[i], childAncestorDragged));
            }
        }

        return false;
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
        vm = ResolveSingleTarget(vm);
        if (vm is null || vm.Kind != NodeKind.Connection) return;

        try
        {
            if (!_lastSnapshotById.TryGetValue(vm.Node.Id, out var node))
            {
                await RefreshAsync();
                if (!_lastSnapshotById.TryGetValue(vm.Node.Id, out node)) return;
            }

            var profile = _inheritanceResolver.Resolve(node, _lastSnapshotById);
            // Factory dispatches by protocol to the matching session tab: the SSH terminal
            // or the RDP surface.
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
    private async Task ShowCredentials(TreeNodeViewModel? clicked)
    {
        clicked = ResolveSingleTarget(clicked);
        if (clicked is null || clicked.Kind != NodeKind.Connection) return;

        try
        {
            if (!_lastSnapshotById.TryGetValue(clicked.Node.Id, out var node))
            {
                await RefreshAsync();
                if (!_lastSnapshotById.TryGetValue(clicked.Node.Id, out node)) return;
            }

            // Resolve through inheritance so a credential set on a parent folder is honoured,
            // matching what OpenConnectionAsync would actually authenticate with.
            var profile = _inheritanceResolver.Resolve(node, _lastSnapshotById);

            if (profile.UseInlinePassword)
            {
                await ShowStoredCredentialSecretAsync(clicked.Name, profile.Username, profile.NodeId, "Password");
                return;
            }

            if (profile.CredentialId is not { } credId)
            {
                await ShowNoStoredCredentialsAsync();
                return;
            }

            // The stored secret for an SshKey credential is the private-key passphrase, not a
            // login password — fetch the credential to label the field honestly.
            var credential = await _credentialRepository.GetByIdAsync(credId);
            if (profile.Protocol == ProtocolType.Vnc &&
                (credential is null || credential.Protocol != ProtocolType.Vnc || credential.Kind != CredentialKind.Password))
            {
                await ShowNoStoredCredentialsAsync();
                return;
            }

            var secretLabel = credential?.Kind == CredentialKind.SshKey ? "Key passphrase" : "Password";
            var username = string.IsNullOrWhiteSpace(profile.Username)
                ? credential?.Username
                : profile.Username;

            await ShowStoredCredentialSecretAsync(clicked.Name, username, credId, secretLabel);
        }
        catch (Exception ex)
        {
            // Mirror OpenConnectionAsync's error path: log + surface a dialog rather than
            // letting the exception escape as an unhandled RelayCommand failure. The secret
            // is never passed to the logger (CLAUDE.md: never log credentials).
            _logger.LogError(ex, "Failed to reveal credentials for connection '{Name}'", clicked.Name);
            await _dialog.ShowMessageAsync("Couldn't show credentials", ex.Message);
        }
    }

    private async Task ShowStoredCredentialSecretAsync(
        string connectionName,
        string? username,
        Guid secretId,
        string secretLabel)
    {
        var secret = await _credentialService.ReadPasswordAsync(secretId);
        if (string.IsNullOrEmpty(secret))
        {
            await ShowNoStoredCredentialsAsync();
            return;
        }

        await _dialog.ShowCredentialsAsync(
            $"Credentials — {connectionName}",
            username ?? string.Empty,
            secretLabel,
            secret);
    }

    private Task ShowNoStoredCredentialsAsync() =>
        _dialog.ShowMessageAsync(
            "No credentials",
            "This connection has no stored password or key passphrase.");

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
        clicked = ResolveSingleTarget(clicked);
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
    private async Task Duplicate(TreeNodeViewModel? clicked)
    {
        clicked = ResolveSingleTarget(clicked);
        if (clicked is null || clicked.Kind != NodeKind.Connection) return;

        // CloneAsNewIdentity copies the node's OWN fields (not the inheritance-resolved profile),
        // assigns a fresh Id, and drops per-host pinned state — see ConnectionNode for why. The
        // duplicate inherits from its parent exactly as the source does, and CredentialId /
        // RdpGatewayCredentialId / TunnelConfigId are re-used by design (credentials and tunnel
        // configs are a shared pool referenced by id, so there are no secrets to copy).
        var source = clicked.Node;
        var copy = source.CloneAsNewIdentity();
        copy.Name = $"{source.Name} (copy)";
        copy.SortOrder = NextSortOrder(source.ParentId);

        await SafeAddAsync(copy);
    }

    [RelayCommand]
    private void ExpandAll() => SetExpandedRecursive(Roots, true);

    [RelayCommand]
    private void CollapseAll() => SetExpandedRecursive(Roots, false);

    private static void SetExpandedRecursive(IEnumerable<TreeNodeViewModel> level, bool expanded)
    {
        foreach (var node in EnumerateSubtree(level))
        {
            if (node.Kind == NodeKind.Folder)
            {
                node.IsExpanded = expanded;
            }
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
        var targets = ResolveDeleteTargets(clicked);
        if (targets.Count == 0) return;

        var message = BuildDeleteMessage(targets);

        var confirmed = await _dialog.ConfirmAsync("Delete", message, primaryText: "Delete", closeText: "Cancel");
        if (!confirmed) return;

        try
        {
            await _repository.DeleteManyAsync(targets.Select(t => t.Node.Id).ToArray());
            // Purge inline per-connection secrets (Credential Manager, keyed by node Id) for every
            // connection in the deleted subtree. The DB rows cascade via ON DELETE CASCADE, but the
            // out-of-band secrets do not — so deleting a FOLDER must also walk its descendant
            // connections, not just purge the clicked node. Best-effort: DeletePasswordAsync
            // self-swallows a missing entry, so it's a no-op for connections that never used an
            // inline password. Saved-credential secrets are intentionally left alone — they're keyed
            // by CredentialProfile.Id (a shared pool), not by node Id.
            foreach (var connectionId in targets.SelectMany(CollectConnectionNodeIds).Distinct())
            {
                await _credentialService.DeletePasswordAsync(connectionId);
            }
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete {Count} selected connection tree item(s)", targets.Count);
            await _dialog.ShowMessageAsync("Couldn't delete", ex.Message);
        }
    }

    private async Task SafeUpdateAsync(ConnectionNode node)
    {
        try
        {
            await _repository.UpdateAsync(node);
            await ApplyInlineSecretAsync(node);
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

    private TreeNodeViewModel? ResolveSingleTarget(TreeNodeViewModel? clicked)
    {
        if (clicked is not null) return clicked;
        if (SelectedNodes.Count == 1) return SelectedNodes[0];
        if (SelectedNodes.Count > 1) return null;
        return SelectedNode;
    }

    private IReadOnlyList<TreeNodeViewModel> ResolveDeleteTargets(TreeNodeViewModel? clicked)
    {
        if (clicked is not null)
        {
            return SelectedNodes.Count > 1 && SelectedNodes.Contains(clicked)
                ? CanonicalizeBatchTargets(SelectedNodes)
                : new[] { clicked };
        }

        if (SelectedNodes.Count > 0)
        {
            return CanonicalizeBatchTargets(SelectedNodes);
        }

        return SelectedNode is null ? Array.Empty<TreeNodeViewModel>() : new[] { SelectedNode };
    }

    private IReadOnlyList<TreeNodeViewModel> CanonicalizeBatchTargets(IEnumerable<TreeNodeViewModel> candidates)
    {
        var selectedById = new Dictionary<Guid, TreeNodeViewModel>();
        foreach (var candidate in candidates)
        {
            selectedById.TryAdd(candidate.Node.Id, candidate);
        }

        if (selectedById.Count < 2) return selectedById.Values.ToArray();

        var selectedIds = new HashSet<Guid>(selectedById.Keys);
        var encounteredIds = new HashSet<Guid>();
        var result = new List<TreeNodeViewModel>(selectedById.Count);
        CollectCanonicalBatchTargets(Roots, selectedIds, encounteredIds, ancestorSelected: false, result);

        // Defensive fallback for stale selections or tests that pass detached VMs.
        var resultIds = new HashSet<Guid>(result.Select(n => n.Node.Id));
        foreach (var candidate in selectedById.Values)
        {
            if (!encounteredIds.Contains(candidate.Node.Id) && resultIds.Add(candidate.Node.Id))
            {
                result.Add(candidate);
            }
        }

        return result;
    }

    private static void CollectCanonicalBatchTargets(
        IEnumerable<TreeNodeViewModel> level,
        HashSet<Guid> selectedIds,
        HashSet<Guid> encounteredIds,
        bool ancestorSelected,
        List<TreeNodeViewModel> result)
    {
        var stack = new Stack<(TreeNodeViewModel Node, bool AncestorSelected)>();
        PushCanonicalFramesReverse(stack, level, ancestorSelected);

        while (stack.Count > 0)
        {
            var (node, parentSelected) = stack.Pop();
            var isSelected = selectedIds.Contains(node.Node.Id);
            if (isSelected)
            {
                encounteredIds.Add(node.Node.Id);
            }

            if (isSelected && !parentSelected)
            {
                result.Add(node);
            }

            PushCanonicalFramesReverse(stack, node.Children, parentSelected || isSelected);
        }
    }

    private static void PushCanonicalFramesReverse(
        Stack<(TreeNodeViewModel Node, bool AncestorSelected)> stack,
        IEnumerable<TreeNodeViewModel> children,
        bool ancestorSelected)
    {
        if (children is IList<TreeNodeViewModel> list)
        {
            PushCanonicalFramesReverse(stack, list, ancestorSelected);
            return;
        }

        var snapshot = new List<TreeNodeViewModel>(children);
        PushCanonicalFramesReverse(stack, snapshot, ancestorSelected);
    }

    private static void PushCanonicalFramesReverse(
        Stack<(TreeNodeViewModel Node, bool AncestorSelected)> stack,
        IList<TreeNodeViewModel> children,
        bool ancestorSelected)
    {
        for (var i = children.Count - 1; i >= 0; i--)
        {
            stack.Push((children[i], ancestorSelected));
        }
    }

    private static string BuildDeleteMessage(IReadOnlyList<TreeNodeViewModel> targets)
    {
        if (targets.Count == 1)
        {
            var target = targets[0];
            var descendantCount = CountDescendants(target);
            return descendantCount == 0
                ? $"Delete '{target.Node.Name}'? This cannot be undone."
                : $"Delete '{target.Node.Name}' and its {descendantCount} nested item{(descendantCount == 1 ? "" : "s")}? This cannot be undone.";
        }

        var nestedCount = targets.Sum(CountDescendants);
        return nestedCount == 0
            ? $"Delete {targets.Count} selected items? This cannot be undone."
            : $"Delete {targets.Count} selected items and their {nestedCount} nested item{(nestedCount == 1 ? "" : "s")}? This cannot be undone.";
    }

    private static int CountDescendants(TreeNodeViewModel node)
    {
        var count = 0;
        var seen = new HashSet<Guid> { node.Node.Id };
        var stack = new Stack<TreeNodeViewModel>();
        PushChildrenReverse(stack, node.Children);

        while (stack.Count > 0)
        {
            var child = stack.Pop();
            if (!seen.Add(child.Node.Id)) continue;

            count++;
            PushChildrenReverse(stack, child.Children);
        }

        return count;
    }

    // Node Ids of every connection in the subtree rooted at `root` (including the root itself
    // when it is a connection). Drives inline-secret cleanup on delete: a folder delete cascades
    // the DB rows but not the Credential Manager entries keyed by each connection's node Id.
    private static List<Guid> CollectConnectionNodeIds(TreeNodeViewModel root)
    {
        var ids = new List<Guid>();
        var seen = new HashSet<Guid>();
        var stack = new Stack<TreeNodeViewModel>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var node = stack.Pop();
            if (!seen.Add(node.Node.Id)) continue;

            if (node.Kind == NodeKind.Connection)
            {
                ids.Add(node.Node.Id);
            }

            PushChildrenReverse(stack, node.Children);
        }

        return ids;
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
            // A move re-parents the inheritance chain for the dropped node AND its whole
            // subtree (a descendant's own ParentId is unchanged, yet its inherited host can
            // change because an ancestor moved). This path mutates Node in place without
            // reassigning it, so raise Host across the tree to refresh the one-way tooltip
            // bindings instead of waiting for the next full reload.
            NotifyHostForSubtree(Roots);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist drag-drop reorder");
            await _dialog.ShowMessageAsync("Couldn't save", ex.Message);
            await RefreshAsync();
        }
    }

    private static void NotifyHostForSubtree(IEnumerable<TreeNodeViewModel> level)
    {
        foreach (var n in EnumerateSubtree(level))
        {
            n.NotifyHostChanged();
        }
    }

    private static bool HasCycleOrInvalidParent(IList<TreeNodeViewModel> level, HashSet<Guid> seen)
    {
        var stack = new Stack<TreeNodeViewModel>();
        PushChildrenReverse(stack, level);

        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (!seen.Add(n.Node.Id)) return true;
            if (n.Kind == NodeKind.Connection && n.Children.Count > 0) return true;
            PushChildrenReverse(stack, n.Children);
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
        var stack = new Stack<ReorderFrame>();
        for (var i = level.Count - 1; i >= 0; i--)
        {
            stack.Push(new ReorderFrame(level[i], parentId, i));
        }

        while (stack.Count > 0)
        {
            var frame = stack.Pop();
            var n = frame.Node;
            if (n.Node.ParentId != frame.ParentId || n.Node.SortOrder != frame.SortOrder)
            {
                n.Node.ParentId = frame.ParentId;
                n.Node.SortOrder = frame.SortOrder;
                updates.Add(n.Node);
            }

            for (var i = n.Children.Count - 1; i >= 0; i--)
            {
                stack.Push(new ReorderFrame(n.Children[i], n.Node.Id, i));
            }
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
            await ApplyInlineSecretAsync(node);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add {Kind} '{Name}'", node.Kind, node.Name);
            await _dialog.ShowMessageAsync("Couldn't save", ex.Message);
        }
    }

    /// <summary>
    /// Persist (or purge) a connection's inline per-connection password in Credential Manager,
    /// keyed by the node Id, AFTER its DB row has committed — mirroring how CredentialsViewModel
    /// writes a credential's secret after inserting the row. The plaintext arrives on the
    /// transient <see cref="ConnectionNode.PendingInlinePassword"/> set by the editor's WriteTo;
    /// it's cleared here so the live tree snapshot never retains it. Never logged.
    /// </summary>
    private async Task ApplyInlineSecretAsync(ConnectionNode node)
    {
        if (node.Kind != NodeKind.Connection) return;
        try
        {
            if (node.UseInlinePassword == true && !string.IsNullOrEmpty(node.PendingInlinePassword))
            {
                await _credentialService.StorePasswordAsync(node.Id, node.PendingInlinePassword);
            }
            else
            {
                // Delete (never store an empty entry) when there's no usable inline password — the
                // connection switched to a saved credential / prompt-every-time, OR it's inline mode
                // with a blank password. An empty Credential Manager entry reads back as a real ""
                // password that yields no useful inline auth and fails the connect; deleting it instead
                // lets the session credential resolver fall back to prompting. Keyed by node Id, so it never
                // touches a saved credential's secret (those are keyed by credential Id).
                // DeletePasswordAsync self-swallows not-found, so this is also the idempotent purge.
                await _credentialService.DeletePasswordAsync(node.Id);
            }
        }
        finally
        {
            node.PendingInlinePassword = null;
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

        PruneSelectionToSnapshot();

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
        foreach (var node in EnumerateSubtree(level))
        {
            node.IsVisible = true;
        }
    }

    private static bool EvaluateFilter(IEnumerable<TreeNodeViewModel> level, string query)
    {
        var anyVisible = false;
        var seen = new HashSet<Guid>();
        var stack = new Stack<FilterFrame>();
        PushFilterFramesReverse(stack, level, ancestorMatched: false);

        while (stack.Count > 0)
        {
            var frame = stack.Pop();
            var node = frame.Node;
            if (frame.Exiting)
            {
                var hasVisibleChild = false;
                foreach (var child in node.Children)
                {
                    if (child.IsVisible)
                    {
                        hasVisibleChild = true;
                        break;
                    }
                }

                node.IsVisible = hasVisibleChild;
                if (hasVisibleChild)
                {
                    node.IsExpanded = true;
                    anyVisible = true;
                }
                continue;
            }

            if (!seen.Add(node.Node.Id)) continue;

            if (frame.AncestorMatched)
            {
                node.IsVisible = true;
                anyVisible = true;
                PushFilterFramesReverse(stack, node.Children, ancestorMatched: true);
                continue;
            }

            var nameMatches = node.Name.Contains(query, StringComparison.OrdinalIgnoreCase);
            if (node.Kind == NodeKind.Folder && nameMatches)
            {
                // Folder name matched — show the folder and everything beneath it, and
                // expand this folder so the contents the user searched for are visible.
                // Descendant expansion is deliberately left alone; clearing the search will
                // restore the pre-filter snapshot for every folder.
                node.IsVisible = true;
                node.IsExpanded = true;
                anyVisible = true;
                PushFilterFramesReverse(stack, node.Children, ancestorMatched: true);
            }
            else if (node.Kind == NodeKind.Folder)
            {
                stack.Push(new FilterFrame(node, AncestorMatched: false, Exiting: true));
                PushFilterFramesReverse(stack, node.Children, ancestorMatched: false);
            }
            else
            {
                node.IsVisible = nameMatches;
                if (nameMatches) anyVisible = true;
            }
        }

        return anyVisible;
    }

    private static Dictionary<Guid, bool> SnapshotExpandState(IEnumerable<TreeNodeViewModel> level)
    {
        var snapshot = new Dictionary<Guid, bool>();
        foreach (var node in EnumerateSubtree(level))
        {
            if (node.Kind == NodeKind.Folder)
            {
                snapshot[node.Node.Id] = node.IsExpanded;
            }
        }
        return snapshot;
    }

    private static void RestoreExpandState(IEnumerable<TreeNodeViewModel> level, Dictionary<Guid, bool> snapshot)
    {
        foreach (var node in EnumerateSubtree(level))
        {
            if (node.Kind == NodeKind.Folder && snapshot.TryGetValue(node.Node.Id, out var wasExpanded))
            {
                node.IsExpanded = wasExpanded;
            }
        }
    }

    private void PruneSelectionToSnapshot()
    {
        if (SelectedNode is not null && !_lastSnapshotById.ContainsKey(SelectedNode.Node.Id))
        {
            SelectedNode = null;
        }

        if (SelectedNodes.Count == 0) return;

        var selected = new List<TreeNodeViewModel>(SelectedNodes.Count);
        foreach (var node in SelectedNodes)
        {
            if (_lastSnapshotById.ContainsKey(node.Node.Id))
            {
                selected.Add(node);
            }
        }

        if (selected.Count != SelectedNodes.Count)
        {
            SelectedNodes.ReplaceAll(selected);
        }

        if (SelectedNode is null && selected.Count == 1)
        {
            SelectedNode = selected[0];
        }
    }

    // Resolves a connection's effective host exactly as InheritanceResolver does, so the
    // tooltip never advertises a host the session wouldn't actually use. That resolver does
    // `host ??= current.Host` (null-only inheritance: the first NON-NULL host up the chain
    // wins, even if blank) and then rejects a blank result as "no usable host". We mirror
    // both: stop at the first non-null host, and return null for a blank one (suppressing
    // the tooltip) rather than skipping past it to an ancestor.
    private string? ResolveEffectiveHost(ConnectionNode node)
    {
        HashSet<Guid>? seen = null;
        var current = node;
        while (true)
        {
            if (current.Host is { } host)
            {
                return string.IsNullOrWhiteSpace(host) ? null : host;
            }
            if (current.ParentId is not Guid parentId) return null;
            if (!_lastSnapshotById.TryGetValue(parentId, out var parent)) return null;
            seen ??= new HashSet<Guid> { current.Id };
            if (!seen.Add(parent.Id)) return null; // cycle guard, mirrors InheritanceResolver
            current = parent;
        }
    }

    // Mutates `current` in place to match `target` (and recursively each node's children),
    // reusing existing TreeNodeViewModel instances by Id so the TreeView's container
    // tree — and therefore selection, expansion, focus — survives the refresh.
    private void Reconcile(
        BulkObservableCollection<TreeNodeViewModel> current,
        IReadOnlyList<ConnectionNode> target,
        IReadOnlyDictionary<Guid, List<ConnectionNode>> byParent)
    {
        var pending = new Stack<ReconcileFrame>();
        pending.Push(new ReconcileFrame(current, target));

        while (pending.Count > 0)
        {
            var frame = pending.Pop();
            ReconcileLevel(frame.Current, frame.Target, byParent, pending);
        }
    }

    private void ReconcileLevel(
        BulkObservableCollection<TreeNodeViewModel> current,
        IReadOnlyList<ConnectionNode> target,
        IReadOnlyDictionary<Guid, List<ConnectionNode>> byParent,
        Stack<ReconcileFrame> pending)
    {
        if (current.Count == 0)
        {
            if (target.Count == 0) return;

            var next = new List<TreeNodeViewModel>(target.Count);
            foreach (var node in target)
            {
                var vm = new TreeNodeViewModel(node, ResolveEffectiveHost);
                next.Add(vm);
            }

            current.ReplaceAll(next);
            QueueChildReconciles(current, target, byParent, pending);
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
                vm = new TreeNodeViewModel(node, ResolveEffectiveHost);
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
            pending.Push(new ReconcileFrame(
                vm.Children,
                children ?? (IReadOnlyList<ConnectionNode>)Array.Empty<ConnectionNode>()));
        }
    }

    private static void QueueChildReconciles(
        BulkObservableCollection<TreeNodeViewModel> current,
        IReadOnlyList<ConnectionNode> target,
        IReadOnlyDictionary<Guid, List<ConnectionNode>> byParent,
        Stack<ReconcileFrame> pending)
    {
        for (var i = target.Count - 1; i >= 0; i--)
        {
            byParent.TryGetValue(target[i].Id, out var children);
            pending.Push(new ReconcileFrame(
                current[i].Children,
                children ?? (IReadOnlyList<ConnectionNode>)Array.Empty<ConnectionNode>()));
        }
    }

    private static IEnumerable<TreeNodeViewModel> EnumerateSubtree(IEnumerable<TreeNodeViewModel> level)
    {
        var seen = new HashSet<Guid>();
        var stack = new Stack<TreeNodeViewModel>();
        PushChildrenReverse(stack, level);

        while (stack.Count > 0)
        {
            var node = stack.Pop();
            if (!seen.Add(node.Node.Id)) continue;

            yield return node;
            PushChildrenReverse(stack, node.Children);
        }
    }

    private static void PushChildrenReverse(Stack<TreeNodeViewModel> stack, IEnumerable<TreeNodeViewModel> children)
    {
        if (children is IList<TreeNodeViewModel> list)
        {
            PushChildrenReverse(stack, list);
            return;
        }

        var snapshot = new List<TreeNodeViewModel>(children);
        PushChildrenReverse(stack, snapshot);
    }

    private static void PushChildrenReverse(Stack<TreeNodeViewModel> stack, IList<TreeNodeViewModel> children)
    {
        for (var i = children.Count - 1; i >= 0; i--)
        {
            stack.Push(children[i]);
        }
    }

    private static void PushFilterFramesReverse(
        Stack<FilterFrame> stack,
        IEnumerable<TreeNodeViewModel> children,
        bool ancestorMatched)
    {
        if (children is IList<TreeNodeViewModel> list)
        {
            for (var i = list.Count - 1; i >= 0; i--)
            {
                stack.Push(new FilterFrame(list[i], ancestorMatched, Exiting: false));
            }
            return;
        }

        var snapshot = new List<TreeNodeViewModel>(children);
        for (var i = snapshot.Count - 1; i >= 0; i--)
        {
            stack.Push(new FilterFrame(snapshot[i], ancestorMatched, Exiting: false));
        }
    }

    private readonly record struct ReorderFrame(TreeNodeViewModel Node, Guid? ParentId, int SortOrder);

    private readonly record struct FilterFrame(TreeNodeViewModel Node, bool AncestorMatched, bool Exiting);

    private readonly record struct ReconcileFrame(
        BulkObservableCollection<TreeNodeViewModel> Current,
        IReadOnlyList<ConnectionNode> Target);

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
    // Resolves a connection's effective host through folder inheritance. Supplied by the
    // owning ConnectionTreeViewModel; null in unit tests that construct nodes directly,
    // where Host falls back to the node's own field.
    private readonly Func<ConnectionNode, string?>? resolveEffectiveHost;

    public TreeNodeViewModel(ConnectionNode node, Func<ConnectionNode, string?>? resolveEffectiveHost = null)
    {
        this.node = node;
        this.resolveEffectiveHost = resolveEffectiveHost;
    }

    [ObservableProperty]
    private ConnectionNode node = null!;

    public BulkObservableCollection<TreeNodeViewModel> Children { get; } = new();
    public string Name => Node.Name;
    public NodeKind Kind => Node.Kind;
    public bool IsConnection => Kind == NodeKind.Connection;

    // Effective host (IP or FQDN) shown as the row tooltip on hover, resolved through
    // folder inheritance so a host set on an ancestor folder still surfaces. Null for
    // folders and for connections with no usable host anywhere up the chain, which
    // suppresses the tooltip entirely. When a resolver is supplied its result is used
    // verbatim — including null — so a deliberate suppression isn't overridden by the
    // node's own raw Host; the bare-Node.Host path is only the no-resolver test fallback.
    public string? Host => IsConnection
        ? (resolveEffectiveHost is { } resolve ? resolve(Node) : Node.Host)
        : null;

    // Re-evaluates the Host tooltip binding. Needed after a drag-drop changes the parent
    // chain (which can change an inherited host) by mutating Node in place rather than
    // reassigning it, so OnNodeChanged doesn't fire.
    public void NotifyHostChanged() => OnPropertyChanged(nameof(Host));

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
            ProtocolType.Vnc => Glyphs.Vnc,
            ProtocolType.Http or ProtocolType.Https => Glyphs.Web,
            ProtocolType.Serial => Glyphs.Serial,
            _ => Glyphs.Generic,
        };

    partial void OnNodeChanged(ConnectionNode value)
    {
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Kind));
        OnPropertyChanged(nameof(IsConnection));
        OnPropertyChanged(nameof(Host));
        OnPropertyChanged(nameof(Glyph));
    }
}
