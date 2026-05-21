using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
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
    private bool _isLoading;

    public ObservableCollection<TreeNodeViewModel> Roots { get; } = new();

    [ObservableProperty]
    private TreeNodeViewModel? selectedNode;

    [ObservableProperty]
    private string searchText = string.Empty;

    // Captured the moment a filter starts so clearing the search restores the tree
    // to exactly how the user had it expanded before they typed.
    private Dictionary<Guid, bool>? _expandStateBeforeFilter;

    partial void OnSearchTextChanged(string? oldValue, string newValue)
    {
        var wasFiltering = !string.IsNullOrWhiteSpace(oldValue);
        var isFiltering = !string.IsNullOrWhiteSpace(newValue);

        if (!wasFiltering && isFiltering)
        {
            _expandStateBeforeFilter = SnapshotExpandState(Roots);
        }

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
            var all = await _repository.GetAllAsync();
            var byId = all.ToDictionary(n => n.Id);
            if (!byId.TryGetValue(vm.Node.Id, out var node)) return;

            var profile = _inheritanceResolver.Resolve(node, byId);
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
        var name = await _dialog.PromptForTextAsync("New folder", "Name");
        if (string.IsNullOrWhiteSpace(name)) return;

        var parentId = ResolveParentId(clicked);
        await SafeAddAsync(new ConnectionNode
        {
            Name = name,
            Kind = NodeKind.Folder,
            ParentId = parentId,
            SortOrder = NextSortOrder(parentId),
        });
    }

    [RelayCommand]
    private async Task AddConnection(TreeNodeViewModel? clicked)
    {
        var draft = await _dialog.PromptForConnectionAsync();
        if (draft is null) return;

        var parentId = ResolveParentId(clicked);
        await SafeAddAsync(new ConnectionNode
        {
            Name = draft.Name,
            Kind = NodeKind.Connection,
            ParentId = parentId,
            SortOrder = NextSortOrder(parentId),
            Protocol = draft.Protocol,
            Host = draft.Host,
            Port = draft.Port,
            Username = draft.Username,
        });
    }

    [RelayCommand]
    private async Task Edit(TreeNodeViewModel? clicked)
    {
        if (clicked is null) return;
        var node = clicked.Node;

        if (node.Kind == NodeKind.Folder)
        {
            var name = await _dialog.PromptForTextAsync("Rename folder", "Name", defaultValue: node.Name);
            if (string.IsNullOrWhiteSpace(name) || name == node.Name) return;
            node.Name = name;
            await SafeUpdateAsync(node);
            return;
        }

        var initial = new NewConnectionDraft(
            node.Name,
            node.Protocol ?? ProtocolType.Ssh,
            node.Host ?? string.Empty,
            node.Port,
            node.Username);
        var draft = await _dialog.PromptForConnectionAsync(initial);
        if (draft is null || draft == initial) return;

        node.Name = draft.Name;
        node.Protocol = draft.Protocol;
        node.Host = draft.Host;
        node.Port = draft.Port;
        node.Username = draft.Username;
        await SafeUpdateAsync(node);
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
            // Edit mutates clicked.Node in place before persistence; reload from the DB
            // so the tree reflects what was actually committed, not the unsaved draft.
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
            _lastSnapshot = await _repository.GetAllAsync();
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
    private static void ApplyAndCollectChangedNodes(
        IList<TreeNodeViewModel> level,
        Guid? parentId,
        List<ConnectionNode> updates)
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
        clicked is null                   ? null
      : clicked.Kind == NodeKind.Folder   ? clicked.Node.Id
      :                                     clicked.Node.ParentId;

    private int NextSortOrder(Guid? parentId) =>
        _lastSnapshot.Where(n => n.ParentId == parentId)
                     .Select(n => n.SortOrder)
                     .DefaultIfEmpty(-1)
                     .Max() + 1;

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
        _lastSnapshot = all;

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

        if (SelectedNode is not null && all.All(n => n.Id != SelectedNode.Node.Id))
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
                    // Folder name matched — show the folder and everything beneath it
                    // (the user wants to see what's inside the matching folder).
                    node.IsVisible = true;
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
        ObservableCollection<TreeNodeViewModel> current,
        IReadOnlyList<ConnectionNode> target,
        IReadOnlyDictionary<Guid, List<ConnectionNode>> byParent)
    {
        var targetIds = new HashSet<Guid>(target.Count);
        foreach (var n in target) targetIds.Add(n.Id);

        for (var i = current.Count - 1; i >= 0; i--)
        {
            if (!targetIds.Contains(current[i].Node.Id))
            {
                current.RemoveAt(i);
            }
        }

        for (var i = 0; i < target.Count; i++)
        {
            var node = target[i];
            var existingIdx = IndexOfById(current, node.Id);
            TreeNodeViewModel vm;
            if (existingIdx < 0)
            {
                vm = new TreeNodeViewModel(node);
                current.Insert(i, vm);
            }
            else
            {
                vm = current[existingIdx];
                vm.Node = node;
                if (existingIdx != i) current.Move(existingIdx, i);
            }

            byParent.TryGetValue(node.Id, out var children);
            Reconcile(vm.Children, children ?? (IReadOnlyList<ConnectionNode>)Array.Empty<ConnectionNode>(), byParent);
        }
    }

    private static int IndexOfById(ObservableCollection<TreeNodeViewModel> list, Guid id)
    {
        for (var i = 0; i < list.Count; i++)
        {
            if (list[i].Node.Id == id) return i;
        }
        return -1;
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

    public ObservableCollection<TreeNodeViewModel> Children { get; } = new();
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
