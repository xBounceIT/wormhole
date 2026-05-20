using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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
    private bool _isLoading;

    public ObservableCollection<TreeNodeViewModel> Roots { get; } = new();

    [ObservableProperty]
    private TreeNodeViewModel? selectedNode;

    public ConnectionTreeViewModel(
        IConnectionRepository repository,
        InheritanceResolver inheritanceResolver,
        ISessionTabFactory tabFactory)
    {
        _repository = repository;
        _inheritanceResolver = inheritanceResolver;
        _tabFactory = tabFactory;
        _ = RefreshAsync();
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

        var all = await _repository.GetAllAsync();
        var byId = all.ToDictionary(n => n.Id);
        if (!byId.TryGetValue(vm.Node.Id, out var node)) return;

        var profile = _inheritanceResolver.Resolve(node, byId);
        // Factory dispatches by protocol: SSH gets the real terminal, RDP/SFTP get
        // placeholder tabs whose DataTemplate renders the "not implemented yet" notice.
        _tabFactory.Open(profile);
    }

    private async Task LoadAsync()
    {
        var all = await _repository.GetAllAsync();
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

        Roots.Clear();
        foreach (var node in topLevel)
        {
            Roots.Add(Build(node, byParent));
        }
    }

    private static TreeNodeViewModel Build(ConnectionNode node, IReadOnlyDictionary<Guid, List<ConnectionNode>> byParent)
    {
        var vm = new TreeNodeViewModel(node);
        if (byParent.TryGetValue(node.Id, out var children))
        {
            foreach (var child in children)
            {
                vm.Children.Add(Build(child, byParent));
            }
        }
        return vm;
    }
}

public sealed class TreeNodeViewModel
{
    public TreeNodeViewModel(ConnectionNode node)
    {
        Node = node;
    }

    public ConnectionNode Node { get; }
    public ObservableCollection<TreeNodeViewModel> Children { get; } = new();
    public string Name => Node.Name;
    public NodeKind Kind => Node.Kind;

    public string Glyph => Kind == NodeKind.Folder
        ? Glyphs.Folder
        : Node.Protocol switch
        {
            ProtocolType.Ssh => Glyphs.Ssh,
            ProtocolType.Rdp => Glyphs.Rdp,
            ProtocolType.Sftp => Glyphs.Sftp,
            _ => Glyphs.Generic,
        };
}
