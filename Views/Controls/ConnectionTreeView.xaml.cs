using System.Collections.Specialized;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Wormhole.Models;
using Wormhole.ViewModels;

namespace Wormhole.Views.Controls;

public sealed partial class ConnectionTreeView : UserControl
{
    private bool _loaded;
    private readonly Dictionary<TreeViewItem, CheckBox> _selectionCheckBoxes = new();
    private TreeViewItem? _hoveredTreeItem;

    public ConnectionTreeViewModel ViewModel { get; }

    public ConnectionTreeView()
    {
        ViewModel = App.Current.Services.GetRequiredService<ConnectionTreeViewModel>();
        ViewModel.SelectedNodes.CollectionChanged += OnSelectedNodesChanged;
        this.InitializeComponent();
        this.Loaded += async (_, _) =>
        {
            if (_loaded) return;
            _loaded = true;
            await ViewModel.RefreshAsync();
        };
    }

    public double MeasureHeaderDesiredWidth()
    {
        HeaderRow.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        return HeaderRow.DesiredSize.Width;
    }

    private void OnNewFolderAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        ViewModel.AddFolderCommand.Execute(null);
        args.Handled = true;
    }

    private void OnNewConnectionAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        ViewModel.AddConnectionCommand.Execute(null);
        args.Handled = true;
    }

    private async void OnDragItemsCompleted(TreeView sender, TreeViewDragItemsCompletedEventArgs args)
    {
        if (args.DropResult != DataPackageOperation.Move) return;
        await ViewModel.PersistTreeStructureAsync();
    }

    private void OnDragItemsStarting(TreeView sender, TreeViewDragItemsStartingEventArgs args)
    {
        var draggedNodes = ViewModel.ResolveDragSelection(args.Items.OfType<TreeNodeViewModel>());
        SyncDragItems(args.Items, draggedNodes);

        if (ViewModel.ShouldRejectDragSelection(draggedNodes))
        {
            args.Cancel = true;
        }
    }

    private void OnTreeItemLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is not TreeViewItem item) return;

        item.DispatcherQueue.TryEnqueue(() =>
        {
            if (!item.IsLoaded) return;

            SyncSelectionCheckBox(item);
            UpdateSelectionCheckboxChrome();
        });
    }

    private void OnTreeItemUnloaded(object sender, RoutedEventArgs e)
    {
        if (sender is not TreeViewItem item) return;

        _selectionCheckBoxes.Remove(item);
        if (ReferenceEquals(_hoveredTreeItem, item))
        {
            _hoveredTreeItem = null;
            UpdateSelectionCheckboxChrome();
        }
    }

    private void OnTreeItemGotFocus(object sender, RoutedEventArgs e)
    {
        if (sender is TreeViewItem { DataContext: TreeNodeViewModel vm })
        {
            ViewModel.SelectedNode = vm;
        }
    }

    private void OnTreeItemPointerEntered(object sender, PointerRoutedEventArgs e)
    {
        if (sender is not TreeViewItem item) return;

        _hoveredTreeItem = item;
        SyncSelectionCheckBox(item);
        UpdateSelectionCheckboxChrome();
    }

    private void OnTreeItemPointerExited(object sender, PointerRoutedEventArgs e)
    {
        if (sender is not TreeViewItem item || !ReferenceEquals(_hoveredTreeItem, item)) return;

        _hoveredTreeItem = null;
        UpdateSelectionCheckboxChrome();
    }

    private void OnRenameAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (SingleSelectedNode() is { } node)
        {
            ViewModel.EditCommand.Execute(node);
        }
        args.Handled = true;
    }

    private void OnDeleteAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        ViewModel.DeleteCommand.Execute(null);
        args.Handled = true;
    }

    private void OnNodeDoubleTapped(object sender, Microsoft.UI.Xaml.Input.DoubleTappedRoutedEventArgs args)
    {
        if (sender is FrameworkElement fe &&
            fe.DataContext is TreeNodeViewModel vm &&
            ViewModel.OpenConnectionCommand.CanExecute(vm))
        {
            ViewModel.OpenConnectionCommand.Execute(vm);
            args.Handled = true;
        }
    }

    private void OnTreeItemInvoked(TreeView sender, TreeViewItemInvokedEventArgs args)
    {
        // Single-click on a folder toggles expansion so the entire row is a hit target.
        // Connections still open via DoubleTapped to avoid accidental session opens.
        if (args.InvokedItem is not TreeNodeViewModel vm) return;

        ViewModel.SelectedNode = vm;
        if (vm.Kind == NodeKind.Folder)
        {
            vm.IsExpanded = !vm.IsExpanded;
            args.Handled = true;
        }
    }

#pragma warning disable CA1822 // XAML-wired event handler (Tapped="OnSelectionCheckBoxTapped")
    private void OnSelectionCheckBoxTapped(object sender, TappedRoutedEventArgs e)
    {
        e.Handled = true;
    }
#pragma warning restore CA1822

    private void OnSelectionCheckBoxClick(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { Tag: TreeNodeViewModel vm } checkBox) return;

        ViewModel.SetNodeSelection(vm, checkBox.IsChecked == true);
    }

    // Per-node MenuFlyout items dispatch via Click because ElementName bindings
    // can't reach Root from inside a Popup nested in a DataTemplate.
    private void OnAddFolderItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is TreeNodeViewModel vm)
        {
            ViewModel.AddFolderCommand.Execute(vm);
        }
    }

    private void OnAddConnectionItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is TreeNodeViewModel vm)
        {
            ViewModel.AddConnectionCommand.Execute(vm);
        }
    }

    private void OnShowCredentialsItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is TreeNodeViewModel vm)
        {
            ViewModel.ShowCredentialsCommand.Execute(vm);
        }
    }

    private void OnDuplicateItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is TreeNodeViewModel vm)
        {
            ViewModel.DuplicateCommand.Execute(vm);
        }
    }

    private void OnEditItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is TreeNodeViewModel vm)
        {
            ViewModel.EditCommand.Execute(vm);
        }
    }

    private void OnDeleteItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is TreeNodeViewModel vm)
        {
            ViewModel.DeleteCommand.Execute(vm);
        }
    }

    private void OnOpenAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (SingleSelectedNode() is { } vm &&
            ViewModel.OpenConnectionCommand.CanExecute(vm))
        {
            ViewModel.OpenConnectionCommand.Execute(vm);
            args.Handled = true;
        }
    }

    private static void SyncDragItems(IList<object> dragItems, IReadOnlyList<TreeNodeViewModel> draggedNodes)
    {
        if (dragItems.Count == draggedNodes.Count)
        {
            var alreadyMatches = true;
            for (var i = 0; i < draggedNodes.Count; i++)
            {
                if (ReferenceEquals(dragItems[i], draggedNodes[i])) continue;

                alreadyMatches = false;
                break;
            }

            if (alreadyMatches) return;
        }

        dragItems.Clear();
        foreach (var node in draggedNodes)
        {
            dragItems.Add(node);
        }
    }

    private TreeNodeViewModel? SingleSelectedNode()
    {
        if (ViewModel.SelectedNodes.Count == 1) return ViewModel.SelectedNodes[0];
        if (ViewModel.SelectedNodes.Count > 1) return null;
        return ViewModel.SelectedNode;
    }

    private void OnSelectedNodesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        foreach (var item in _selectionCheckBoxes.Keys.ToArray())
        {
            SyncSelectionCheckBox(item);
        }

        UpdateSelectionCheckboxChrome();
    }

    private void UpdateSelectionCheckboxChrome()
    {
        var showAll = ViewModel.SelectedNodes.Count > 0;
        foreach (var pair in _selectionCheckBoxes)
        {
            var show = showAll || ReferenceEquals(pair.Key, _hoveredTreeItem);
            pair.Value.Opacity = show ? 1 : 0;
            pair.Value.IsHitTestVisible = show;
            pair.Value.IsTabStop = show;
            pair.Value.IsEnabled = show;
        }
    }

    private CheckBox? RegisterSelectionCheckBox(TreeViewItem item)
    {
        if (_selectionCheckBoxes.TryGetValue(item, out var cached))
        {
            return cached;
        }

        var checkBox = FindSelectionCheckBox(item);
        if (checkBox is null) return null;

        _selectionCheckBoxes[item] = checkBox;
        return checkBox;
    }

    private void SyncSelectionCheckBox(TreeViewItem item)
    {
        var checkBox = RegisterSelectionCheckBox(item);
        if (checkBox is not null)
        {
            SyncSelectionCheckBox(item, checkBox);
        }
    }

    private void SyncSelectionCheckBox(TreeViewItem item, CheckBox checkBox)
    {
        var node = checkBox.Tag as TreeNodeViewModel ?? item.DataContext as TreeNodeViewModel;
        var shouldBeChecked = node is not null && ViewModel.IsSelected(node);
        if (checkBox.IsChecked != shouldBeChecked)
        {
            checkBox.IsChecked = shouldBeChecked;
        }
    }

    private static CheckBox? FindSelectionCheckBox(DependencyObject root)
    {
        var queue = new Queue<DependencyObject>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var node = queue.Dequeue();
            if (node is CheckBox { Name: "SelectCheckBox" } checkBox)
            {
                return checkBox;
            }

            var childCount = VisualTreeHelper.GetChildrenCount(node);
            for (var i = 0; i < childCount; i++)
            {
                queue.Enqueue(VisualTreeHelper.GetChild(node, i));
            }
        }

        return null;
    }
}
