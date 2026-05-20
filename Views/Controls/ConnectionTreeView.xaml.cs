using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Wormhole.Models;
using Wormhole.ViewModels;

namespace Wormhole.Views.Controls;

public sealed partial class ConnectionTreeView : UserControl
{
    private bool _loaded;

    public ConnectionTreeViewModel ViewModel { get; }

    public ConnectionTreeView()
    {
        ViewModel = App.Current.Services.GetRequiredService<ConnectionTreeViewModel>();
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

    private void OnRenameAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (Tree.SelectedItem is TreeNodeViewModel node)
        {
            ViewModel.EditCommand.Execute(node);
        }
        args.Handled = true;
    }

    private void OnDeleteAccelerator(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
    {
        if (Tree.SelectedItem is TreeNodeViewModel node)
        {
            ViewModel.DeleteCommand.Execute(node);
        }
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
        // Connections fall through to the DoubleTapped handler to avoid accidental opens.
        if (args.InvokedItem is TreeNodeViewModel vm && vm.Kind == NodeKind.Folder)
        {
            vm.IsExpanded = !vm.IsExpanded;
            args.Handled = true;
        }
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
        if (Tree.SelectedItem is TreeNodeViewModel vm &&
            ViewModel.OpenConnectionCommand.CanExecute(vm))
        {
            ViewModel.OpenConnectionCommand.Execute(vm);
            args.Handled = true;
        }
    }
}
