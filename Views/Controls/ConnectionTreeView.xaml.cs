using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.ApplicationModel.DataTransfer;
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
}
