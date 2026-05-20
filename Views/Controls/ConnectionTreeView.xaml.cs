using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels;

namespace Wormhole.Views.Controls;

public sealed partial class ConnectionTreeView : UserControl
{
    public ConnectionTreeViewModel ViewModel { get; }

    public ConnectionTreeView()
    {
        ViewModel = App.Current.Services.GetRequiredService<ConnectionTreeViewModel>();
        this.InitializeComponent();
    }

    private void Tree_ItemInvoked(TreeView sender, TreeViewItemInvokedEventArgs args)
    {
        if (args.InvokedItem is TreeNodeViewModel vm &&
            ViewModel.OpenConnectionCommand.CanExecute(vm))
        {
            ViewModel.OpenConnectionCommand.Execute(vm);
        }
    }
}
