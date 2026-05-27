using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Wormhole.Models;
using Wormhole.ViewModels;

namespace Wormhole.Views.Pages;

public sealed partial class TunnelConfigsPage : Page
{
    public TunnelConfigsViewModel ViewModel { get; }

    public TunnelConfigsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<TunnelConfigsViewModel>();
        this.InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = ViewModel.EnsureLoadedAsync();
    }

    private void OnCardDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: TunnelConfig config })
        {
            ViewModel.EditTunnelCommand.Execute(config);
        }
    }

    private void OnEditMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: TunnelConfig config })
        {
            ViewModel.EditTunnelCommand.Execute(config);
        }
    }

    private void OnDeleteMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: TunnelConfig config })
        {
            ViewModel.DeleteTunnelCommand.Execute(config);
        }
    }
}
