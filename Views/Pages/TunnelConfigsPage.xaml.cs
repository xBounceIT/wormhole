using System.Windows.Input;
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

    private static void ExecuteIfCan(ICommand command, object? parameter)
    {
        if (command.CanExecute(parameter))
        {
            command.Execute(parameter);
        }
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
            ExecuteIfCan(ViewModel.EditTunnelCommand, config);
        }
    }

    private void OnEditMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: TunnelConfig config })
        {
            ExecuteIfCan(ViewModel.EditTunnelCommand, config);
        }
    }

    private async void OnTestMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: TunnelConfig config } &&
            ViewModel.TestTunnelCommand.CanExecute(config))
        {
            await ViewModel.TestTunnelCommand.ExecuteAsync(config);
        }
    }

    private void OnDeleteMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: TunnelConfig config })
        {
            ExecuteIfCan(ViewModel.DeleteTunnelCommand, config);
        }
    }
}
