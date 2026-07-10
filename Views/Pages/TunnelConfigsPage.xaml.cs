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
    private TunnelConfig? _contextTarget;

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

    private void OnTunnelRightTapped(object sender, RightTappedRoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: TunnelConfig config })
        {
            _contextTarget = config;
        }
    }

    private void OnTunnelContextRequested(UIElement sender, ContextRequestedEventArgs args)
    {
        if (sender is FrameworkElement { DataContext: TunnelConfig config })
        {
            _contextTarget = config;
        }
    }

    private TunnelConfig? ResolveActionTarget(object sender) =>
        sender is FrameworkElement { DataContext: TunnelConfig config }
            ? config
            : _contextTarget;

    private void OnEditMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (ResolveActionTarget(sender) is { } config)
        {
            ExecuteIfCan(ViewModel.EditTunnelCommand, config);
        }
    }

    private async void OnTestMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (ResolveActionTarget(sender) is { } config &&
            ViewModel.TestTunnelCommand.CanExecute(config))
        {
            await ViewModel.TestTunnelCommand.ExecuteAsync(config);
        }
    }

    private void OnDeleteMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (ResolveActionTarget(sender) is { } config)
        {
            ExecuteIfCan(ViewModel.DeleteTunnelCommand, config);
        }
    }
}
