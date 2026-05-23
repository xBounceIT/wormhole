using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Services;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Pages;

public sealed partial class SessionsPage : Page
{
    private readonly ISessionTabFactory _sessionTabFactory;
    private readonly IFileTransferDialogService _fileTransferDialog;

    public ShellViewModel ViewModel { get; }

    public SessionsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<ShellViewModel>();
        _sessionTabFactory = App.Current.Services.GetRequiredService<ISessionTabFactory>();
        _fileTransferDialog = App.Current.Services.GetRequiredService<IFileTransferDialogService>();
        this.InitializeComponent();
    }

    private async void SessionTabs_TabCloseRequested(TabView sender, TabViewTabCloseRequestedEventArgs args)
    {
        if (args.Item is SessionTabViewModel tab)
        {
            await CloseTabAsync(tab);
        }
    }

    private async Task CloseTabAsync(SessionTabViewModel tab)
    {
        if (tab is SshSessionViewModel ssh)
        {
            await ssh.DetachAsync();
        }
        ViewModel.Tabs.Remove(tab);
    }

    private void OnTabDuplicateClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe &&
            fe.DataContext is SessionTabViewModel tab &&
            tab.Profile is { } profile)
        {
            _sessionTabFactory.Open(profile);
        }
    }

    private void OnTabReconnectClick(object sender, RoutedEventArgs e)
    {
        // Activate the tab before MenuFlyoutItem invokes the Reconnect Command (Click
        // fires first, Command.Execute second). For background SSH tabs the view is
        // unloaded and _webView is null, so RetryAsync would otherwise fan out into a
        // detached InitializationRetryRequested and silently no-op — selecting the tab
        // schedules its view to re-Load, where AttachAsync consumes the reconnect intent.
        if (sender is FrameworkElement fe &&
            fe.DataContext is SessionTabViewModel tab &&
            !ReferenceEquals(ViewModel.SelectedTab, tab))
        {
            ViewModel.SelectedTab = tab;
        }
    }

    private async void OnTabCloseClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is SessionTabViewModel tab)
        {
            await CloseTabAsync(tab);
        }
    }

    private async void OnTabFileTransferClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.DataContext is SessionTabViewModel tab)
        {
            await _fileTransferDialog.ShowAsync(tab);
        }
    }
}
