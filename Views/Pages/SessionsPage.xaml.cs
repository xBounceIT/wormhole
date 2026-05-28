using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Helpers;
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
        try
        {
            await tab.CloseAsync();
        }
        finally
        {
            ViewModel.Tabs.Remove(tab);
        }
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

    // Active suppression scope while a tab context menu is open. Only one tab context menu can be
    // open at a time (opening another light-dismisses the first), so a single field suffices; the
    // Dispose-before-reassign guards against any transient overlap.
    private IDisposable? _tabFlyoutOverlaySuppression;

    private void OnTabContextFlyoutOpened(object? sender, object e)
    {
        // The tab context menu drops over the session content area, where a connected RDP overlay
        // (a top-level window composited above WinUI) would occlude it. Hide the overlay for the
        // menu's open lifetime, mirroring the ContentDialog suppression.
        _tabFlyoutOverlaySuppression?.Dispose();
        _tabFlyoutOverlaySuppression = RdpOverlayCoordinator.Suppress();
    }

    private void OnTabContextFlyoutClosed(object? sender, object e)
    {
        _tabFlyoutOverlaySuppression?.Dispose();
        _tabFlyoutOverlaySuppression = null;
    }

    private async void OnTabFileTransferClick(object sender, RoutedEventArgs e)
    {
        // async void: an exception here reaches App.OnUnhandledException which only
        // logs and does not set e.Handled, so the runtime terminates the process.
        // ShowAsync has internal try/catch around the connect path but the dialog-
        // construction block (XamlRoot lookup, ContentDialog ctor, orchestrator ctor)
        // is wrapped only in try/finally — any throw there must not be allowed to
        // escape this handler.
        if (sender is not FrameworkElement fe || fe.DataContext is not SessionTabViewModel tab) return;
        try
        {
            await _fileTransferDialog.ShowAsync(tab);
        }
        catch (Exception ex)
        {
            var logger = App.Current.Services.GetService<ILogger<SessionsPage>>();
            logger?.LogError(ex, "File-transfer dialog failed to open.");
        }
    }
}
