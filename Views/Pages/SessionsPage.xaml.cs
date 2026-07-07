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
    private readonly HashSet<SessionTabViewModel> _closingTabs = new();

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
        if (!ViewModel.Tabs.Contains(tab)) return;
        if (!_closingTabs.Add(tab)) return;

        var wasSelected = ReferenceEquals(ViewModel.SelectedTab, tab);
        try
        {
            // When the *active* tab is closed, move selection to its closest neighbour BEFORE
            // removing it. Removing the selected item and letting TabView auto-pick a successor
            // routes the new tab through a content-realization path that doesn't reliably
            // re-Load its surface: the SSH session keeps running but the terminal's WebView2
            // never rebinds, so it stays black until a full reconnect. Selecting the neighbour
            // first drives the switch through the normal selection-change path (the same one a
            // manual tab switch uses, which reattaches correctly), after which the closed tab is
            // just a background tab whose removal no longer disturbs the visible surface.
            // Only redirect when there's actually a neighbour to move to - closing the last
            // tab leaves removal to clear selection and show the empty state.
            if (wasSelected && FindClosestTab(tab) is { } neighbour)
            {
                ViewModel.SelectedTab = neighbour;
            }

            // Remove the tab BEFORE awaiting its teardown. CloseAsync can take a noticeable
            // amount of time (e.g. an SSH tab waiting on tunnel sidecar disposal), and while it
            // runs the tab would otherwise linger in ViewModel.Tabs. A second close issued in
            // that window could then redirect selection back onto this tab (or TabView could
            // auto-select it), re-Loading its view after the session was nulled - which spins up
            // an orphaned reconnection right before the tab is finally removed. Pulling it from
            // the collection up front makes it unreachable for selection during teardown; the VM
            // stays alive through the captured local, so CloseAsync still runs to completion.
            ViewModel.Tabs.Remove(tab);
            if (wasSelected)
            {
                FocusSessionsSurface();
            }

            await tab.CloseAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            var logger = App.Current.Services.GetService<ILogger<SessionsPage>>();
            logger?.LogWarning(ex, "Session tab '{Title}' failed to close.", tab.Title);
        }
        finally
        {
            _closingTabs.Remove(tab);
        }
    }

    private void FocusSessionsSurface()
    {
        _ = DispatcherQueue.TryEnqueue(() =>
        {
            try
            {
                if (ViewModel.HasTabs && SessionTabs.Focus(FocusState.Programmatic)) return;
                SessionsRoot.Focus(FocusState.Programmatic);
            }
            catch (Exception ex)
            {
                var logger = App.Current?.Services?.GetService<ILogger<SessionsPage>>();
                logger?.LogDebug(ex, "SessionsPage focus push after tab close was suppressed.");
            }
        });
    }

    // The still-open tab nearest the one being closed: prefer the right neighbour, then the
    // left, mirroring TabView's own "closest" heuristic. Null when <paramref name="tab"/> is
    // the only tab, leaving the sessions surface empty.
    private SessionTabViewModel? FindClosestTab(SessionTabViewModel tab)
    {
        var tabs = ViewModel.Tabs;
        var index = tabs.IndexOf(tab);
        if (index < 0) return null;
        if (index + 1 < tabs.Count) return tabs[index + 1];
        if (index - 1 >= 0) return tabs[index - 1];
        return null;
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
