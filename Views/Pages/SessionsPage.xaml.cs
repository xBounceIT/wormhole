using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Wormhole.Helpers;
using Wormhole.Services;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;
using Wormhole.Views.Controls;

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

    private void SessionTabs_Loaded(object sender, RoutedEventArgs e)
    {
        EnsureTabViewHeaderOnlyLayout();
    }

    private void SessionTabs_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        // Template children can appear after the first Loaded, and Visibility toggles can rebuild
        // the template while the page stays cached — keep the collapse idempotent.
        EnsureTabViewHeaderOnlyLayout();
    }

    /// <summary>
    /// Collapse TabView's internal content presenter so the control is header-strip-only.
    /// The protocol surface is hosted outside the TabView (SelectedSessionHost) bound to
    /// SelectedTab — leaving the default star-sized content row would steal the whole pane
    /// (and Auto-size the strip row incorrectly). Idempotent: safe to re-run after template rebuild.
    /// </summary>
    private void EnsureTabViewHeaderOnlyLayout()
    {
        // Default TabView template: root Grid row0=TabListView, row1=ContentPresenter (star height).
        if (VisualTreeHelper.GetChildrenCount(SessionTabs) < 1) return;
        if (VisualTreeHelper.GetChild(SessionTabs, 0) is not Grid root) return;
        if (root.RowDefinitions.Count < 2) return;

        // Zero the star content row and collapse its presenter. Height/MaxHeight are left alone —
        // Visibility.Collapsed + a 0-height row is enough for Auto sizing of the strip.
        if (root.RowDefinitions[1].Height != new GridLength(0))
        {
            root.RowDefinitions[1].Height = new GridLength(0);
        }

        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            if (VisualTreeHelper.GetChild(root, i) is not FrameworkElement child) continue;
            if (Grid.GetRow(child) != 1) continue;
            if (child.Visibility != Visibility.Collapsed) child.Visibility = Visibility.Collapsed;
        }
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

        // TabView updates its own SelectedItem as part of the middle-click gesture, while the
        // TwoWay binding can reach the VM a dispatcher tick later. Treat either side as authoritative
        // during that window; relying on the VM alone makes this path timing-dependent.
        var wasSelected = ReferenceEquals(SessionTabs.SelectedItem, tab) ||
                          ReferenceEquals(ViewModel.SelectedTab, tab);
        try
        {
            // When the *active* tab is closed, move selection to its closest neighbour BEFORE
            // removing it. The heavy session surface lives outside TabView (SelectedSessionHost
            // on SelectedTab), so a background-tab close no longer disturbs it — but closing the
            // selected tab still needs an explicit neighbour hand-off. Selecting the neighbour
            // first drives the switch through the normal selection-change path; the closed tab is
            // then just a background header whose removal no longer blanks the host.
            // Only redirect when there's actually a neighbour to move to - closing the last
            // tab leaves removal to clear selection and show the empty state.
            if (wasSelected && FindClosestTab(tab) is { } neighbour)
            {
                // Drive the control directly as well as the VM. Setting only the bound property can
                // be overtaken by TabView's own selection coercion when the selected container is
                // removed later in this same close gesture.
                SessionTabs.SelectedItem = neighbour;
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
        try
        {
            // Middle-click does not move keyboard focus to the tab header. Move it away from the
            // tree immediately, then verify again after TabView has finished its pointer/selection
            // work. The delayed pass only acts if the original focus became stale or WinUI returned
            // focus to the connection tree, so it cannot steal focus from the new terminal, a
            // dialog, or a native RDP surface.
            var focusAtClose = GetFocusedElement();
            if (focusAtClose is null) return;

            if (!IsFocusWithinSessionsSurface(focusAtClose))
            {
                FocusSessionsSurfaceCore();
            }

            _ = DispatcherQueue.TryEnqueue(
                DispatcherQueuePriority.Low,
                () => RestoreFocusIfStale(focusAtClose));
        }
        catch (Exception ex)
        {
            LogFocusFailure(ex);
        }
    }

    private void RestoreFocusIfStale(DependencyObject focusAtClose)
    {
        try
        {
            var focused = GetFocusedElement();
            var returnedToTree = IsFocusWithinConnectionTree(focused);
            var originalFocusBecameStale =
                ReferenceEquals(focused, focusAtClose) && !IsFocusWithinSessionsSurface(focused);
            if (returnedToTree || originalFocusBecameStale)
            {
                FocusSessionsSurfaceCore();
            }
        }
        catch (Exception ex)
        {
            LogFocusFailure(ex);
        }
    }

    private void FocusSessionsSurfaceCore()
    {
        if (!SessionsRoot.Focus(FocusState.Programmatic) && ViewModel.HasTabs)
        {
            SessionTabs.Focus(FocusState.Programmatic);
        }
    }

    private DependencyObject? GetFocusedElement() =>
        XamlRoot is { } root ? FocusManager.GetFocusedElement(root) as DependencyObject : null;

    private bool IsFocusWithinSessionsSurface(DependencyObject? current)
    {
        while (current is not null)
        {
            if (ReferenceEquals(current, SessionsRoot)) return true;
            current = VisualTreeHelper.GetParent(current);
        }

        return false;
    }

    private static bool IsFocusWithinConnectionTree(DependencyObject? current)
    {
        while (current is not null)
        {
            if (current is ConnectionTreeView) return true;
            current = VisualTreeHelper.GetParent(current);
        }

        return false;
    }

    private static void LogFocusFailure(Exception ex)
    {
        var logger = App.Current?.Services?.GetService<ILogger<SessionsPage>>();
        logger?.LogDebug(ex, "SessionsPage focus push after tab close was suppressed.");
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
