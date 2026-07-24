using System.Collections.Specialized;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Wormhole.Helpers;
using Wormhole.Services;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;
using Wormhole.ViewModels.Sessions.Layout;
using Wormhole.Views.Controls;
using Wormhole.Views.Sessions;

namespace Wormhole.Views.Pages;

public sealed partial class SessionsPage : Page
{
    private readonly ISessionTabFactory _sessionTabFactory;
    private readonly IFileTransferDialogService _fileTransferDialog;
    private readonly HashSet<SessionTabViewModel> _closingTabs = new();
    private bool _sessionSurfaceHostHooked;

    public ShellViewModel ViewModel { get; }

    public SessionsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<ShellViewModel>();
        _sessionTabFactory = App.Current.Services.GetRequiredService<ISessionTabFactory>();
        _fileTransferDialog = App.Current.Services.GetRequiredService<IFileTransferDialogService>();
        this.InitializeComponent();
        Loaded += OnSessionsPageLoaded;
        Unloaded += OnSessionsPageUnloaded;
    }

    private void OnSessionsPageLoaded(object sender, RoutedEventArgs e)
    {
        EnsureSessionSurfaceHostHooked();
        SyncSessionSurfaces();
        UpdateGlobalTabStripVisibility();
    }

    private void OnSessionsPageUnloaded(object sender, RoutedEventArgs e)
    {
        // NavigationCacheMode=Required keeps the page instance; surfaces stay in the layout host
        // so a return can re-show them. Unhook collection listeners only while the page is out of
        // the tree so a cached instance does not double-subscribe after the next Loaded.
        if (!_sessionSurfaceHostHooked) return;
        ViewModel.Tabs.CollectionChanged -= OnSessionTabsChanged;
        ViewModel.PropertyChanged -= OnShellPropertyChanged;
        ViewModel.Layout.PropertyChanged -= OnLayoutPropertyChanged;
        SessionLayout.PaneCloseRequested -= OnPaneCloseRequested;
        SessionLayout.PaneRestoreFullViewRequested -= OnPaneRestoreFullViewRequested;
        SessionLayout.PaneDuplicateRequested -= OnPaneDuplicateRequested;
        SessionLayout.PaneFileTransferRequested -= OnPaneFileTransferRequested;
        _sessionSurfaceHostHooked = false;
    }

    private void EnsureSessionSurfaceHostHooked()
    {
        if (_sessionSurfaceHostHooked) return;
        ViewModel.Tabs.CollectionChanged += OnSessionTabsChanged;
        ViewModel.PropertyChanged += OnShellPropertyChanged;
        ViewModel.Layout.PropertyChanged += OnLayoutPropertyChanged;
        SessionLayout.PaneCloseRequested += OnPaneCloseRequested;
        SessionLayout.PaneRestoreFullViewRequested += OnPaneRestoreFullViewRequested;
        SessionLayout.PaneDuplicateRequested += OnPaneDuplicateRequested;
        SessionLayout.PaneFileTransferRequested += OnPaneFileTransferRequested;
        _sessionSurfaceHostHooked = true;
    }

    private void OnShellPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ShellViewModel.SelectedTab) or nameof(ShellViewModel.Tabs))
        {
            SyncSessionSurfaces();
        }
    }

    private void OnLayoutPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(SessionLayoutController.StructureVersion)
            or nameof(SessionLayoutController.Root)
            or nameof(SessionLayoutController.LeafCount))
        {
            SyncSessionSurfaces();
            UpdateGlobalTabStripVisibility();
        }
    }

    /// <summary>
    /// Multi-pane layouts use per-pane connection rows (mRemoteNG-style). Hide the global
    /// strip so each tiled pane owns its own detached connection header.
    /// </summary>
    private void UpdateGlobalTabStripVisibility()
    {
        var multiPane = ViewModel.Layout.LeafCount > 1;
        SessionTabs.Visibility = multiPane ? Visibility.Collapsed : Visibility.Visible;
        if (!multiPane)
        {
            EnsureTabViewHeaderOnlyLayout();
        }
    }

    private async void OnPaneCloseRequested(object? sender, SessionTabViewModel tab)
    {
        await CloseTabAsync(tab);
    }

    private void OnPaneRestoreFullViewRequested(object? sender, SessionTabViewModel tab)
    {
        ViewModel.RestoreTabToFullView(tab);
        UpdateGlobalTabStripVisibility();
    }

    private void OnPaneDuplicateRequested(object? sender, SessionTabViewModel tab)
    {
        if (tab.Profile is { } profile)
        {
            _sessionTabFactory.Open(profile);
        }
    }

    private async void OnPaneFileTransferRequested(object? sender, SessionTabViewModel tab)
    {
        try
        {
            await _fileTransferDialog.ShowAsync(tab);
        }
        catch (Exception ex)
        {
            var logger = App.Current.Services.GetService<ILogger<SessionsPage>>();
            logger?.LogError(ex, "File-transfer dialog failed to open from pane header.");
        }
    }

    private void OnSessionTabsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        SyncSessionSurfaces();
    }

    /// <summary>
    /// Keep one realized protocol surface per open tab inside <see cref="SessionLayout"/>.
    /// Visible leaves show their surfaces tiled; other tabs stay Collapsed (not Unloaded) so SSH
    /// WebView2 / exact-replay checkpoints survive tab switches and pane moves.
    /// </summary>
    private void SyncSessionSurfaces()
    {
        var selector = (SessionContentSelector)Resources["SessionContentSelector"];
        SessionLayout.SyncSurfaces(ViewModel.Tabs, selector);
    }

    private void SessionTabs_TabDragStarting(TabView sender, TabViewTabDragStartingEventArgs args)
    {
        if (args.Item is not SessionTabViewModel tab)
        {
            return;
        }

        SessionLayout.BeginTabDrag(tab);
        args.Data.Properties[SessionLayoutHost.DragTabFormat] = tab;
        args.Data.RequestedOperation = DataPackageOperation.Move;
    }

    private void SessionTabs_TabDragCompleted(TabView sender, TabViewTabDragCompletedEventArgs args)
    {
        SessionLayout.NotifyDragSourceCompleted();
    }

    /// <summary>
    /// Dropping a tiled tab back onto the strip restores the original single-pane view.
    /// When only one pane is visible, leave the event alone so TabView can reorder.
    /// </summary>
    private void SessionTabs_TabStripDragOver(object sender, DragEventArgs e)
    {
        if (!TryGetRestoreDropTab(e, out _))
        {
            return;
        }

        e.AcceptedOperation = DataPackageOperation.Move;
        if (e.DragUIOverride is not null)
        {
            e.DragUIOverride.IsGlyphVisible = false;
            e.DragUIOverride.Caption = "Restore full view";
        }

        e.Handled = true;
    }

    private void SessionTabs_TabStripDrop(object sender, DragEventArgs e)
    {
        if (!TryGetRestoreDropTab(e, out var tab) || tab is null)
        {
            return;
        }

        ViewModel.RestoreTabToFullView(tab);
        e.Handled = true;
    }

    private bool TryGetRestoreDropTab(DragEventArgs e, out SessionTabViewModel? tab)
    {
        tab = SessionLayout.DraggedTab;
        if (tab is null
            || ViewModel.Layout.LeafCount <= 1
            || ViewModel.Layout.FindLeaf(tab) is null)
        {
            return false;
        }

        return true;
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
    /// Protocol surfaces are hosted in SessionLayoutHost (outside the TabView) — leaving the
    /// default star-sized content row would steal the whole pane (and Auto-size the strip row
    /// incorrectly). Idempotent: safe to re-run after template rebuild.
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
            // removing it. Multi-surface hosting keeps background surfaces alive, but closing the
            // selected tab still needs an explicit neighbour hand-off through the normal
            // selection-change path.
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
            // SyncSessionSurfaces removes the matching surface from SessionLayoutHost.
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
        // fires first, Command.Execute second). Background SSH tabs keep their surface alive
        // under Collapsed, but selecting still ensures focus and activation run before Retry.
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
