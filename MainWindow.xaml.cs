using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Wormhole.Services;
using Wormhole.Services.Mcp;
using Wormhole.ViewModels;
using Wormhole.Views.Pages;

namespace Wormhole;

public sealed partial class MainWindow : Window
{
    // ConnectionTreeView's horizontal Margin "8,4,8,8" (8 left + 8 right = 16)
    // plus NavigationView's empirically-observed PaneCustomContent padding (~12).
    private const double PaneCustomContentInset = 28;

    // Pane padding/separator above and below the footer items block. Tuned so
    // the bounded tree leaves a small gap before the footer rather than butting
    // right up against it.
    private const double FooterChromeReserve = 24;

    // Floor so a transient zero-height layout pass (e.g. before the footer
    // items have measured) doesn't collapse the tree to nothing.
    private const double MinConnectionsTreeHeight = 100;

    private readonly INavigationService _navigationService;
    private readonly IDialogService _dialogService;
    private readonly ILogger<MainWindow> _logger;

    private bool _isResizingSidebar;
    private double _resizeStartWidth;
    private double _resizeStartPointerX;
    private bool _minSidebarMeasured;

    private OverlappedPresenter? _windowPresenter;
    private OverlappedPresenterState _currentWindowState;
    private bool _sessionCleanupInProgress;
    private bool _sessionCleanupComplete;
    private bool _closePromptInProgress;
    private double _lastConnectionsTreeMaxHeight = double.NaN;

    public ShellViewModel ViewModel { get; }

    public MainWindow(ShellViewModel viewModel, INavigationService navigationService, IDialogService dialogService, ILogger<MainWindow> logger)
    {
        ViewModel = viewModel;
        _navigationService = navigationService;
        _dialogService = dialogService;
        _logger = logger;

        this.InitializeComponent();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        // The native TitleBar control renders at ~48 px; match the AppWindow's
        // caption-button strip so they don't draw at different heights and leave
        // a visible seam.
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

        // Workaround for WinUI issue #9934 (microsoft/microsoft-ui-xaml): even
        // with PreferredHeightOption.Tall, a 1-2 px gap remains between the
        // system caption buttons and the content below the title bar. Pull
        // the content up by a small negative margin to close it, and re-apply
        // on window-state changes since the inset differs when maximized.
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            _windowPresenter = presenter;
            _currentWindowState = presenter.State;
            AdjustContentMargin(force: true);
            AppWindow.Changed += (_, _) => AdjustContentMargin();
        }

        SystemBackdrop = new MicaBackdrop { Kind = Microsoft.UI.Composition.SystemBackdrops.MicaKind.Base };
        AppWindow.Closing += OnAppWindowClosing;

        _navigationService.Initialize(ContentFrame);
        _navigationService.Navigate(typeof(SessionsPage));

        // Keep the VM informed of the window's content width so the sidebar can
        // re-clamp on window shrink and the resizer stays reachable on-screen.
        RootGrid.SizeChanged += (_, args) =>
        {
            ViewModel.MaxAvailableWidth = args.NewSize.Width;
        };

        // NavigationView.PaneCustomContent sits in an Auto-height row of the
        // pane template, so ConnectionTreeView is measured with infinite
        // height and its TreeView's internal ScrollViewer never engages —
        // the tree just grows and z-orders over the footer items. Bound the
        // tree's height to "pane height minus footer block" on every resize
        // so the built-in scroller takes over and the footer stays visible.
        NavView.SizeChanged += (_, _) => ApplyConnectionsTreeMaxHeight();

        Activated += OnFirstActivated;

        _ = RunStartupUpdateCheckAsync();
    }

    private async Task RunStartupUpdateCheckAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        await ViewModel.Update.RunStartupCheckAsync().ConfigureAwait(false);
    }

    private async void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_sessionCleanupComplete) return;

        args.Cancel = true;
        // Ignore repeat close clicks while we're already mid-teardown, or while the
        // confirmation prompt from an earlier click is still up. Both run on this (UI)
        // thread, so the flags are only ever read/written between awaits — no locking needed.
        if (_sessionCleanupInProgress || _closePromptInProgress) return;

        // Warn before tearing down live connections so a stray Alt+F4 — or a misclick on the
        // close button — can't silently drop an SSH shell or RDP session. Only prompt when
        // something is actually connected/connecting; a window full of disconnected tabs has
        // nothing to lose. A "Cancel" leaves the window open for a later attempt.
        // Snapshot once: ActiveSessionCount scans the tab collection, and capturing it keeps the
        // gate and the message text consistent.
        var activeCount = ViewModel.ActiveSessionCount;
        if (activeCount > 0)
        {
            _closePromptInProgress = true;
            bool confirmed;
            try
            {
                confirmed = await _dialogService.ConfirmAsync(
                    "Close Wormhole?",
                    activeCount == 1
                        ? "1 connection is still open. Closing the app will disconnect it."
                        : $"{activeCount} connections are still open. Closing the app will disconnect them.",
                    primaryText: "Close and disconnect",
                    closeText: "Cancel");
            }
            catch (Exception ex)
            {
                // Showing our ContentDialog fails if another one already owns the XamlRoot (WinUI
                // permits only one at a time) — e.g. an MCP approval prompt, a file-transfer dialog,
                // or an in-flight backup/import. Fail safe: leave the window open rather than tearing
                // down live sessions out from under that dialog; the user can finish it and retry.
                _logger.LogWarning(ex, "Could not show close-confirmation prompt; leaving the window open.");
                confirmed = false;
            }
            finally
            {
                _closePromptInProgress = false;
            }

            if (!confirmed) return;
        }

        _sessionCleanupInProgress = true;
        try
        {
            try
            {
                // Bound the wait: a long in-flight MCP request (e.g. a slow run_command) must not
                // hold the window-close path open on Kestrel's graceful drain. The cancellation
                // token forces shutdown after a short grace period; the process exit reclaims the
                // rest. Stopping the host first also keeps new tool calls off the sessions that
                // CloseAllSessionsAsync is about to dispose.
                using var stopCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await App.Current.Services.GetRequiredService<IMcpServerHost>().StopAsync(stopCts.Token);
            }
            catch (Exception)
            {
                // Never let MCP shutdown block (or break) the app from closing.
            }
            await ViewModel.CloseAllSessionsAsync();
        }
        finally
        {
            _sessionCleanupComplete = true;
            if (!DispatcherQueue.TryEnqueue(Close))
            {
                Close();
            }
        }
    }

    private void OnFirstActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState == WindowActivationState.Deactivated) return;
        Activated -= OnFirstActivated;
        // Focus the content Frame so the QuickConnect ComboBox (first focusable
        // element in the title-bar row) doesn't keep default launch focus and
        // draw a focus ring. Frame is a Control with IsTabStop=true and a
        // template that draws no focus visual, so this absorbs focus silently.
        // (An IsTabStop=false sink wouldn't work — programmatic Focus returns
        // false in that state in WinUI 3.)
        // Deferred to a low-priority dispatcher tick because the framework's
        // initial-focus pass runs after Activated and would otherwise overwrite
        // our override back onto the ComboBox.
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => ContentFrame.Focus(FocusState.Programmatic));
    }

    private void AdjustContentMargin(bool force = false)
    {
        if (_windowPresenter is null || (!force && _windowPresenter.State == _currentWindowState))
        {
            return;
        }

        var top = _windowPresenter.State == OverlappedPresenterState.Maximized ? -1d : -2d;
        var infoBarMargin = UpdateInfoBar.Margin;
        UpdateInfoBar.Margin = new Thickness(infoBarMargin.Left, top, infoBarMargin.Right, infoBarMargin.Bottom);
        var contentMargin = ContentArea.Margin;
        ContentArea.Margin = new Thickness(contentMargin.Left, top, contentMargin.Right, contentMargin.Bottom);
        _currentWindowState = _windowPresenter.State;
    }

    private void UpdateInfoBar_CloseButtonClick(InfoBar sender, object args)
    {
        ViewModel.Update.DismissCommand.Execute(null);
    }

    /// <summary>
    /// Show <paramref name="content"/> centered in the app-modal overlay layer. This is a plain XAML
    /// layer rather than a <c>ContentDialog</c>, so provider-driven <c>ContentDialog</c>s (the OTP /
    /// WatchGuard SAML prompts a tunnel test can trigger) can still open over it on the same
    /// <c>XamlRoot</c>. Call <see cref="HideModalOverlay"/> to dismiss. UI thread only.
    /// </summary>
    public void ShowModalOverlay(UIElement content)
    {
        ModalOverlayContent.Content = content;
        ModalOverlayHost.Visibility = Visibility.Visible;
    }

    /// <summary>Hide the app-modal overlay and release its content so the hosted control (and its
    /// view-model) can be collected.</summary>
    public void HideModalOverlay()
    {
        ModalOverlayHost.Visibility = Visibility.Collapsed;
        ModalOverlayContent.Content = null;
    }

    private void NavView_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
    {
        if (args.InvokedItemContainer is not NavigationViewItem item) return;
        switch (item.Tag as string)
        {
            case "Credentials":
                _navigationService.Navigate(typeof(CredentialsPage));
                break;
            case "Sessions":
                _navigationService.Navigate(typeof(SessionsPage));
                break;
            case "Tunnels":
                _navigationService.Navigate(typeof(TunnelConfigsPage));
                break;
            case "Settings":
                _navigationService.Navigate(typeof(SettingsPage));
                break;
        }
    }

    private void NavView_Loaded(object sender, RoutedEventArgs e)
    {
        if (_minSidebarMeasured) return;
        _minSidebarMeasured = true;
        // Defer until after the footer items have applied their templates so DesiredSize
        // reflects icon + text + internal padding rather than zero. The same deferral
        // also lets the footer items' ActualHeight settle for ApplyConnectionsTreeMaxHeight.
        NavView.DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () =>
        {
            ComputeMinSidebarWidth();
            ApplyConnectionsTreeMaxHeight();
        });
    }

    private void ApplyConnectionsTreeMaxHeight()
    {
        var footerHeight =
            GetActualHeight(CredentialsItem) +
            GetActualHeight(SessionsItem) +
            GetActualHeight(TunnelsItem) +
            GetActualHeight(SettingsItem);

        var available = NavView.ActualHeight - footerHeight - FooterChromeReserve;
        var maxHeight = Math.Max(MinConnectionsTreeHeight, available);
        if (Math.Abs(maxHeight - _lastConnectionsTreeMaxHeight) < 0.5)
        {
            return;
        }

        _lastConnectionsTreeMaxHeight = maxHeight;
        ConnectionsTree.MaxHeight = maxHeight;
    }

    private static double GetActualHeight(FrameworkElement? element) => element?.ActualHeight ?? 0;

    private void ComputeMinSidebarWidth()
    {
        double maxItemWidth = 0;
        foreach (var item in new[] { CredentialsItem, SessionsItem, TunnelsItem, SettingsItem })
        {
            if (item is null) continue;
            item.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            if (item.DesiredSize.Width > maxItemWidth)
            {
                maxItemWidth = item.DesiredSize.Width;
            }
        }

        var headerWidth = ConnectionsTree.MeasureHeaderDesiredWidth() + PaneCustomContentInset;
        ViewModel.ApplyMeasuredMinSidebarWidth(Math.Max(maxItemWidth, headerWidth));
    }

    private void SidebarResizer_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (sender is not UIElement element) return;
        // Mouse: only the primary (left) button starts a resize so right/middle
        // clicks don't capture the pointer and accidentally shift the pane.
        // Touch/pen presses are inherently primary — no button to gate on.
        var point = e.GetCurrentPoint(element);
        if (e.Pointer.PointerDeviceType == PointerDeviceType.Mouse
            && !point.Properties.IsLeftButtonPressed)
        {
            return;
        }
        if (!element.CapturePointer(e.Pointer)) return;
        _isResizingSidebar = true;
        _resizeStartWidth = ViewModel.SidebarWidth;
        _resizeStartPointerX = e.GetCurrentPoint(null).Position.X;
        e.Handled = true;
    }

    private void SidebarResizer_PointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_isResizingSidebar) return;
        var currentX = e.GetCurrentPoint(null).Position.X;
        ViewModel.SidebarWidth = _resizeStartWidth + (currentX - _resizeStartPointerX);
        e.Handled = true;
    }

    private void SidebarResizer_PointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (!_isResizingSidebar) return;
        // Clear before releasing capture: ReleasePointerCapture fires PointerCaptureLost
        // synchronously, and the handler must short-circuit so it doesn't undo the resize.
        _isResizingSidebar = false;
        if (sender is UIElement element)
        {
            element.ReleasePointerCapture(e.Pointer);
        }
        ViewModel.PersistSidebarWidth();
        e.Handled = true;
    }

    private void SidebarResizer_PointerCaptureLost(object sender, PointerRoutedEventArgs e)
    {
        // Cancel paths (capture stolen, window deactivated, etc.) reach here without
        // a prior PointerReleased, so persist the in-memory width so the resize
        // isn't lost. Normal release short-circuits: PointerReleased clears the
        // flag before ReleasePointerCapture, so this fires with flag=false.
        if (!_isResizingSidebar) return;
        _isResizingSidebar = false;
        ViewModel.PersistSidebarWidth();
    }
}
