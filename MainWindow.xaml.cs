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
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Mcp;
using Wormhole.Services.Security;
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
    private readonly IAppSettingsService _settingsService;
    private readonly IAppAuthenticationService _appAuthentication;
    private readonly IWindowsHelloService _windowsHello;
    private readonly IAppLockState _lockState;
    private readonly AppInactivityLockEvaluator _inactivityLockEvaluator;
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
    private DispatcherQueueTimer? _idleLockTimer;
    private Task<bool>? _activeUnlockTask;
    private TaskCompletionSource<bool>? _activeUnlockTcs;
    private IDisposable? _lockOverlaySuppression;
    private AppAuthenticationFallbackMethod _lockFallbackMethod = AppAuthenticationFallbackMethod.Pin;
    private bool _lockHelloInProgress;
    private bool _lockUnlockInProgress;

    public ShellViewModel ViewModel { get; }

    public MainWindow(
        ShellViewModel viewModel,
        INavigationService navigationService,
        IDialogService dialogService,
        IAppSettingsService settingsService,
        IAppAuthenticationService appAuthentication,
        IWindowsHelloService windowsHello,
        IAppLockState lockState,
        AppInactivityLockEvaluator inactivityLockEvaluator,
        ILogger<MainWindow> logger)
    {
        ViewModel = viewModel;
        _navigationService = navigationService;
        _dialogService = dialogService;
        _settingsService = settingsService;
        _appAuthentication = appAuthentication;
        _windowsHello = windowsHello;
        _lockState = lockState;
        _inactivityLockEvaluator = inactivityLockEvaluator;
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
        _settingsService.SettingsChanged += OnSettingsChanged;
        EnsureIdleLockTimer();
        if (_settingsService.Current.AppAuthenticationMode != AppAuthenticationMode.Disabled)
        {
            ShowPendingAuthenticationOverlay();
        }

        _ = RunStartupUpdateCheckAsync();
    }

    public async Task RunStartupAuthenticationAsync()
    {
        _inactivityLockEvaluator.MarkUnlocked(DateTimeOffset.UtcNow);
        if (await ShouldRequireAuthenticationAsync().ConfigureAwait(true))
        {
            await ShowLockOverlayAsync("Unlock Wormhole to continue.").ConfigureAwait(true);
            return;
        }

        HideLockOverlay();
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
                // Fail safe: leave the window open rather than tearing down live sessions if the
                // confirmation cannot be shown or queued for any reason.
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
        if (activeCount > 0 || ViewModel.HasTabs)
        {
            ShowModalOverlay(CreateShutdownOverlay(activeCount));
            await WaitForDispatcherTurnAsync().ConfigureAwait(true);
        }

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

    private static StackPanel CreateShutdownOverlay(int activeCount)
    {
        var panel = new StackPanel
        {
            Spacing = 12,
            Margin = new Thickness(28),
            Width = 360,
        };

        panel.Children.Add(new ProgressRing
        {
            IsActive = true,
            Width = 36,
            Height = 36,
            HorizontalAlignment = HorizontalAlignment.Center,
        });
        panel.Children.Add(new TextBlock
        {
            Text = "Closing connections...",
            FontSize = 20,
            HorizontalAlignment = HorizontalAlignment.Center,
            TextAlignment = TextAlignment.Center,
        });
        panel.Children.Add(new TextBlock
        {
            Text = activeCount == 1
                ? "Disconnecting 1 active connection and shutting down Wormhole."
                : activeCount > 1
                    ? $"Disconnecting {activeCount} active connections and shutting down Wormhole."
                    : "Closing session tabs and shutting down Wormhole.",
            TextWrapping = TextWrapping.Wrap,
            TextAlignment = TextAlignment.Center,
            Opacity = 0.8,
        });

        return panel;
    }

    private Task WaitForDispatcherTurnAsync()
    {
        var completion = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => completion.TrySetResult(null)))
        {
            return Task.CompletedTask;
        }
        return completion.Task;
    }

    private void OnSettingsChanged(object? sender, EventArgs args)
    {
        if (DispatcherQueue.HasThreadAccess)
        {
            _ = ApplySettingsChangedAsync();
            return;
        }

        if (!DispatcherQueue.TryEnqueue(() => _ = ApplySettingsChangedAsync()))
        {
            _logger.LogWarning("Could not marshal settings-change handling to the UI thread.");
        }
    }

    private async Task ApplySettingsChangedAsync()
    {
        try
        {
            EnsureIdleLockTimer();
            if (!await ShouldRequireAuthenticationAsync().ConfigureAwait(true))
            {
                HideLockOverlay();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to apply settings change.");
        }
    }

    private void EnsureIdleLockTimer()
    {
        if (_idleLockTimer is null)
        {
            _idleLockTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
            _idleLockTimer.Interval = TimeSpan.FromSeconds(15);
            _idleLockTimer.IsRepeating = true;
            _idleLockTimer.Tick += IdleLockTimer_Tick;
        }

        if (_settingsService.Current.AppAuthenticationMode != AppAuthenticationMode.Disabled &&
            _settingsService.Current.AppAuthenticationIdleTimeoutMinutes is not null)
        {
            _idleLockTimer.Start();
        }
        else
        {
            _idleLockTimer.Stop();
        }
    }

    private async void IdleLockTimer_Tick(DispatcherQueueTimer sender, object args)
    {
        if (!await ShouldRequireAuthenticationAsync().ConfigureAwait(true)) return;
        var idle = GetSystemIdleTime();
        if (!_inactivityLockEvaluator.ShouldLock(_settingsService.Current, _lockState.IsLocked, idle, DateTimeOffset.UtcNow))
        {
            return;
        }
        _ = ShowLockOverlayAsync("Wormhole locked after inactivity.");
    }

    private static TimeSpan GetSystemIdleTime()
    {
        var info = new Win32Interop.LASTINPUTINFO
        {
            cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Win32Interop.LASTINPUTINFO>(),
        };
        if (!Win32Interop.GetLastInputInfo(ref info))
        {
            return TimeSpan.Zero;
        }

        var now = unchecked((uint)Win32Interop.GetTickCount64());
        var elapsed = unchecked(now - info.dwTime);
        return TimeSpan.FromMilliseconds(elapsed);
    }

    private async Task<bool> ShouldRequireAuthenticationAsync()
    {
        var settings = _settingsService.Current;
        if (settings.AppAuthenticationMode == AppAuthenticationMode.Disabled) return false;

        var configured = await _appAuthentication.IsConfiguredForModeAsync(
            settings.AppAuthenticationMode,
            settings.AppAuthenticationHelloFallback).ConfigureAwait(true);
        if (!configured)
        {
            _logger.LogWarning(
                "App authentication mode {Mode} is enabled but no valid verifier is configured; skipping lock.",
                settings.AppAuthenticationMode);
        }
        return configured;
    }

    private Task<bool> ShowLockOverlayAsync(string message)
    {
        if (_activeUnlockTask is not null) return _activeUnlockTask;
        _activeUnlockTask = ShowLockOverlayCoreAsync(message);
        return _activeUnlockTask;
    }

    private async Task<bool> ShowLockOverlayCoreAsync(string message)
    {
        _activeUnlockTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _lockState.SetLocked(true);
        BeginLockOverlaySuppression();
        ResetLockOverlay(message);

        var settings = _settingsService.Current;
        if (settings.AppAuthenticationMode == AppAuthenticationMode.WindowsHello)
        {
            WindowsHelloUnlockButton.Visibility = Visibility.Visible;
            _lockFallbackMethod = settings.AppAuthenticationHelloFallback;
            await TryUnlockWithWindowsHelloAsync().ConfigureAwait(true);
        }
        else
        {
            _lockFallbackMethod = FallbackMethodForMode(settings.AppAuthenticationMode);
            ShowFallbackUnlock(null);
        }

        try
        {
            return await _activeUnlockTcs.Task.ConfigureAwait(true);
        }
        finally
        {
            _activeUnlockTask = null;
            _activeUnlockTcs = null;
        }
    }

    private void ShowPendingAuthenticationOverlay()
    {
        _lockState.SetLocked(true);
        BeginLockOverlaySuppression();
        ResetLockOverlay("Checking app authentication.");
    }

    private void ResetLockOverlay(string message)
    {
        ContentDialogTracker.LockAndHideAll();
        SetShellEnabled(false);
        LockTitleText.Text = "Wormhole is locked";
        LockMessageText.Text = message;
        LockErrorBar.IsOpen = false;
        LockSecretBox.Password = string.Empty;
        LockSecretBox.Visibility = Visibility.Collapsed;
        LockUnlockButton.Visibility = Visibility.Collapsed;
        WindowsHelloUnlockButton.Visibility = Visibility.Collapsed;
        LockOverlayHost.Visibility = Visibility.Visible;
    }

    private void BeginLockOverlaySuppression()
    {
        _lockOverlaySuppression ??= RdpOverlayCoordinator.Suppress();
    }

    private void HideLockOverlay()
    {
        LockSecretBox.Password = string.Empty;
        LockOverlayHost.Visibility = Visibility.Collapsed;
        _lockOverlaySuppression?.Dispose();
        _lockOverlaySuppression = null;
        _lockState.SetLocked(false);
        ContentDialogTracker.Unlock();
        SetShellEnabled(true);
    }

    private void SetShellEnabled(bool isEnabled)
    {
        var shellOpacity = isEnabled ? 1.0 : 0.0;
        AppTitleBar.IsEnabled = isEnabled;
        AppTitleBar.Opacity = shellOpacity;
        UpdateInfoBar.IsEnabled = isEnabled;
        UpdateInfoBar.Opacity = shellOpacity;
        NavView.IsEnabled = isEnabled;
        ContentArea.Visibility = isEnabled ? Visibility.Visible : Visibility.Collapsed;
        ContentArea.IsHitTestVisible = isEnabled;
        ModalOverlayHost.Opacity = shellOpacity;
        ModalOverlayHost.IsHitTestVisible = isEnabled;
        if (ModalOverlayContent.Content is Control modalControl)
        {
            modalControl.IsEnabled = isEnabled;
        }
    }

    private async void WindowsHelloUnlockButton_Click(object sender, RoutedEventArgs e)
    {
        await TryUnlockWithWindowsHelloAsync().ConfigureAwait(true);
    }

    private async Task TryUnlockWithWindowsHelloAsync()
    {
        if (_lockHelloInProgress) return;
        _lockHelloInProgress = true;
        WindowsHelloUnlockButton.IsEnabled = false;
        LockMessageText.Text = "Waiting for Windows Hello.";
        LockErrorBar.IsOpen = false;
        try
        {
            WindowsHelloAvailability availability;
            try
            {
                availability = await _windowsHello.CheckAvailabilityAsync().ConfigureAwait(true);
            }
            catch (Exception ex) when (IsExpectedWindowsHelloFailure(ex))
            {
                ShowWindowsHelloUnavailableFallback(ex);
                return;
            }

            if (!availability.IsAvailable)
            {
                ShowFallbackUnlock(availability.Message);
                return;
            }

            WindowsHelloVerification verified;
            try
            {
                verified = await _windowsHello.RequestVerificationAsync(this.GetHwnd(), "Unlock Wormhole").ConfigureAwait(true);
            }
            catch (Exception ex) when (IsExpectedWindowsHelloFailure(ex))
            {
                ShowWindowsHelloUnavailableFallback(ex);
                return;
            }

            if (verified.IsVerified)
            {
                CompleteUnlock();
                return;
            }
            ShowFallbackUnlock(verified.Message);
        }
        finally
        {
            _lockHelloInProgress = false;
            WindowsHelloUnlockButton.IsEnabled = true;
        }
    }

    private void ShowFallbackUnlock(string? error)
    {
        LockMessageText.Text = _lockFallbackMethod == AppAuthenticationFallbackMethod.Pin
            ? "Enter your Wormhole PIN to continue."
            : "Enter your Wormhole password to continue.";
        LockSecretBox.Header = SecretLabel(_lockFallbackMethod);
        LockUnlockButton.Content = "Unlock";
        LockSecretBox.Visibility = Visibility.Visible;
        LockUnlockButton.Visibility = Visibility.Visible;
        if (!string.IsNullOrWhiteSpace(error))
        {
            LockErrorBar.Message = error;
            LockErrorBar.IsOpen = true;
        }
        LockSecretBox.Focus(FocusState.Programmatic);
    }

    private void LockSecretBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        LockUnlockButton.IsEnabled = !string.IsNullOrEmpty(LockSecretBox.Password);
    }

    private async void LockSecretBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key != Windows.System.VirtualKey.Enter || !LockUnlockButton.IsEnabled) return;
        e.Handled = true;
        await TryUnlockWithFallbackAsync().ConfigureAwait(true);
    }

    private async void LockUnlockButton_Click(object sender, RoutedEventArgs e)
    {
        await TryUnlockWithFallbackAsync().ConfigureAwait(true);
    }

    private async Task TryUnlockWithFallbackAsync()
    {
        if (_lockUnlockInProgress) return;
        _lockUnlockInProgress = true;
        LockUnlockButton.IsEnabled = false;
        try
        {
            var verified = await _appAuthentication.VerifySecretAsync(_lockFallbackMethod, LockSecretBox.Password).ConfigureAwait(true);
            if (verified)
            {
                CompleteUnlock();
                return;
            }

            LockErrorBar.Message = InvalidSecretMessage(_lockFallbackMethod);
            LockErrorBar.IsOpen = true;
            LockSecretBox.Password = string.Empty;
            LockSecretBox.Focus(FocusState.Programmatic);
        }
        finally
        {
            _lockUnlockInProgress = false;
            LockUnlockButton.IsEnabled = !string.IsNullOrEmpty(LockSecretBox.Password);
        }
    }

    private static bool IsExpectedWindowsHelloFailure(Exception ex) =>
        ex is UnauthorizedAccessException
            or InvalidOperationException
            or NotSupportedException
            or System.Runtime.InteropServices.COMException
            or InvalidCastException;

    private void ShowWindowsHelloUnavailableFallback(Exception ex)
    {
        _logger.LogInformation(ex, "Windows Hello unlock was unavailable; showing configured fallback.");
        ShowFallbackUnlock("Windows Hello is unavailable.");
    }

    private static AppAuthenticationFallbackMethod FallbackMethodForMode(AppAuthenticationMode mode) =>
        mode == AppAuthenticationMode.Password
            ? AppAuthenticationFallbackMethod.Password
            : AppAuthenticationFallbackMethod.Pin;

    private static string SecretLabel(AppAuthenticationFallbackMethod method) =>
        method == AppAuthenticationFallbackMethod.Pin ? "PIN" : "Password";

    private static string InvalidSecretMessage(AppAuthenticationFallbackMethod method) =>
        method == AppAuthenticationFallbackMethod.Pin ? "Invalid PIN." : "Invalid password.";

    private void CompleteUnlock()
    {
        HideLockOverlay();
        _inactivityLockEvaluator.MarkUnlocked(DateTimeOffset.UtcNow);
        _activeUnlockTcs?.TrySetResult(true);
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, () => ContentFrame.Focus(FocusState.Programmatic));
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
    public void ShowModalOverlay(UIElement content, double? width = null, double? height = null)
    {
        if (width is { } modalWidth)
        {
            ModalOverlayFrame.MinWidth = modalWidth;
            ModalOverlayFrame.MaxWidth = modalWidth;
        }
        else
        {
            ModalOverlayFrame.MinWidth = 380;
            ModalOverlayFrame.MaxWidth = 600;
        }

        if (height is { } modalHeight)
        {
            ModalOverlayFrame.MinHeight = modalHeight;
            ModalOverlayFrame.MaxHeight = modalHeight;
        }
        else
        {
            ModalOverlayFrame.MinHeight = 0;
            ModalOverlayFrame.MaxHeight = double.PositiveInfinity;
        }

        ModalOverlayContent.Content = content;
        ModalOverlayHost.Visibility = Visibility.Visible;
    }

    /// <summary>Hide the app-modal overlay and release its content so the hosted control (and its
    /// view-model) can be collected.</summary>
    public void HideModalOverlay()
    {
        ModalOverlayHost.Visibility = Visibility.Collapsed;
        ModalOverlayContent.Content = null;
        ModalOverlayFrame.MinWidth = 380;
        ModalOverlayFrame.MaxWidth = 600;
        ModalOverlayFrame.MinHeight = 0;
        ModalOverlayFrame.MaxHeight = double.PositiveInfinity;
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
