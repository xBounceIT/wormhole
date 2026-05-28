using System;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Wormhole.Helpers;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Sessions;

/// <summary>
/// Hosts the RDP ActiveX surface, which lives in a SEPARATE TOP-LEVEL window owned by the main
/// window and composited above the WinUI content (not reparented in as a child — that hits the
/// WinUI 3 airspace problem and renders behind the XAML). This control owns the layout slot and
/// drives MoveWindow in SCREEN coordinates on every SizeChanged / XamlRoot.Changed (DPI) /
/// AppWindow.Changed (move/resize/minimize) tick to keep the overlay positioned over our bounds.
/// The Grid in XAML stays empty — the native surface paints itself over the slot.
/// </summary>
public sealed partial class RdpSurfaceHost : UserControl
{
    private const double LayoutCoalesceMs = 16;

    private RdpSessionViewModel? _viewModel;
    private DispatcherQueueTimer? _layoutTimer;
    private IntPtr _ownerHwnd;
    private bool _attached;
    private double _lastRasterScale = 1.0;
    private Window? _ownerWindow;
    private XamlRoot? _trackedXamlRoot;
    private AppWindow? _trackedAppWindow;
    // One-shot per view load: ensures WinUI focus is pushed at most once per
    // RdpSurfaceHost instance, on the first IsConnected=true transition (cold connect).
    // Resets on Unloaded so a fresh view (Sessions↔Settings nav back, or close+reopen)
    // can push focus again. Without this, auto-reconnect cycles (Status: Connected →
    // Connecting → Connected) would re-fire TryFocusHost on every recovery and steal
    // focus from wherever the user moved it during the reconnect banner.
    private bool _focusPushed;
    // True while a modal ContentDialog is shown over the tab. The overlay is hidden for the
    // duration; layout/visibility ticks must not re-show it (a window move while the dialog is
    // open would otherwise pop the overlay back over the dialog).
    private bool _overlaySuppressed;

    public RdpSurfaceHost()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        SizeChanged += OnSizeChanged;
        // LayoutUpdated is intentionally NOT subscribed: it fires for every visual tree
        // mutation project-wide, not just for this control. SizeChanged + XamlRoot.Changed (DPI)
        // + AppWindow.Changed (window move/resize/minimize) catch the geometry shifts we care
        // about. The overlay is a separate top-level window and does NOT auto-track the owner's
        // client area, so those handlers are required to keep it positioned.
    }

    public RdpSessionViewModel? ViewModel
    {
        get => _viewModel;
        private set
        {
            if (ReferenceEquals(_viewModel, value)) return;
            if (_viewModel is not null)
            {
                _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
            }
            _viewModel = value;
            if (_viewModel is not null)
            {
                _viewModel.PropertyChanged += OnViewModelPropertyChanged;
                UpdateReconnectAttemptText();
            }
        }
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        ViewModel = DataContext as RdpSessionViewModel;
        if (ViewModel is null) return;

        _ownerWindow = App.Current.MainWindow;
        if (_ownerWindow is null)
        {
            var logger = App.Current.Services.GetService<ILogger<RdpSurfaceHost>>();
            logger?.LogWarning("RdpSurfaceHost loaded with no active MainWindow; skipping attach.");
            return;
        }

        _ownerHwnd = _ownerWindow.GetHwnd();
        _lastRasterScale = XamlRoot?.RasterizationScale ?? 1.0;

        // Track XamlRoot.Changed so we re-apply bounds on DPI / window-mode changes (the
        // bare SizeChanged event doesn't fire for those).
        var root = XamlRoot;
        if (root is not null && !ReferenceEquals(_trackedXamlRoot, root))
        {
            if (_trackedXamlRoot is not null) _trackedXamlRoot.Changed -= OnXamlRootChanged;
            _trackedXamlRoot = root;
            _trackedXamlRoot.Changed += OnXamlRootChanged;
        }

        // Follow the main window: the RDP surface is an owned TOP-LEVEL overlay positioned in
        // screen coordinates, so it must be repositioned whenever the main window moves,
        // resizes, maximizes/restores, or is minimized/restored. AppWindow.Changed reports all
        // of these; per-monitor DPI changes are handled separately via XamlRoot.Changed above.
        var appWindow = _ownerWindow.AppWindow;
        if (appWindow is not null && !ReferenceEquals(_trackedAppWindow, appWindow))
        {
            if (_trackedAppWindow is not null) _trackedAppWindow.Changed -= OnOwnerAppWindowChanged;
            _trackedAppWindow = appWindow;
            _trackedAppWindow.Changed += OnOwnerAppWindowChanged;
        }

        // Hide the overlay while a modal ContentDialog is shown over the tab (the top-level
        // overlay would otherwise occlude the centered dialog) and restore it when it closes.
        RdpOverlayCoordinator.SuppressChanged -= OnOverlaySuppressChanged;
        RdpOverlayCoordinator.SuppressChanged += OnOverlaySuppressChanged;
        // Seed from the current state: SuppressChanged only fires on the 0↔1 edge, so a host that
        // loads while a dialog is already open would otherwise miss the active suppression.
        _overlaySuppressed = RdpOverlayCoordinator.IsSuppressed;

        var bounds = ComputeBoundsScreenPx();
        if (bounds.IsDegenerate(minDim: 1)) bounds = HostBounds.Seed;

        // Mark layout active before AttachAsync can show a credentials dialog. SizeChanged
        // events fired while that dialog is open must be allowed to schedule a replay;
        // otherwise the native host can stay at the initial 1x1 seed forever.
        _attached = true;
        try
        {
            await ViewModel.AttachAsync(_ownerHwnd, bounds);
        }
        catch (Exception ex)
        {
            var logger = App.Current.Services.GetService<ILogger<RdpSurfaceHost>>();
            logger?.LogError(ex, "RdpSurfaceHost AttachAsync failed.");
        }
        // Re-check IsLoaded after the await: if the tab was closed while AttachAsync was in
        // flight, OnUnloaded already cleared _attached and we must not flip it back on.
        if (IsLoaded)
        {
            ApplyLayout();
            DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, ApplyLayout);
        }

        // No WinUI focus push on rebind: AttachAsync's rebind branch already issued Win32
        // SetFocus on the OCX HWND, and pushing WinUI Focus(Programmatic) on this
        // UserControl AFTER that can pull keyboard focus off the OCX child. Mirrors the
        // SSH terminal's rebind path, which also relies on the native focus surface alone.
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        // Hide rather than fully tear down — the VM survives navigation. The owned overlay is
        // just hidden via ShowWindow(SW_HIDE), not destroyed.
        ViewModel?.DetachView();
        _attached = false;
        // Reset so the next OnLoaded → cold-connect cycle (or close+reopen) can push WinUI
        // focus once again. Without this reset, a same-instance reload (theoretical;
        // current XAML always creates a new instance per nav) would skip the focus push.
        _focusPushed = false;

        // The session VM survives navigation and is shared across re-mounts of this control.
        // If we leave the PropertyChanged subscription attached, each unload/reload cycle
        // keeps the old host rooted by the VM and stacks duplicate callbacks. ViewModel = null
        // routes through the setter which detaches the handler and drops our reference.
        ViewModel = null;

        if (_trackedXamlRoot is not null)
        {
            _trackedXamlRoot.Changed -= OnXamlRootChanged;
            _trackedXamlRoot = null;
        }

        if (_trackedAppWindow is not null)
        {
            _trackedAppWindow.Changed -= OnOwnerAppWindowChanged;
            _trackedAppWindow = null;
        }

        RdpOverlayCoordinator.SuppressChanged -= OnOverlaySuppressChanged;

        // Stop the timer (no further ticks fire) and drop our reference. The dispatcher
        // releases its pending-tick reference on Stop, so the captured `() => ApplyLayout()`
        // closure becomes GC-eligible along with the UserControl.
        if (_layoutTimer is not null)
        {
            _layoutTimer.Stop();
            _layoutTimer = null;
        }
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        ScheduleLayoutRefresh();
    }

    private void OnXamlRootChanged(XamlRoot sender, XamlRootChangedEventArgs args)
    {
        // RasterizationScale change or window mode flip (windowed ↔ fullscreen). The
        // coalesced ApplyLayout will re-read the scale and re-emit MoveWindow only if the
        // resulting bounds differ from the cached value.
        ScheduleLayoutRefresh();
    }

    private void OnOwnerAppWindowChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (!_attached || ViewModel is null) return;

        // Minimize / restore: an owned overlay is auto-hidden by Windows when the owner
        // minimizes, but the cached _lastBounds in the session adapter would suppress the
        // re-show MoveWindow on restore, so drive Hide/Show explicitly here.
        if (args.DidVisibilityChange)
        {
            if (sender.IsVisible)
            {
                if (!_overlaySuppressed) ViewModel.ResumeSurfaceForOverlay(ComputeBoundsScreenPx());
            }
            else
            {
                ViewModel.SuspendSurfaceForOverlay();
            }
            return;
        }

        // Move / resize / maximize / restore / monitor drag → reposition over the tab.
        if (args.DidPositionChange || args.DidSizeChange || args.DidPresenterChange)
        {
            ScheduleLayoutRefresh();
        }
    }

    private void OnOverlaySuppressChanged(bool suppress)
    {
        _overlaySuppressed = suppress;
        if (!_attached || ViewModel is null) return;
        if (suppress)
        {
            ViewModel.SuspendSurfaceForOverlay();
        }
        else if (_trackedAppWindow is null || _trackedAppWindow.IsVisible)
        {
            // Don't resume while the owner is minimized (a dialog dismissed during minimize) —
            // the AppWindow restore handler re-shows it when the window comes back.
            ViewModel.ResumeSurfaceForOverlay(ComputeBoundsScreenPx());
        }
    }

    private void ScheduleLayoutRefresh()
    {
        if (!_attached || ViewModel is null) return;

        if (_layoutTimer is null)
        {
            _layoutTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
            _layoutTimer.Interval = TimeSpan.FromMilliseconds(LayoutCoalesceMs);
            _layoutTimer.IsRepeating = false;
            _layoutTimer.Tick += (_, _) => ApplyLayout();
        }
        _layoutTimer.Stop();
        _layoutTimer.Start();
    }

    private void ApplyLayout()
    {
        if (!_attached || ViewModel is null) return;
        // A covering dialog owns visibility while suppressed — don't reposition/re-show under it.
        if (_overlaySuppressed) return;
        // While the owner is minimized, ComputeBoundsScreenPx maps to off-screen coords and the
        // SetBounds→EnsureVisibleAndRedraw side effect would (re)show the overlay; skip until the
        // window is restored (the AppWindow visibility handler re-shows it then).
        if (_trackedAppWindow is { IsVisible: false }) return;

        // Per-monitor DPI moves: WinUI 3 updates XamlRoot.RasterizationScale before layout
        // re-runs after a DPI change, so recomputing here picks up the new scale.
        _lastRasterScale = XamlRoot?.RasterizationScale ?? _lastRasterScale;
        var bounds = ComputeBoundsScreenPx();

        // Skip degenerate sizes — during drag-reorder or initial layout the host may report
        // zero. < 8 px is visually pointless and triggers ActiveX layout glitches.
        if (bounds.IsDegenerate()) return;

        // SetBounds on the session adapter caches the last-applied bounds and skips the
        // MoveWindow call when unchanged, so repeated equal ticks are free.
        ViewModel.SetBounds(bounds);
    }

    /// <summary>
    /// Compute host bounds in SCREEN physical pixels. The RDP surface is an owned top-level
    /// window (not a child of the WinUI window), so its position is the main window's client
    /// origin on screen (<see cref="Win32Interop.ClientToScreen"/>) plus this element's offset
    /// within the window content, both in physical pixels.
    /// </summary>
    private HostBounds ComputeBoundsScreenPx()
    {
        if (_ownerWindow?.Content is not UIElement root || ActualWidth <= 0 || ActualHeight <= 0)
        {
            return HostBounds.Empty;
        }

        GeneralTransform transform;
        try
        {
            transform = TransformToVisual(root);
        }
        catch
        {
            return HostBounds.Empty;
        }
        var topLeftDip = transform.TransformPoint(new Point(0, 0));

        var scale = _lastRasterScale > 0 ? _lastRasterScale : 1.0;

        // Offset the element's window-client position by the main window's client origin on
        // screen so the top-level overlay lands over the tab rather than at the screen corner.
        // If the HWND is missing or ClientToScreen fails (invalid/teardown), report Empty so
        // callers skip the move instead of positioning at a bogus origin.
        var origin = new Win32Interop.POINT { x = 0, y = 0 };
        if (_ownerHwnd == IntPtr.Zero || !Win32Interop.ClientToScreen(_ownerHwnd, ref origin))
        {
            return HostBounds.Empty;
        }

        return new HostBounds(
            origin.x + (int)Math.Round(topLeftDip.X * scale),
            origin.y + (int)Math.Round(topLeftDip.Y * scale),
            (int)Math.Round(ActualWidth * scale),
            (int)Math.Round(ActualHeight * scale));
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(RdpSessionViewModel.ReconnectAttempt) ||
            e.PropertyName == nameof(RdpSessionViewModel.IsConnecting))
        {
            UpdateReconnectAttemptText();
        }
        // _focusPushed gate logic:
        //
        // First IsConnected=true transition (cold connect) → push WinUI focus, latch flag.
        // IsConnected=false with Status in {Disconnected, Failed} → user-initiated teardown,
        //   clear the flag so a subsequent Retry/Reconnect re-pushes focus on the next
        //   IsConnected=true. Auto-reconnect's transient Connecting state does NOT match
        //   this branch (Status==Connecting), so it correctly preserves the latch and the
        //   recovery doesn't steal focus from wherever the user moved it.
        //
        // PropertyChanged fires synchronously from the Status setter (via the VM ctor hook)
        // BEFORE OnSessionConnected's TryFocusSession runs, so WinUI Focus runs first and
        // the Win32 SetFocus in the dispatcher closure wins last — landing on the OCX HWND.
        if (e.PropertyName == nameof(RdpSessionViewModel.IsConnected))
        {
            if (ViewModel is { IsConnected: true })
            {
                // Push WinUI focus first so the Win32 SetFocus inside ResumeSurfaceForOverlay
                // (and OnSessionConnected) wins last, landing keyboard focus on the OCX.
                if (!_focusPushed && TryFocusHost())
                {
                    _focusPushed = true;
                }
                // The overlay is a top-level window ABOVE the WinUI content; it was kept hidden
                // during Connecting so the status overlays stayed visible. Show it now at the
                // current bounds — unless a dialog is covering the tab or the owner is minimized
                // (it'll be shown when the dialog closes / the window is restored).
                if (!_overlaySuppressed && (_trackedAppWindow is null || _trackedAppWindow.IsVisible))
                {
                    ViewModel.ResumeSurfaceForOverlay(ComputeBoundsScreenPx());
                }
                DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, ApplyLayout);
            }
            else
            {
                // Not connected (Connecting / auto-reconnecting / Disconnected / Failed): hide the
                // native overlay so it doesn't occlude the WinUI status overlays (spinner+Cancel,
                // error+Retry, Disconnected). No-op when the session is already gone.
                ViewModel?.SuspendSurfaceForOverlay();
                if (ViewModel is { Status: SessionStatus.Disconnected or SessionStatus.Failed })
                {
                    _focusPushed = false;
                }
            }
        }
    }

    /// <summary>
    /// Best-effort WinUI focus push onto this UserControl. Returns <c>true</c> only when
    /// the underlying <see cref="UIElement.Focus"/> reported success — callers (the
    /// _focusPushed latch in particular) rely on this to avoid burning the one-shot when
    /// the focus push couldn't actually run (IsLoaded race, Focus declining the request).
    /// IsLoaded gate avoids focusing a host whose Unloaded raced ahead; the try/catch
    /// keeps a teardown-window throw from escaping the PropertyChanged callback. App.Current
    /// is accessed via <c>?.</c> in case the catch runs during process shutdown when the
    /// App singleton has already been torn down.
    /// </summary>
    private bool TryFocusHost()
    {
        if (!IsLoaded) return false;
        try
        {
            return this.Focus(FocusState.Programmatic);
        }
        catch (Exception ex)
        {
            var logger = App.Current?.Services?.GetService<ILogger<RdpSurfaceHost>>();
            logger?.LogDebug(ex, "RdpSurfaceHost WinUI focus push suppressed.");
            return false;
        }
    }

    private void UpdateReconnectAttemptText()
    {
        var vm = ViewModel;
        if (vm is null || vm.ReconnectAttempt <= 0 || !vm.IsConnecting)
        {
            ReconnectAttemptText.Visibility = Visibility.Collapsed;
            return;
        }
        ReconnectAttemptText.Text = $"Reconnecting… (attempt {vm.ReconnectAttempt})";
        ReconnectAttemptText.Visibility = Visibility.Visible;
    }
}
