using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
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
    // The overlay window tracks the tab on every 16ms layout tick (LayoutCoalesceMs), but the
    // REMOTE desktop resolution must only be renegotiated at the END of a resize gesture: each
    // UpdateSessionDisplaySettings triggers a server-side display-mode change, so firing it per
    // frame during a drag would flood the Display Control channel and flicker. This longer
    // trailing debounce coalesces a drag/maximize burst into a single renegotiation.
    private const double ResolutionDebounceMs = 250;

    private RdpSessionViewModel? _viewModel;
    private DispatcherQueueTimer? _layoutTimer;
    // Separate trailing-edge timer for the remote-resolution renegotiation (see ResolutionDebounceMs).
    // Distinct from _layoutTimer so the per-frame overlay-move cadence is never slowed.
    private DispatcherQueueTimer? _resolutionTimer;
    // Last surface size (physical px) we asked the OCX to renegotiate to. Guards against re-sending
    // on pure window moves (size unchanged) and against the 1x1 activation seed. Reset to 0 on the
    // Connected transition so a cold connect / in-place auto-reconnect always re-negotiates once.
    private int _lastNegotiatedWidthPx;
    private int _lastNegotiatedHeightPx;
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

    // Native subclass on the owner window so window MOVES reposition the overlay synchronously
    // inside the WM_WINDOWPOSCHANGED message — the managed AppWindow.Changed + 16ms timer path
    // lags a frame or more behind the OS-composited window during a drag, making the overlay
    // look detached. _subclassProc is the GC root for the marshaled callback and MUST stay a
    // field for the subclass lifetime. Each RdpSurfaceHost uses a distinct _subclassId so several
    // RDP tabs can subclass the shared main window without colliding.
    private static int _subclassIdSeq;
    private Win32Interop.SubclassProc? _subclassProc; // non-null exactly while the subclass is installed
    private UIntPtr _subclassId;
    // Element-relative geometry (physical px) from the last non-degenerate ComputeBoundsScreenPx,
    // consumed by the synchronous move path so it never has to touch a WinUI layout API (which is
    // unsafe to re-enter mid-WndProc and reports stale values during a resize). Only the screen
    // origin is recomputed in the hook via ClientToScreen.
    private int _cachedOffsetX, _cachedOffsetY, _cachedWidthPx, _cachedHeightPx;
    private bool _cacheValid;
    // Last window client size seen via WM_WINDOWPOSCHANGED, to tell a move from a resize: a resize
    // changes the element size too, which the cache can't know synchronously, so it defers to the
    // async SizeChanged/timer path that recomputes after WinUI re-measures.
    private int _lastWindowCx, _lastWindowCy;

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

        // Subclass the owner window so a drag/shake repositions the overlay synchronously in the
        // same WM_WINDOWPOSCHANGED message instead of trailing behind via AppWindow.Changed.
        if (_subclassProc is null && _ownerHwnd != IntPtr.Zero)
        {
            _subclassProc = OwnerSubclassProc; // root the delegate before handing it to native code
            _subclassId = (UIntPtr)(uint)Interlocked.Increment(ref _subclassIdSeq);
            if (!Win32Interop.SetWindowSubclass(_ownerHwnd, _subclassProc, _subclassId, UIntPtr.Zero))
            {
                _subclassProc = null; // install failed — don't keep a thunk rooted for a subclass that isn't live
            }
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

        // Detach the owner subclass before dropping the delegate root. The main window outlives
        // the tab, so the HWND is still valid here.
        if (_subclassProc is not null && _ownerHwnd != IntPtr.Zero)
        {
            Win32Interop.RemoveWindowSubclass(_ownerHwnd, _subclassProc, _subclassId);
        }
        _subclassProc = null;
        _cacheValid = false;

        RdpOverlayCoordinator.SuppressChanged -= OnOverlaySuppressChanged;

        // Stop the timer (no further ticks fire) and drop our reference. The dispatcher
        // releases its pending-tick reference on Stop, so the captured `() => ApplyLayout()`
        // closure becomes GC-eligible along with the UserControl.
        if (_layoutTimer is not null)
        {
            _layoutTimer.Stop();
            _layoutTimer = null;
        }

        // Same teardown for the resolution-debounce timer so a pending tick can't fire
        // UpdateRemoteResolution into a detached VM after Unloaded.
        if (_resolutionTimer is not null)
        {
            _resolutionTimer.Stop();
            _resolutionTimer = null;
        }
        _lastNegotiatedWidthPx = 0;
        _lastNegotiatedHeightPx = 0;
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
                if (!_overlaySuppressed)
                {
                    ViewModel.ResumeSurfaceForOverlay(ComputeBoundsScreenPx());
                    // ApplyLayout was suppressed while hidden, so a size change that happened
                    // off-screen (e.g. a monitor/DPI reconfig) never scheduled a renegotiation —
                    // do it now that the cache is fresh. ApplyResolution dedups, so it's a no-op
                    // when the size is unchanged.
                    ScheduleResolutionRefresh();
                }
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
            // The window can be resized while a modal dialog covers the tab (window chrome stays
            // interactive). ApplyLayout no-ops while suppressed, so the resolution would stay stale
            // until the next unrelated layout tick — renegotiate now that the dialog is gone and
            // the cache is refreshed. ApplyResolution dedups, so an unchanged size is a no-op.
            ScheduleResolutionRefresh();
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
        // While the owner is minimized, ComputeBoundsScreenPx maps to off-screen coords; skip until
        // the window is restored (the AppWindow visibility handler re-shows it then).
        if (_trackedAppWindow is { IsVisible: false }) return;

        // ComputeBoundsScreenPx refreshes _lastRasterScale from the live XamlRoot, so per-monitor
        // DPI moves are picked up here without a separate scale read.
        var bounds = ComputeBoundsScreenPx();

        // Skip degenerate sizes — during drag-reorder or initial layout the host may report
        // zero. < 8 px is visually pointless and triggers ActiveX layout glitches.
        if (bounds.IsDegenerate()) return;

        // SetBounds on the session adapter caches the last-applied bounds and skips the
        // MoveWindow call when unchanged, so repeated equal ticks are free.
        ViewModel.SetBounds(bounds);

        // Renegotiate the remote desktop resolution to match the new surface — debounced to the
        // end of the resize so a drag doesn't flood the Display Control channel. The per-tick
        // overlay move above is untouched; only the (rare) resolution change is deferred.
        // ApplyResolution dedups on size, so this is a no-op for pure window moves.
        ScheduleResolutionRefresh();
    }

    private void ScheduleResolutionRefresh()
    {
        if (!_attached || ViewModel is null) return;

        if (_resolutionTimer is null)
        {
            _resolutionTimer = DispatcherQueue.GetForCurrentThread().CreateTimer();
            _resolutionTimer.Interval = TimeSpan.FromMilliseconds(ResolutionDebounceMs);
            _resolutionTimer.IsRepeating = false;
            _resolutionTimer.Tick += (_, _) => ApplyResolution();
        }
        _resolutionTimer.Stop();
        _resolutionTimer.Start();
    }

    private void ApplyResolution()
    {
        // Mirror ApplyLayout's guards — the 250ms debounce is long enough for the overlay to be
        // suppressed by a dialog, minimized, or torn down between scheduling and firing.
        if (!_attached || ViewModel is null) return;
        if (_overlaySuppressed) return;
        if (_trackedAppWindow is { IsVisible: false }) return;
        // Use the physical-px element size cached by the last non-degenerate ComputeBoundsScreenPx;
        // without a valid cache there is no real size to negotiate.
        if (!_cacheValid) return;

        var widthPx = _cachedWidthPx;
        var heightPx = _cachedHeightPx;
        if (widthPx < 1 || heightPx < 1) return;

        // Renegotiate only on an actual size change. Pure moves (new origin, same size) and the
        // 1x1 activation seed must never trigger a server-side display-mode change.
        if (widthPx == _lastNegotiatedWidthPx && heightPx == _lastNegotiatedHeightPx) return;
        _lastNegotiatedWidthPx = widthPx;
        _lastNegotiatedHeightPx = heightPx;

        // Non-fatal in the VM: a server without dynamic-resolution support keeps SmartSizing scaling.
        ViewModel.UpdateRemoteResolution(widthPx, heightPx);
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

        // Refresh the cached DPI scale from the live XamlRoot here (not only in ApplyLayout) so
        // every caller — including resume-from-minimize, dialog-close, and reconnect, which don't
        // refresh it themselves — composes bounds and populates the geometry cache below with the
        // CURRENT scale. Safe: ComputeBoundsScreenPx only runs on the UI thread, never from the
        // native WM_WINDOWPOSCHANGED callback (which reuses the cache instead of recomputing).
        _lastRasterScale = XamlRoot?.RasterizationScale ?? _lastRasterScale;
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

        var offsetX = (int)Math.Round(topLeftDip.X * scale);
        var offsetY = (int)Math.Round(topLeftDip.Y * scale);
        var widthPx = (int)Math.Round(ActualWidth * scale);
        var heightPx = (int)Math.Round(ActualHeight * scale);

        var bounds = new HostBounds(origin.x + offsetX, origin.y + offsetY, widthPx, heightPx);

        // Cache the element-relative pieces so the synchronous WM_WINDOWPOSCHANGED move path can
        // re-derive screen bounds from just a fresh ClientToScreen, without a WinUI layout call.
        // Only cache real geometry — a degenerate result would otherwise poison the fast path.
        if (!bounds.IsDegenerate())
        {
            _cachedOffsetX = offsetX;
            _cachedOffsetY = offsetY;
            _cachedWidthPx = widthPx;
            _cachedHeightPx = heightPx;
            _cacheValid = true;
        }

        return bounds;
    }

    /// <summary>
    /// Subclass procedure on the owner window. Chains to <see cref="Win32Interop.DefSubclassProc"/>
    /// FIRST so the window's new rect is final, then — for a pure move — repositions the overlay
    /// synchronously so it tracks the window in the same frame instead of trailing the async
    /// AppWindow.Changed path. Must never let an exception escape into the native caller.
    /// </summary>
    private IntPtr OwnerSubclassProc(
        IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam, UIntPtr id, UIntPtr data)
    {
        var result = Win32Interop.DefSubclassProc(hWnd, uMsg, wParam, lParam);

        if (uMsg == Win32Interop.WM_WINDOWPOSCHANGED)
        {
            try
            {
                RepositionOverlaySynchronously(lParam);
            }
            catch (Exception ex)
            {
                var logger = App.Current?.Services?.GetService<ILogger<RdpSurfaceHost>>();
                logger?.LogDebug(ex, "RDP overlay synchronous reposition failed.");
            }
        }

        return result;
    }

    private void RepositionOverlaySynchronously(IntPtr lParamWindowPos)
    {
        // Mirror ApplyLayout's guards: a covering dialog or a minimized owner owns visibility, and
        // we need a real geometry cache to derive bounds without a WinUI layout call.
        if (!_attached || _viewModel is null || _overlaySuppressed || !_cacheValid) return;
        if (_trackedAppWindow is { IsVisible: false }) return;

        var wp = Marshal.PtrToStructure<Win32Interop.WINDOWPOS>(lParamWindowPos);

        // Resize → the element size (and thus the cached offset) is about to change, but WinUI
        // re-measures asynchronously so we can't know the new geometry here. Update the size
        // tracker and defer to the SizeChanged/timer path that recomputes after the relayout.
        var sizeChanged = (wp.flags & Win32Interop.SWP_NOSIZE) == 0 &&
                          (wp.cx != _lastWindowCx || wp.cy != _lastWindowCy);
        _lastWindowCx = wp.cx;
        _lastWindowCy = wp.cy;
        if (sizeChanged) return;

        // Pure move: only the screen origin changed. Re-derive it from the owner's client origin
        // plus the cached element offset (both physical px). No WinUI layout API is touched.
        var origin = new Win32Interop.POINT { x = 0, y = 0 };
        if (_ownerHwnd == IntPtr.Zero || !Win32Interop.ClientToScreen(_ownerHwnd, ref origin)) return;

        var bounds = new HostBounds(
            origin.x + _cachedOffsetX,
            origin.y + _cachedOffsetY,
            _cachedWidthPx,
            _cachedHeightPx);
        if (bounds.IsDegenerate()) return;

        // SetBounds is gated on Status==Connected in the VM and dedupes equal bounds in the
        // adapter, so a trailing async tick that computes the same value becomes a no-op.
        _viewModel.SetBounds(bounds);
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
                // Force the next resolution tick to renegotiate. A cold connect may have happened
                // after the window was resized during the spinner (so the OCX's connect-time
                // resolution is already stale), and an in-place auto-reconnect re-establishes the
                // OCX at its ORIGINAL connect-time resolution — both leave _lastNegotiated stale.
                // The ApplyLayout enqueued below reschedules ApplyResolution, which now fires.
                _lastNegotiatedWidthPx = 0;
                _lastNegotiatedHeightPx = 0;

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
