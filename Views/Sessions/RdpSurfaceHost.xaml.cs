using System;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Wormhole.Helpers;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Sessions;

/// <summary>
/// Hosts the reparented RDP ActiveX form. The ActiveX HWND lives in the main window's client
/// area as a child window; this control owns the layout slot and drives MoveWindow on every
/// SizeChanged / XamlRoot.Changed (DPI) tick to keep the child positioned over our bounds.
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
    // One-shot per view load: ensures WinUI focus is pushed at most once per
    // RdpSurfaceHost instance, on the first IsConnected=true transition (cold connect).
    // Resets on Unloaded so a fresh view (Sessions↔Settings nav back, or close+reopen)
    // can push focus again. Without this, auto-reconnect cycles (Status: Connected →
    // Connecting → Connected) would re-fire TryFocusHost on every recovery and steal
    // focus from wherever the user moved it during the reconnect banner.
    private bool _focusPushed;

    public RdpSurfaceHost()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        SizeChanged += OnSizeChanged;
        // LayoutUpdated is intentionally NOT subscribed: it fires for every visual tree
        // mutation project-wide, not just for this control. SizeChanged + XamlRoot.Changed
        // (DPI / window resize) catch the geometry shifts we care about; the reparented
        // ActiveX HWND keeps its position relative to the WinUI window client area on its
        // own otherwise.
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

        var bounds = ComputeBoundsPhysicalPx();
        if (bounds.IsDegenerate(minDim: 1)) bounds = HostBounds.Seed;

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
        if (IsLoaded) _attached = true;

        // No WinUI focus push on rebind: AttachAsync's rebind branch already issued Win32
        // SetFocus on the OCX HWND, and pushing WinUI Focus(Programmatic) on this
        // UserControl AFTER that can pull keyboard focus off the OCX child. Mirrors the
        // SSH terminal's rebind path, which also relies on the native focus surface alone.
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        // Hide rather than fully tear down — the VM survives navigation. SetParent-to-null
        // risks losing the ActiveX's internal device context.
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

        // Per-monitor DPI moves: WinUI 3 updates XamlRoot.RasterizationScale before layout
        // re-runs after a DPI change, so recomputing here picks up the new scale.
        _lastRasterScale = XamlRoot?.RasterizationScale ?? _lastRasterScale;
        var bounds = ComputeBoundsPhysicalPx();

        // Skip degenerate sizes — during drag-reorder or initial layout the host may report
        // zero. < 8 px is visually pointless and triggers ActiveX layout glitches.
        if (bounds.IsDegenerate()) return;

        // SetBounds on the session adapter caches the last-applied bounds and skips the
        // MoveWindow call when unchanged, so repeated equal ticks are free.
        ViewModel.SetBounds(bounds);
    }

    /// <summary>Compute host bounds in the owner window's client physical pixels.</summary>
    private HostBounds ComputeBoundsPhysicalPx()
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
        return new HostBounds(
            (int)Math.Round(topLeftDip.X * scale),
            (int)Math.Round(topLeftDip.Y * scale),
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
                if (!_focusPushed && TryFocusHost())
                {
                    _focusPushed = true;
                }
            }
            else if (ViewModel is { Status: SessionStatus.Disconnected or SessionStatus.Failed })
            {
                _focusPushed = false;
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
