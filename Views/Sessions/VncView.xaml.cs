using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using MarcusW.VncClient;
using MarcusW.VncClient.Rendering;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Foundation;
using Windows.System;
using Windows.UI.Core;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions;
using UIDispatcherQueue = Microsoft.UI.Dispatching.DispatcherQueue;
using VncPixelFormat = MarcusW.VncClient.PixelFormat;
using VncScreen = MarcusW.VncClient.Screen;
using VncSize = MarcusW.VncClient.Size;

namespace Wormhole.Views.Sessions;

// CA1001 suppressed deliberately: UserControl has no deterministic dispose hook. The render target
// owns a native framebuffer plus coalesced pooled frame snapshots, both tied to the view instance.
#pragma warning disable CA1001
public sealed partial class VncView : UserControl, ISessionSurfaceActivation
#pragma warning restore CA1001
{
    private VncRenderTarget _renderTarget;
    private readonly Dictionary<VirtualKey, int> _pressedKeySymbols = new();
    private VncSessionViewModel? _viewModel;
    private Window? _ownerWindow;
    private int _framebufferWidth;
    private int _framebufferHeight;
    private int _lastPointerX;
    private int _lastPointerY;
    private bool _hasLastPointer;
    private VncPointerButtons _pressedButtons;
    private bool _sessionSurfaceActive = true;

    public VncView()
    {
        InitializeComponent();
        _renderTarget = new VncRenderTarget(DispatcherQueue);
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        DataContextChanged += OnDataContextChanged;
    }

    public void SetSessionSurfaceActive(bool isActive)
    {
        if (_sessionSurfaceActive == isActive) return;
        _sessionSurfaceActive = isActive;
        FramebufferHost.Visibility = isActive ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        AttachOwnerWindowActivation();
        await AttachCurrentViewModelAsync().ConfigureAwait(true);
        if (!_sessionSurfaceActive)
        {
            SetSessionSurfaceActive(false);
        }
    }

    private async void OnDataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)
    {
        if (!IsLoaded) return;
        await AttachCurrentViewModelAsync().ConfigureAwait(true);
    }

    private async Task AttachCurrentViewModelAsync()
    {
        if (_sessionSurfaceActive)
        {
            FramebufferHost.Visibility = Visibility.Visible;
        }
        var newVm = DataContext as VncSessionViewModel;
        if (newVm is null)
        {
            if (_viewModel is not null)
            {
                await DetachCurrentRenderTargetAsync(replaceRenderTarget: true).ConfigureAwait(true);
                _viewModel = null;
            }
            return;
        }

        if (!ReferenceEquals(newVm, _viewModel))
        {
            await DetachCurrentRenderTargetAsync(replaceRenderTarget: _viewModel is not null).ConfigureAwait(true);
            _viewModel = newVm;
            FramebufferImage.Source = null;
            WaitingFrameText.Visibility = Visibility.Visible;
            _framebufferWidth = 0;
            _framebufferHeight = 0;
            _hasLastPointer = false;
            _pressedButtons = VncPointerButtons.None;
        }

        _renderTarget.SetActive(true);
        _renderTarget.FrameReady -= OnFrameReady;
        _renderTarget.FrameReady += OnFrameReady;

        try
        {
            await newVm.AttachAsync(_renderTarget).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            newVm.ReportFailure(ex.Message);
        }
    }

    private async void OnUnloaded(object sender, RoutedEventArgs e)
    {
        DetachOwnerWindowActivation();
        FramebufferHost.Visibility = Visibility.Collapsed;
        await DetachCurrentRenderTargetAsync(replaceRenderTarget: false).ConfigureAwait(true);
    }

    private async Task DetachCurrentRenderTargetAsync(bool replaceRenderTarget)
    {
        _renderTarget.FrameReady -= OnFrameReady;
        _renderTarget.SetActive(false);
        ReleaseAllPointerCaptures();
        _hasLastPointer = false;
        _pressedButtons = VncPointerButtons.None;
        await ReleasePressedKeysAsync().ConfigureAwait(true);
        if (replaceRenderTarget)
        {
            _renderTarget = new VncRenderTarget(DispatcherQueue);
        }
    }

    private void AttachOwnerWindowActivation()
    {
        var ownerWindow = App.Current?.MainWindow;
        if (ReferenceEquals(_ownerWindow, ownerWindow)) return;

        DetachOwnerWindowActivation();
        _ownerWindow = ownerWindow;
        if (_ownerWindow is not null)
        {
            _ownerWindow.Activated += OnOwnerWindowActivated;
        }
    }

    private void DetachOwnerWindowActivation()
    {
        if (_ownerWindow is null) return;
        _ownerWindow.Activated -= OnOwnerWindowActivated;
        _ownerWindow = null;
    }

    private async void OnOwnerWindowActivated(object sender, Microsoft.UI.Xaml.WindowActivatedEventArgs e)
    {
        if (e.WindowActivationState == Microsoft.UI.Xaml.WindowActivationState.Deactivated)
        {
            await ReleasePressedKeysAsync().ConfigureAwait(true);
        }
    }

    private async void OnLostFocus(object sender, RoutedEventArgs e)
    {
        await ReleasePressedKeysAsync().ConfigureAwait(true);
    }

    private void OnFrameReady(object? sender, VncFrameReadyEventArgs e)
    {
        _framebufferWidth = e.Width;
        _framebufferHeight = e.Height;
        FramebufferImage.Source = e.Bitmap;
        WaitingFrameText.Visibility = Visibility.Collapsed;
    }

    private async void OnPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        Focus(FocusState.Pointer);
        FramebufferHost.CapturePointer(e.Pointer);
        _pressedButtons = ButtonsFromPoint(e.GetCurrentPoint(FramebufferHost));
        await SendPointerFromEventAsync(e, _pressedButtons).ConfigureAwait(true);
    }

    private async void OnPointerReleased(object sender, PointerRoutedEventArgs e)
    {
        var point = e.GetCurrentPoint(FramebufferHost);
        _pressedButtons = ButtonsFromPoint(point);
        await SendPointerAtPointAsync(
            point.Position,
            _pressedButtons,
            useLastPointOnMiss: true).ConfigureAwait(true);
        if (_pressedButtons == VncPointerButtons.None)
        {
            ReleaseAllPointerCaptures();
        }
        e.Handled = true;
    }

    private async void OnPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        await SendPointerFromEventAsync(e, _pressedButtons).ConfigureAwait(true);
    }

    private async void OnPointerWheelChanged(object sender, PointerRoutedEventArgs e)
    {
        var point = e.GetCurrentPoint(FramebufferHost);
        var wheel = point.Properties.MouseWheelDelta >= 0
            ? VncPointerButtons.WheelUp
            : VncPointerButtons.WheelDown;
        if (point.Properties.IsHorizontalMouseWheel)
        {
            wheel = point.Properties.MouseWheelDelta >= 0
                ? VncPointerButtons.WheelRight
                : VncPointerButtons.WheelLeft;
        }

        await SendPointerAtPointAsync(point.Position, _pressedButtons | wheel).ConfigureAwait(true);
        await SendPointerAtPointAsync(point.Position, _pressedButtons).ConfigureAwait(true);
        e.Handled = true;
    }

    private async void OnPointerCanceled(object sender, PointerRoutedEventArgs e)
    {
        await ReleasePointerButtonsAsync(e).ConfigureAwait(true);
    }

    private async void OnPointerCaptureLost(object sender, PointerRoutedEventArgs e)
    {
        await ReleasePointerButtonsAsync(e).ConfigureAwait(true);
    }

    private async void OnPointerExited(object sender, PointerRoutedEventArgs e)
    {
        await SendPointerFromEventAsync(e, _pressedButtons).ConfigureAwait(true);
    }

    private async void OnKeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (!TryMapKey(e.Key, out var keySymbol))
        {
            LogUnsupportedKey(e.Key);
            return;
        }
        e.Handled = true;
        _pressedKeySymbols[e.Key] = keySymbol;
        await SendKeyAsync(isDown: true, keySymbol).ConfigureAwait(true);
    }

    private async void OnKeyUp(object sender, KeyRoutedEventArgs e)
    {
        if (!_pressedKeySymbols.Remove(e.Key, out var keySymbol) && !TryMapKey(e.Key, out keySymbol))
        {
            LogUnsupportedKey(e.Key);
            return;
        }
        e.Handled = true;
        await SendKeyAsync(isDown: false, keySymbol).ConfigureAwait(true);
    }

    private async Task SendPointerFromEventAsync(PointerRoutedEventArgs e, VncPointerButtons buttons)
    {
        var point = e.GetCurrentPoint(FramebufferHost);
        await SendPointerAtPointAsync(point.Position, buttons).ConfigureAwait(true);
        e.Handled = true;
    }

    private async Task SendPointerAtPointAsync(
        Point point,
        VncPointerButtons buttons,
        bool useLastPointOnMiss = false)
    {
        if (_viewModel is null) return;
        if (!TryMapToFramebuffer(point, out var x, out var y))
        {
            if (!useLastPointOnMiss || !_hasLastPointer) return;
            x = _framebufferWidth > 0 ? Math.Clamp(_lastPointerX, 0, _framebufferWidth - 1) : _lastPointerX;
            y = _framebufferHeight > 0 ? Math.Clamp(_lastPointerY, 0, _framebufferHeight - 1) : _lastPointerY;
        }
        else
        {
            _lastPointerX = x;
            _lastPointerY = y;
            _hasLastPointer = true;
        }

        try
        {
            await _viewModel.SendPointerAsync(x, y, buttons).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            LogDebug(ex, "VNC pointer event send failed.");
        }
    }

    private async Task ReleasePointerButtonsAsync(PointerRoutedEventArgs e)
    {
        _pressedButtons = VncPointerButtons.None;
        var point = e.GetCurrentPoint(FramebufferHost);
        await SendPointerAtPointAsync(
            point.Position,
            VncPointerButtons.None,
            useLastPointOnMiss: true).ConfigureAwait(true);
        ReleaseAllPointerCaptures();
        e.Handled = true;
    }

    private async Task SendKeyAsync(bool isDown, int keySymbol)
    {
        if (_viewModel is null) return;
        try
        {
            await _viewModel.SendKeyAsync(isDown, keySymbol).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            LogDebug(ex, "VNC key event send failed.");
        }
    }

    private async Task ReleasePressedKeysAsync()
    {
        if (_pressedKeySymbols.Count == 0) return;
        var keySymbols = new List<int>(_pressedKeySymbols.Values);
        _pressedKeySymbols.Clear();
        foreach (var keySymbol in keySymbols)
        {
            await SendKeyAsync(isDown: false, keySymbol).ConfigureAwait(true);
        }
    }

    private bool TryMapToFramebuffer(Point point, out int x, out int y)
    {
        x = 0;
        y = 0;
        if (_framebufferWidth <= 0 || _framebufferHeight <= 0) return false;
        var hostWidth = FramebufferHost.ActualWidth;
        var hostHeight = FramebufferHost.ActualHeight;
        if (hostWidth <= 0 || hostHeight <= 0) return false;

        var scale = Math.Min(hostWidth / _framebufferWidth, hostHeight / _framebufferHeight);
        if (scale <= 0) return false;
        var displayWidth = _framebufferWidth * scale;
        var displayHeight = _framebufferHeight * scale;
        var left = (hostWidth - displayWidth) / 2;
        var top = (hostHeight - displayHeight) / 2;
        if (point.X < left || point.X > left + displayWidth || point.Y < top || point.Y > top + displayHeight)
        {
            return false;
        }

        x = Math.Clamp((int)((point.X - left) / scale), 0, _framebufferWidth - 1);
        y = Math.Clamp((int)((point.Y - top) / scale), 0, _framebufferHeight - 1);
        return true;
    }

    private static VncPointerButtons ButtonsFromPoint(PointerPoint point)
    {
        var props = point.Properties;
        var buttons = VncPointerButtons.None;
        if (props.IsLeftButtonPressed) buttons |= VncPointerButtons.Left;
        if (props.IsMiddleButtonPressed) buttons |= VncPointerButtons.Middle;
        if (props.IsRightButtonPressed) buttons |= VncPointerButtons.Right;
        return buttons;
    }

    private void ReleaseAllPointerCaptures()
    {
        try { FramebufferHost.ReleasePointerCaptures(); }
        catch (Exception ex) { LogDebug(ex, "VNC pointer capture release failed."); }
    }

    private static bool TryMapKey(VirtualKey key, out int keySymbol)
    {
        var shift = IsKeyDown(VirtualKey.Shift);
        if (key is >= VirtualKey.A and <= VirtualKey.Z)
        {
            var offset = key - VirtualKey.A;
            keySymbol = (shift ? 'A' : 'a') + (int)offset;
            return true;
        }

        if (key is >= VirtualKey.Number0 and <= VirtualKey.Number9)
        {
            const string shiftedDigits = ")!@#$%^&*(";
            var offset = (int)(key - VirtualKey.Number0);
            keySymbol = shift ? shiftedDigits[offset] : '0' + offset;
            return true;
        }

        if (key is >= VirtualKey.NumberPad0 and <= VirtualKey.NumberPad9)
        {
            keySymbol = '0' + (int)(key - VirtualKey.NumberPad0);
            return true;
        }

        if (TryMapOemKey((int)key, shift, out keySymbol))
        {
            return true;
        }

        keySymbol = key switch
        {
            VirtualKey.Space => (int)KeySymbol.space,
            VirtualKey.Back => (int)KeySymbol.BackSpace,
            VirtualKey.Tab => (int)KeySymbol.Tab,
            VirtualKey.Enter => (int)KeySymbol.Return,
            VirtualKey.Escape => (int)KeySymbol.Escape,
            VirtualKey.Delete => (int)KeySymbol.Delete,
            VirtualKey.Home => (int)KeySymbol.Home,
            VirtualKey.End => (int)KeySymbol.End,
            VirtualKey.PageUp => (int)KeySymbol.Page_Up,
            VirtualKey.PageDown => (int)KeySymbol.Page_Down,
            VirtualKey.Left => (int)KeySymbol.Left,
            VirtualKey.Right => (int)KeySymbol.Right,
            VirtualKey.Up => (int)KeySymbol.Up,
            VirtualKey.Down => (int)KeySymbol.Down,
            VirtualKey.Insert => (int)KeySymbol.Insert,
            VirtualKey.Shift => (int)KeySymbol.Shift_L,
            VirtualKey.Control => (int)KeySymbol.Control_L,
            VirtualKey.Menu => (int)KeySymbol.Alt_L,
            VirtualKey.F1 => (int)KeySymbol.F1,
            VirtualKey.F2 => (int)KeySymbol.F2,
            VirtualKey.F3 => (int)KeySymbol.F3,
            VirtualKey.F4 => (int)KeySymbol.F4,
            VirtualKey.F5 => (int)KeySymbol.F5,
            VirtualKey.F6 => (int)KeySymbol.F6,
            VirtualKey.F7 => (int)KeySymbol.F7,
            VirtualKey.F8 => (int)KeySymbol.F8,
            VirtualKey.F9 => (int)KeySymbol.F9,
            VirtualKey.F10 => (int)KeySymbol.F10,
            VirtualKey.F11 => (int)KeySymbol.F11,
            VirtualKey.F12 => (int)KeySymbol.F12,
            VirtualKey.Add => (int)KeySymbol.plus,
            VirtualKey.Subtract => (int)KeySymbol.minus,
            VirtualKey.Multiply => (int)KeySymbol.asterisk,
            VirtualKey.Divide => (int)KeySymbol.slash,
            VirtualKey.Decimal => (int)KeySymbol.period,
            _ => 0,
        };
        return keySymbol != 0;
    }

    private static bool TryMapOemKey(int virtualKey, bool shift, out int keySymbol)
    {
        keySymbol = virtualKey switch
        {
            186 => shift ? ':' : ';',
            187 => shift ? '+' : '=',
            188 => shift ? '<' : ',',
            189 => shift ? '_' : '-',
            190 => shift ? '>' : '.',
            191 => shift ? '?' : '/',
            192 => shift ? '~' : '`',
            219 => shift ? '{' : '[',
            220 => shift ? '|' : '\\',
            221 => shift ? '}' : ']',
            222 => shift ? '"' : '\'',
            _ => 0,
        };
        return keySymbol != 0;
    }

    private static bool IsKeyDown(VirtualKey key)
    {
        try
        {
            return InputKeyboardSource.GetKeyStateForCurrentThread(key).HasFlag(CoreVirtualKeyStates.Down);
        }
        catch
        {
            return false;
        }
    }

    private static void LogDebug(Exception ex, string message) =>
        App.Current?.Services?.GetService<ILogger<VncView>>()?.LogDebug(ex, "{Message}", message);

    private static void LogUnsupportedKey(VirtualKey key) =>
        App.Current?.Services?.GetService<ILogger<VncView>>()?.LogDebug(
            "Ignoring unsupported VNC key {Key}.", key);

    private sealed class VncRenderTarget : IVncRenderTarget, IDisposable
    {
        private static readonly VncPixelFormat Bgra32 = new(
            "BGRA32",
            bitsPerPixel: 32,
            depth: 32,
            bigEndian: false,
            trueColor: true,
            hasAlpha: true,
            redMax: 255,
            greenMax: 255,
            blueMax: 255,
            alphaMax: 255,
            redShift: 16,
            greenShift: 8,
            blueShift: 0,
            alphaShift: 24);

        private readonly UIDispatcherQueue _dispatcher;
        private readonly object _gate = new();
        private byte[]? _pendingPixels;
        private int _pendingLength;
        private int _pendingWidth;
        private int _pendingHeight;
        private bool _snapshotInProgress;
        private bool _snapshotDirty;
        private NativeFramebuffer? _framebuffer;
        private WriteableBitmap? _bitmap;
        private int _publishQueued;
        private bool _active = true;
        private bool _disposed;

        public VncRenderTarget(UIDispatcherQueue dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public event EventHandler<VncFrameReadyEventArgs>? FrameReady;

        public IFramebufferReference GrabFramebufferReference(VncSize size, IImmutableSet<VncScreen> layout)
        {
            var framebuffer = RentFramebuffer(size);
            return new FramebufferReference(this, framebuffer, size);
        }

        public void SetActive(bool active)
        {
            byte[]? pending = null;
            lock (_gate)
            {
                if (_disposed || _active == active) return;
                _active = active;
                if (!active)
                {
                    pending = _pendingPixels;
                    _pendingPixels = null;
                    _pendingLength = 0;
                    _pendingWidth = 0;
                    _pendingHeight = 0;
                    _snapshotDirty = false;
                }
            }

            ReturnPending(pending);
            if (!active)
            {
                _bitmap = null;
            }
            if (active)
            {
                QueueCurrentFramebufferSnapshot();
            }
        }

        public void Dispose()
        {
            NativeFramebuffer? framebufferToFree = null;
            byte[]? pending = null;
            lock (_gate)
            {
                if (_disposed) return;

                _disposed = true;
                pending = _pendingPixels;
                _pendingPixels = null;
                _pendingLength = 0;
                _pendingWidth = 0;
                _pendingHeight = 0;
                _snapshotDirty = false;

                framebufferToFree = _framebuffer;
                _framebuffer = null;
                if (framebufferToFree is { RefCount: > 0 })
                {
                    framebufferToFree.ReleaseWhenIdle = true;
                    framebufferToFree = null;
                }
            }

            ReturnPending(pending);
            _bitmap = null;
            framebufferToFree?.Free();
        }

        private NativeFramebuffer RentFramebuffer(VncSize size)
        {
            var length = checked(size.Width * size.Height * Bgra32.BytesPerPixel);
            NativeFramebuffer? framebufferToFree = null;
            NativeFramebuffer framebuffer;
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);

                framebuffer = _framebuffer is { } current &&
                    current.Length == length &&
                    current.Width == size.Width &&
                    current.Height == size.Height
                        ? current
                        : CreateReplacementFramebuffer(size, length, out framebufferToFree);
                framebuffer.RefCount++;
            }

            framebufferToFree?.Free();
            return framebuffer;
        }

        private NativeFramebuffer CreateReplacementFramebuffer(
            VncSize size,
            int length,
            out NativeFramebuffer? framebufferToFree)
        {
            framebufferToFree = null;
            if (_framebuffer is { } old)
            {
                if (old.RefCount == 0)
                {
                    framebufferToFree = old;
                }
                else
                {
                    old.ReleaseWhenIdle = true;
                }
            }

            var replacement = new NativeFramebuffer(size.Width, size.Height, length);
            ClearNativeBuffer(replacement.Address, replacement.Length);
            _framebuffer = replacement;
            return replacement;
        }

        private void ReleaseReference(NativeFramebuffer framebuffer)
        {
            NativeFramebuffer? framebufferToFree = null;
            lock (_gate)
            {
                framebuffer.RefCount--;
                if (framebuffer.RefCount == 0 && framebuffer.ReleaseWhenIdle)
                {
                    framebufferToFree = framebuffer;
                }
            }

            framebufferToFree?.Free();
        }

        private static void ClearNativeBuffer(IntPtr address, int length)
        {
            var zeroes = ArrayPool<byte>.Shared.Rent(length);
            try
            {
                Array.Clear(zeroes, 0, length);
                Marshal.Copy(zeroes, 0, address, length);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(zeroes);
            }
        }

        private void Present(VncSize size, IntPtr address, int length)
        {
            if (length <= 0) return;
            lock (_gate)
            {
                if (_disposed || !_active) return;
            }

            QueueFrameSnapshot(size.Width, size.Height, address, length);
        }

        private void QueueCurrentFramebufferSnapshot()
        {
            NativeFramebuffer framebuffer;
            lock (_gate)
            {
                if (_disposed || !_active || _framebuffer is null || _framebuffer.Address == IntPtr.Zero) return;
                framebuffer = _framebuffer;
                framebuffer.RefCount++;
            }

            try
            {
                QueueFrameSnapshot(framebuffer.Width, framebuffer.Height, framebuffer.Address, framebuffer.Length);
            }
            finally
            {
                ReleaseReference(framebuffer);
            }
        }

        private void QueueFrameSnapshot(int width, int height, IntPtr address, int length)
        {
            if (!TryBeginFrameSnapshot()) return;

            var pixels = ArrayPool<byte>.Shared.Rent(length);
            var committed = false;
            var snapshotEnded = false;
            try
            {
                Marshal.Copy(address, pixels, 0, length);
                for (var i = 3; i < length; i += 4)
                {
                    pixels[i] = 0xFF;
                }

                committed = TryCommitFrameSnapshot(width, height, length, pixels);
                snapshotEnded = true;
            }
            finally
            {
                if (!snapshotEnded)
                {
                    EndFrameSnapshot();
                }
                if (!committed)
                {
                    ReturnPending(pixels);
                }
            }

            if (committed)
            {
                QueuePublish();
            }
        }

        private bool TryBeginFrameSnapshot()
        {
            lock (_gate)
            {
                if (_disposed || !_active) return false;
                if (_snapshotInProgress || _pendingPixels is not null)
                {
                    _snapshotDirty = true;
                    return false;
                }

                _snapshotInProgress = true;
                return true;
            }
        }

        private void EndFrameSnapshot()
        {
            lock (_gate)
            {
                _snapshotInProgress = false;
            }
        }

        private bool TryCommitFrameSnapshot(int width, int height, int length, byte[] pixels)
        {
            byte[]? previous = null;
            var committed = false;
            lock (_gate)
            {
                _snapshotInProgress = false;
                if (!_disposed && _active)
                {
                    previous = _pendingPixels;
                    _pendingPixels = pixels;
                    _pendingLength = length;
                    _pendingWidth = width;
                    _pendingHeight = height;
                    committed = true;
                }
            }

            ReturnPending(previous);
            return committed;
        }

        private void QueuePublish()
        {
            if (Interlocked.Exchange(ref _publishQueued, 1) != 0) return;
            if (!_dispatcher.TryEnqueue(PublishPending))
            {
                Interlocked.Exchange(ref _publishQueued, 0);
                DropPending();
            }
        }

        private void PublishPending()
        {
            byte[]? pixels;
            int length;
            int width;
            int height;
            bool queueDirtySnapshot;
            lock (_gate)
            {
                pixels = _pendingPixels;
                length = _pendingLength;
                width = _pendingWidth;
                height = _pendingHeight;
                queueDirtySnapshot = _snapshotDirty;
                _pendingPixels = null;
                _pendingLength = 0;
                _pendingWidth = 0;
                _pendingHeight = 0;
                _snapshotDirty = false;
            }
            Interlocked.Exchange(ref _publishQueued, 0);

            try
            {
                if (_disposed || !_active || pixels is null || width <= 0 || height <= 0)
                {
                    return;
                }

                var bitmap = GetOrCreateBitmap(width, height);
                using (var stream = bitmap.PixelBuffer.AsStream())
                {
                    stream.Write(pixels, 0, length);
                }
                bitmap.Invalidate();
                FrameReady?.Invoke(this, new VncFrameReadyEventArgs(bitmap, width, height));
            }
            finally
            {
                ReturnPending(pixels);

                if (!_disposed && _active)
                {
                    if (queueDirtySnapshot)
                    {
                        QueueCurrentFramebufferSnapshot();
                    }

                    if (HasPendingFrame())
                    {
                        QueuePublish();
                    }
                }
            }
        }

        private WriteableBitmap GetOrCreateBitmap(int width, int height)
        {
            if (_bitmap is null || _bitmap.PixelWidth != width || _bitmap.PixelHeight != height)
            {
                _bitmap = new WriteableBitmap(width, height);
            }

            return _bitmap;
        }

        private bool HasPendingFrame()
        {
            lock (_gate)
            {
                return _pendingPixels is not null;
            }
        }

        private void DropPending()
        {
            byte[]? pending = null;
            lock (_gate)
            {
                pending = _pendingPixels;
                _pendingPixels = null;
                _pendingLength = 0;
                _snapshotDirty = false;
            }
            ReturnPending(pending);
        }

        private static void ReturnPending(byte[]? pending)
        {
            if (pending is not null)
            {
                ArrayPool<byte>.Shared.Return(pending);
            }
        }

        private sealed class NativeFramebuffer
        {
            public NativeFramebuffer(int width, int height, int length)
            {
                Width = width;
                Height = height;
                Length = length;
                Address = Marshal.AllocHGlobal(length);
            }

            public int Width { get; }
            public int Height { get; }
            public int Length { get; }
            public IntPtr Address { get; private set; }
            public int RefCount { get; set; }
            public bool ReleaseWhenIdle { get; set; }

            public void Free()
            {
                if (Address == IntPtr.Zero) return;
                Marshal.FreeHGlobal(Address);
                Address = IntPtr.Zero;
            }
        }

        private sealed class FramebufferReference : IFramebufferReference
        {
            private readonly VncRenderTarget _owner;
            private readonly NativeFramebuffer _framebuffer;
            private readonly int _length;
            private bool _disposed;

            public FramebufferReference(VncRenderTarget owner, NativeFramebuffer framebuffer, VncSize size)
            {
                _owner = owner;
                _framebuffer = framebuffer;
                Size = size;
                _length = framebuffer.Length;
                Address = framebuffer.Address;
            }

            public IntPtr Address { get; }
            public VncSize Size { get; }
            public VncPixelFormat Format => Bgra32;
            public double HorizontalDpi => 96;
            public double VerticalDpi => 96;

            public void Dispose()
            {
                if (_disposed) return;
                _disposed = true;
                try
                {
                    _owner.Present(Size, Address, _length);
                }
                finally
                {
                    _owner.ReleaseReference(_framebuffer);
                }
            }
        }
    }

    private sealed record VncFrameReadyEventArgs(WriteableBitmap Bitmap, int Width, int Height);
}
