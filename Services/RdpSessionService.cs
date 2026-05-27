using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Interop.Rdp;
using Wormhole.Models;

namespace Wormhole.Services;

public sealed class RdpSessionService : IRdpSessionService
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<RdpSessionService> _logger;

    public RdpSessionService(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<RdpSessionService>();
    }

    public Task<IRdpSession> ConnectAsync(
        ConnectionProfile profile,
        string? password,
        IntPtr ownerHwnd,
        string? gatewayUsername = null,
        string? gatewayPassword = null,
        Action<IRdpSession>? onSessionReady = null,
        CancellationToken cancellationToken = default)
    {
        // Must run on the WinUI UI thread (STA). The form constructor enforces this.
        if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
        {
            throw new InvalidOperationException("RdpSessionService.ConnectAsync must be invoked on the STA UI thread.");
        }
        cancellationToken.ThrowIfCancellationRequested();

        var form = new RdpHostForm(_loggerFactory.CreateLogger<RdpHostForm>());
        try
        {
            _ = form.Hwnd; // force handle creation + AxHost CreateControl before Configure / SetParent
            form.Configure(profile, password, gatewayUsername, gatewayPassword, ownerHwnd);
            cancellationToken.ThrowIfCancellationRequested();

            // WinForms creates a top-level Form with WS_POPUP. SetParent alone leaves that bit
            // set, which produces a popup hosted inside another window: focus, clipping, and
            // Alt-Tab all misbehave. Switch the style to WS_CHILD before reparenting — this is
            // the canonical Win32 recipe for embedding a foreign HWND into a host window.
            var style = Win32Interop.GetWindowLong(form.Hwnd, Win32Interop.GWL_STYLE);
            var childStyle = (style & ~Win32Interop.WS_POPUP) | Win32Interop.WS_CHILD;
            if (childStyle != style)
            {
                _ = Win32Interop.SetWindowLong(form.Hwnd, Win32Interop.GWL_STYLE, childStyle);
            }

            // SetParent returns the previous parent on success, NULL on failure — but it can
            // also return NULL on SUCCESS when the window had no previous parent (which is
            // the normal case for a top-level WinForms Form). The only reliable way to
            // disambiguate is to clear the last error before the call and consult it only
            // when the return is NULL: nonzero error means real failure.
            Marshal.SetLastSystemError(0);
            var oldParent = Win32Interop.SetParent(form.Hwnd, ownerHwnd);
            if (oldParent == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                if (err != 0)
                {
                    throw new InvalidOperationException(
                        $"SetParent failed reparenting the RDP host onto the WinUI main window (Win32 error {err}).");
                }
            }
            cancellationToken.ThrowIfCancellationRequested();

            // Construct the adapter BEFORE Start() and let the caller subscribe via
            // onSessionReady — both legs together close the early-event race. Adapter-then-VM
            // subscriptions are fully wired by the time ocx.Connect() runs synchronously
            // inside form.Start(); an immediate auth reject or transport failure right after
            // Connect therefore reaches the VM and produces a terminal transition.
            var adapter = new RdpSessionAdapter(form, _logger);
            onSessionReady?.Invoke(adapter);
            form.Start();

            _logger.LogInformation("RDP session opened to {Host}:{Port}.", profile.Host, profile.Port);
            return Task.FromResult<IRdpSession>(adapter);
        }
        catch
        {
            try { form.Dispose(); }
            catch (Exception disposeEx)
            {
                _logger.LogWarning(disposeEx, "RDP host form Dispose failed during cleanup of a failed Connect.");
            }
            throw;
        }
    }

    /// <summary>
    /// Thin wrapper that adapts <see cref="RdpHostForm"/> events to the <see cref="IRdpSession"/>
    /// surface and translates disconnect codes into <see cref="RdpDisconnectInfo"/>. Skips the
    /// MoveWindow call when bounds haven't changed since the last apply — the surface host
    /// drives SetBounds every layout tick (60Hz during a window drag) and the OCX is sensitive
    /// to spurious WM_PAINT.
    /// </summary>
    private sealed class RdpSessionAdapter : IRdpSession
    {
        private readonly RdpHostForm _form;
        private readonly ILogger _logger;
        private bool _loggedOn;
        private HostBounds _lastBounds = HostBounds.Empty;
        // One-shot per adapter: emits the diagnostic on the first SetBounds that is NOT the
        // (0,0,1,1) Seed placeholder. The cold-connect and Retry paths both seed with Seed
        // before real layout arrives (RdpSessionViewModel.cs:222, :411), so gating on Empty
        // alone would always record the useless 1×1 placeholder and never the real geometry.
        private bool _firstRealBoundsLogged;

        public RdpSessionAdapter(RdpHostForm form, ILogger logger)
        {
            _form = form;
            _logger = logger;
            _form.Connected += () =>
            {
                _loggedOn = true;
                Connected?.Invoke(this, EventArgs.Empty);
            };
            _form.Disconnected += code =>
            {
                _loggedOn = false;
                var (extended, desc) = _form.GetDisconnectInfo(code);
                // Reason codes 0-3 are clean (user-initiated, server-initiated, idle, etc.)
                // per the IMsTscAxEvents.OnDisconnected reference table. Everything else is
                // a fault that should surface the failure overlay.
                var clean = code is >= 0 and <= 3;
                Disconnected?.Invoke(this, new RdpDisconnectInfo(code, extended, desc, clean));
            };
            _form.FatalError += code => FatalError?.Invoke(this, code);
            _form.LogonError += code => LogonError?.Invoke(this, code);
            _form.AutoReconnecting2 += (reason, available, attempt, max) =>
                AutoReconnecting?.Invoke(this, new RdpReconnectInfo(attempt, max, reason));
            _form.AutoReconnected += () =>
            {
                _loggedOn = true;
                AutoReconnected?.Invoke(this, EventArgs.Empty);
            };
        }

        public IntPtr Hwnd => _form.Hwnd;
        public bool IsLoggedOn => _loggedOn;

        public event EventHandler? Connected;
        public event EventHandler<RdpDisconnectInfo>? Disconnected;
        public event EventHandler<int>? FatalError;
        public event EventHandler<int>? LogonError;
        public event EventHandler<RdpReconnectInfo>? AutoReconnecting;
        public event EventHandler? AutoReconnected;

        public void SetBounds(HostBounds bounds)
        {
            if (bounds.Width < 1 || bounds.Height < 1) return;
            if (bounds == _lastBounds) return;
            _lastBounds = bounds;
            Win32Interop.MoveWindow(_form.Hwnd, bounds.X, bounds.Y, bounds.Width, bounds.Height, bRepaint: true);
            // Diagnostic: log once per adapter the FIRST real bounds (skipping the (0,0,1,1)
            // Seed placeholder the VM uses before real layout arrives). Set the flag after a
            // successful log so a transient logger fault retries on the next call instead of
            // permanently suppressing the diagnostic.
            if (!_firstRealBoundsLogged && bounds != HostBounds.Seed)
            {
                _logger.LogInformation(
                    "RDP MoveWindow (first real bounds): x={X} y={Y} w={W} h={H}.",
                    bounds.X, bounds.Y, bounds.Width, bounds.Height);
                _firstRealBoundsLogged = true;
            }
        }

        public void Show()
        {
            Win32Interop.ShowWindow(_form.Hwnd, Win32Interop.SW_SHOWNA);
            // Emit the post-Show diagnostic on every Show() call — not gated. Show() is rare
            // (called from AttachAsync once per attach: cold connect + each rebind after a
            // nav-away). A latched gate would hide exactly the rebind path most likely to
            // surface a "black after navigating back" regression. WS_POPUP is surfaced
            // separately because the reparent flow explicitly strips it — a regression would
            // otherwise be buried inside the raw hex style. The rect is screen coordinates
            // (GetWindowRect's contract); compare against the "MoveWindow (first real bounds)"
            // entry above for client-relative geometry.
            var style = Win32Interop.GetWindowLong(_form.Hwnd, Win32Interop.GWL_STYLE);
            if (!Win32Interop.GetWindowRect(_form.Hwnd, out var r))
            {
                var err = Marshal.GetLastWin32Error();
                _logger.LogInformation(
                    "RDP HWND post-Show: style=0x{Style:X8} (WS_VISIBLE={Visible}, WS_CHILD={Child}, WS_POPUP={Popup}); GetWindowRect failed (Win32 error {Error}).",
                    style,
                    (style & Win32Interop.WS_VISIBLE) != 0,
                    (style & Win32Interop.WS_CHILD) != 0,
                    (style & Win32Interop.WS_POPUP) != 0,
                    err);
                return;
            }
            _logger.LogInformation(
                "RDP HWND post-Show: style=0x{Style:X8} (WS_VISIBLE={Visible}, WS_CHILD={Child}, WS_POPUP={Popup}), screenRect=({L},{T})-({R},{B}).",
                style,
                (style & Win32Interop.WS_VISIBLE) != 0,
                (style & Win32Interop.WS_CHILD) != 0,
                (style & Win32Interop.WS_POPUP) != 0,
                r.left, r.top, r.right, r.bottom);
        }

        public void Hide() => Win32Interop.ShowWindow(_form.Hwnd, Win32Interop.SW_HIDE);

        public void Disconnect() => _form.Disconnect();

        public void Focus() => _form.RequestFocus();

        public void Dispose()
        {
            try { _form.Dispose(); }
            catch (Exception ex)
            {
                // COM may throw mid-teardown — log so a real leak isn't silent.
                _logger.LogWarning(ex, "RdpSessionAdapter.Dispose suppressed an exception from the host form.");
            }
        }
    }
}
