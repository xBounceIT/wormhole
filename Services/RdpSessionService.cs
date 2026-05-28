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
        HostBounds initialBounds = default,
        Action<IRdpSession>? onSessionReady = null,
        CancellationToken cancellationToken = default)
    {
        // Must run on the WinUI UI thread (STA). The form constructor enforces this.
        if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
        {
            throw new InvalidOperationException("RdpSessionService.ConnectAsync must be invoked on the STA UI thread.");
        }
        if (ownerHwnd == IntPtr.Zero)
        {
            throw new InvalidOperationException("RDP host cannot be embedded because the owner window handle is not available.");
        }
        cancellationToken.ThrowIfCancellationRequested();

        var form = CreateRealizedHostForm();
        try
        {
            var surfaceBounds = initialBounds.IsDegenerate(minDim: 1) ? HostBounds.Empty : initialBounds;
            form.Configure(
                profile,
                password,
                gatewayUsername,
                gatewayPassword,
                ownerHwnd,
                surfaceBounds.Width,
                surfaceBounds.Height);
            cancellationToken.ThrowIfCancellationRequested();

            // Host the OCX in a SEPARATE TOP-LEVEL WINDOW owned by the WinUI main window and
            // positioned in screen coordinates over the tab — do NOT reparent it INTO the WinUI
            // window. Reparenting (SetParent + WS_CHILD) makes the child composite BEHIND the
            // XAML DirectComposition surface (the WinUI 3 "airspace" problem): the transparent
            // tab slot then reveals the window background instead of the remote desktop. An owned
            // top-level window is composited by DWM ABOVE the owner's content, so it renders
            // correctly; the owner relationship keeps it minimizing/restoring/closing with the
            // main window and out of the taskbar / Alt-Tab.
            ConfigureAsOwnedOverlay(form.Hwnd, ownerHwnd);
            cancellationToken.ThrowIfCancellationRequested();

            // Force the OCX visible/in-place-active before Connect(). Use the real first
            // surface bounds when available; otherwise a 1x1 child is enough to keep
            // mstscax from starting the handshake against a never-shown ActiveX host.
            var activationBounds = surfaceBounds.IsDegenerate(minDim: 1) ? HostBounds.Seed : surfaceBounds;
            if (!form.SetHostBounds(activationBounds.X, activationBounds.Y, activationBounds.Width, activationBounds.Height))
            {
                throw new InvalidOperationException("RDP host failed to activate its initial native surface.");
            }

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
    /// Turn the (top-level, WS_POPUP) WinForms host into an owned overlay of the WinUI main
    /// window: set the main window as owner (GWLP_HWNDPARENT) so it minimizes/restores/closes
    /// with the parent and stays above it, and OR-in WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW so
    /// clicking the remote surface doesn't steal WinUI activation and the overlay never gets a
    /// taskbar / Alt-Tab entry. Deliberately does NOT switch to WS_CHILD / SetParent — see
    /// <see cref="ConnectAsync"/> for why that breaks rendering.
    /// </summary>
    private void ConfigureAsOwnedOverlay(IntPtr hwnd, IntPtr ownerHwnd)
    {
        // Owner is stored in GWLP_HWNDPARENT for a top-level window. Use the *LongPtr accessor
        // so the 64-bit owner HWND isn't truncated. A NULL return is only a failure when the
        // last error is nonzero (NULL + zero error means there was no previous owner).
        Marshal.SetLastSystemError(0);
        var previousOwner = Win32Interop.SetWindowLongPtr(hwnd, Win32Interop.GWLP_HWNDPARENT, ownerHwnd);
        if (previousOwner == IntPtr.Zero)
        {
            var ownerError = Marshal.GetLastWin32Error();
            if (ownerError != 0)
            {
                throw new InvalidOperationException(
                    $"SetWindowLongPtr(GWLP_HWNDPARENT) failed setting the RDP overlay owner (Win32 error {ownerError}).");
            }
        }

        // OR-in the extended styles so we don't clobber anything WinForms already set.
        Marshal.SetLastSystemError(0);
        var exStyle = Win32Interop.GetWindowLongPtr(hwnd, Win32Interop.GWL_EXSTYLE).ToInt64();
        var getExError = Marshal.GetLastWin32Error();
        if (exStyle == 0 && getExError != 0)
        {
            throw new InvalidOperationException(
                $"GetWindowLongPtr(GWL_EXSTYLE) failed reading the RDP overlay styles (Win32 error {getExError}).");
        }
        var newExStyle = exStyle | Win32Interop.WS_EX_NOACTIVATE | Win32Interop.WS_EX_TOOLWINDOW;
        if (newExStyle != exStyle)
        {
            Marshal.SetLastSystemError(0);
            var previousExStyle = Win32Interop.SetWindowLongPtr(hwnd, Win32Interop.GWL_EXSTYLE, (IntPtr)newExStyle);
            var setExError = Marshal.GetLastWin32Error();
            if (previousExStyle == IntPtr.Zero && setExError != 0)
            {
                throw new InvalidOperationException(
                    $"SetWindowLongPtr(GWL_EXSTYLE) failed applying the RDP overlay styles (Win32 error {setExError}).");
            }
        }

        // Recompute the non-client frame after the style change.
        Marshal.SetLastSystemError(0);
        if (!Win32Interop.SetWindowPos(
                hwnd,
                IntPtr.Zero,
                0,
                0,
                0,
                0,
                Win32Interop.SWP_NOMOVE |
                Win32Interop.SWP_NOSIZE |
                Win32Interop.SWP_NOZORDER |
                Win32Interop.SWP_NOACTIVATE |
                Win32Interop.SWP_FRAMECHANGED))
        {
            _logger.LogWarning(
                "SetWindowPos(SWP_FRAMECHANGED) failed configuring RDP overlay styles (Win32 error {Error}).",
                Marshal.GetLastWin32Error());
        }
    }

    private RdpHostForm CreateRealizedHostForm()
    {
        var hostLogger = _loggerFactory.CreateLogger<RdpHostForm>();
        var candidates = AxMsRdpClient9NotSafeForScripting.GetRegisteredClasses();
        for (var i = 0; i < candidates.Count - 1; i++)
        {
            RdpHostForm? form = null;
            try
            {
                form = new RdpHostForm(candidates[i], hostLogger);
                _ = form.Hwnd; // force handle creation + AxHost CreateControl before Configure / SetParent
                return form;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "RDP ActiveX class {ClassName} ({Clsid}) failed during activation; trying next registered class.",
                    candidates[i].Name,
                    candidates[i].ClsidString);
                try { form?.Dispose(); }
                catch (Exception disposeEx)
                {
                    _logger.LogDebug(disposeEx, "RDP host form Dispose failed after ActiveX activation fallback.");
                }
            }
        }

        var fallback = candidates[^1];
        var finalForm = new RdpHostForm(fallback, hostLogger);
        _ = finalForm.Hwnd;
        return finalForm;
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
                Connected?.Invoke(this, EventArgs.Empty);
            };
            _form.LoginComplete += () =>
            {
                _loggedOn = true;
                LoginComplete?.Invoke(this, EventArgs.Empty);
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
        public event EventHandler? LoginComplete;
        public event EventHandler<RdpDisconnectInfo>? Disconnected;
        public event EventHandler<int>? FatalError;
        public event EventHandler<int>? LogonError;
        public event EventHandler<RdpReconnectInfo>? AutoReconnecting;
        public event EventHandler? AutoReconnected;

        public void SetBounds(HostBounds bounds)
        {
            if (bounds.Width < 1 || bounds.Height < 1) return;
            if (bounds == _lastBounds) return;
            if (!_form.SetHostBounds(bounds.X, bounds.Y, bounds.Width, bounds.Height))
            {
                throw new InvalidOperationException(
                    $"RDP host failed to apply bounds x={bounds.X}, y={bounds.Y}, width={bounds.Width}, height={bounds.Height}.");
            }
            _lastBounds = bounds;
            // Diagnostic: log once per adapter the FIRST real bounds (skipping the (0,0,1,1)
            // Seed placeholder the VM uses before real layout arrives). Set the flag after a
            // successful log so a transient logger fault retries on the next call instead of
            // permanently suppressing the diagnostic.
            if (!_firstRealBoundsLogged && bounds != HostBounds.Seed)
            {
                _logger.LogInformation(
                    "RDP SetHostBounds (first real bounds): x={X} y={Y} w={W} h={H}.",
                    bounds.X, bounds.Y, bounds.Width, bounds.Height);
                _form.LogWindowDiagnostics(_logger, "first-real-bounds");
                _firstRealBoundsLogged = true;
            }
        }

        public void Show()
        {
            Win32Interop.ShowWindow(_form.Hwnd, Win32Interop.SW_SHOWNA);
            if (!_form.EnsureVisibleAndRedraw("show"))
            {
                throw new InvalidOperationException("RDP host failed to become visible after Show().");
            }
            // Emit the post-Show diagnostic on every Show() call — not gated. Show() is rare
            // (called from AttachAsync once per attach: cold connect + each rebind after a
            // nav-away). A latched gate would hide exactly the rebind path most likely to
            // surface a "blank after navigating back" regression. The overlay is a top-level
            // owned window, so the expected style is WS_POPUP=true, WS_CHILD=false; the rect is
            // screen coordinates (GetWindowRect's contract) and should match the tab's on-screen
            // position computed by RdpSurfaceHost.ComputeBoundsScreenPx.
            _form.LogWindowDiagnostics(_logger, "post-Show");
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
