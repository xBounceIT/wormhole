using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Interop.Rdp;
using Wormhole.Models;

namespace Wormhole.Services;

public sealed class RdpSessionService : IRdpSessionService
{
    private readonly ILogger<RdpSessionService> _logger;

    public RdpSessionService(ILogger<RdpSessionService> logger)
    {
        _logger = logger;
    }

    public Task<IRdpSession> ConnectAsync(
        ConnectionProfile profile,
        string? password,
        IntPtr ownerHwnd,
        string? gatewayUsername = null,
        string? gatewayPassword = null,
        CancellationToken cancellationToken = default)
    {
        // Must run on the WinUI UI thread (STA). The form constructor enforces this.
        if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
        {
            throw new InvalidOperationException("RdpSessionService.ConnectAsync must be invoked on the STA UI thread.");
        }
        cancellationToken.ThrowIfCancellationRequested();

        var form = new RdpHostForm();
        try
        {
            _ = form.Hwnd; // force handle creation + AxHost CreateControl before Configure / SetParent
            form.Configure(profile, password, gatewayUsername, gatewayPassword);
            cancellationToken.ThrowIfCancellationRequested();
            // SetParent returns the previous parent on success and IntPtr.Zero on failure.
            // A top-level WinForms Form has the desktop as parent before reparenting, so
            // success returns the desktop HWND (non-zero); Zero unambiguously means failure.
            var oldParent = Win32Interop.SetParent(form.Hwnd, ownerHwnd);
            if (oldParent == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                throw new InvalidOperationException(
                    $"SetParent failed reparenting the RDP host onto the WinUI main window (Win32 error {err}).");
            }
            cancellationToken.ThrowIfCancellationRequested();
            form.Start();
        }
        catch
        {
            try { form.Dispose(); } catch { }
            throw;
        }

        _logger.LogInformation("RDP session opened to {Host}:{Port}.", profile.Host, profile.Port);
        return Task.FromResult<IRdpSession>(new RdpSessionAdapter(form));
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
        private bool _loggedOn;
        private HostBounds _lastBounds = HostBounds.Empty;

        public RdpSessionAdapter(RdpHostForm form)
        {
            _form = form;
            _form.Connected += () =>
            {
                _loggedOn = true;
                Connected?.Invoke(this, EventArgs.Empty);
            };
            _form.Disconnected += code =>
            {
                _loggedOn = false;
                var desc = _form.GetDisconnectDescription(code, 0);
                // Reason codes 0-3 are clean (user-initiated, server-initiated, idle, etc.)
                // per the IMsTscAxEvents.OnDisconnected reference table. Everything else is
                // a fault that should surface the failure overlay.
                var clean = code is >= 0 and <= 3;
                Disconnected?.Invoke(this, new RdpDisconnectInfo(code, 0, desc, clean));
            };
            _form.FatalError += code => FatalError?.Invoke(this, code);
            _form.LogonError += code => LogonError?.Invoke(this, code);
            _form.AutoReconnecting2 += (reason, available, attempt, max) =>
                AutoReconnecting?.Invoke(this, new RdpReconnectInfo(attempt, max, reason));
        }

        public IntPtr Hwnd => _form.Hwnd;
        public bool IsLoggedOn => _loggedOn;

        public event EventHandler? Connected;
        public event EventHandler<RdpDisconnectInfo>? Disconnected;
        public event EventHandler<int>? FatalError;
        public event EventHandler<int>? LogonError;
        public event EventHandler<RdpReconnectInfo>? AutoReconnecting;

        public void SetBounds(HostBounds bounds)
        {
            if (bounds.Width < 1 || bounds.Height < 1) return;
            if (bounds == _lastBounds) return;
            _lastBounds = bounds;
            Win32Interop.MoveWindow(_form.Hwnd, bounds.X, bounds.Y, bounds.Width, bounds.Height, bRepaint: true);
        }

        public void Show() => Win32Interop.ShowWindow(_form.Hwnd, Win32Interop.SW_SHOWNA);

        public void Hide() => Win32Interop.ShowWindow(_form.Hwnd, Win32Interop.SW_HIDE);

        public void Disconnect() => _form.Disconnect();

        public void Dispose()
        {
            try { _form.Dispose(); } catch { /* COM may throw during teardown */ }
        }
    }
}
