using System;
using Wormhole.Services;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// Test double for <see cref="IRdpSession"/>. Each event has a matching <c>Raise*</c> driver
/// so tests can simulate the ActiveX OCX firing them. <see cref="Disposed"/> tracks whether
/// the VM tore the session down — assert it from the test to verify cleanup.
/// </summary>
public sealed class FakeRdpSession : IRdpSession
{
    public IntPtr Hwnd => (IntPtr)0x1234;
    public bool IsLoggedOn { get; private set; }
    public bool Disposed { get; private set; }

    public event EventHandler? Connected;
    public event EventHandler<RdpDisconnectInfo>? Disconnected;
    public event EventHandler<int>? FatalError;
    public event EventHandler<int>? LogonError;
    public event EventHandler<RdpReconnectInfo>? AutoReconnecting;
    public event EventHandler? AutoReconnected;

    public void RaiseConnected() { IsLoggedOn = true; Connected?.Invoke(this, EventArgs.Empty); }
    public void RaiseDisconnected(RdpDisconnectInfo info) { IsLoggedOn = false; Disconnected?.Invoke(this, info); }
    public void RaiseFatalError(int code) => FatalError?.Invoke(this, code);
    public void RaiseLogonError(int code) => LogonError?.Invoke(this, code);
    public void RaiseAutoReconnecting(RdpReconnectInfo info) => AutoReconnecting?.Invoke(this, info);
    public void RaiseAutoReconnected() { IsLoggedOn = true; AutoReconnected?.Invoke(this, EventArgs.Empty); }

    public void SetBounds(HostBounds bounds) { }
    public void Show() { }
    public void Hide() { }
    public void Disconnect() { }
    public void Dispose() { Disposed = true; }
}
