using Wormhole.Models;

namespace Wormhole.Services;

public interface IRdpSessionService
{
    Task<IRdpSession> ConnectAsync(
        ConnectionProfile profile,
        string? password,
        IntPtr ownerHwnd,
        string? gatewayUsername = null,
        string? gatewayPassword = null,
        CancellationToken cancellationToken = default);
}

public interface IRdpSession : IDisposable
{
    /// <summary>HWND of the embedded ActiveX host. Used by the surface host for positioning.</summary>
    IntPtr Hwnd { get; }

    /// <summary>True once OnLoginComplete fires. False during the TLS+NLA handshake and after disconnect.</summary>
    bool IsLoggedOn { get; }

    /// <summary>Raised after OnLoginComplete — credentials accepted, shell is starting.</summary>
    event EventHandler? Connected;

    /// <summary>Raised on OnDisconnected. Carries a reason code + human description from GetErrorDescription.</summary>
    event EventHandler<RdpDisconnectInfo>? Disconnected;

    /// <summary>Raised on OnFatalError. Carries the fatal error code.</summary>
    event EventHandler<int>? FatalError;

    /// <summary>Raised on OnLogonError — credential failure (bad password, expired, etc.). lError is the OnLogonError code.</summary>
    event EventHandler<int>? LogonError;

    /// <summary>Raised while ActiveX is in auto-reconnect: attempt # and cap.</summary>
    event EventHandler<RdpReconnectInfo>? AutoReconnecting;

    /// <summary>Position the embedded host inside the parent window's client area.</summary>
    void SetBounds(HostBounds bounds);

    /// <summary>Make the host window visible (e.g. on tab activation).</summary>
    void Show();

    /// <summary>Hide the host window (e.g. on tab deactivation) without disconnecting.</summary>
    void Hide();

    /// <summary>Request a graceful disconnect; idempotent.</summary>
    void Disconnect();
}

/// <summary>Disconnect description supplied to the view-model. <paramref name="IsClean"/> tracks whether
/// the disconnect was user/server-initiated (reason codes 0..3) vs. a fault.</summary>
public sealed record RdpDisconnectInfo(int Code, int ExtendedCode, string Description, bool IsClean);

public sealed record RdpReconnectInfo(int Attempt, int MaxAttempts, int DisconnectReason);

/// <summary>
/// Window-client physical-pixel rectangle for the reparented RDP surface. Used in place of
/// 4 positional ints across the IRdpSession + surface host boundary.
/// </summary>
public readonly record struct HostBounds(int X, int Y, int Width, int Height)
{
    public static readonly HostBounds Empty = new(0, 0, 0, 0);

    /// <summary>1×1 placeholder used when the host control hasn't been measured yet.</summary>
    public static readonly HostBounds Seed = new(0, 0, 1, 1);

    public bool IsDegenerate(int minDim = 8) => Width < minDim || Height < minDim;
}
