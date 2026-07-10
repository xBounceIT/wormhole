using MarcusW.VncClient.Rendering;
using Wormhole.Models;
using Wormhole.Services.Tunneling;

namespace Wormhole.Services;

public interface IVncSessionService
{
    Task<IVncSession> ConnectAsync(
        ConnectionProfile profile,
        IVncPasswordProvider passwordProvider,
        IVncRenderTarget renderTarget,
        ITunnelInstance? tunnel = null,
        CancellationToken cancellationToken = default);
}

public interface IVncSession : IAsyncDisposable
{
    event EventHandler<VncSessionClosedEventArgs>? Closed;

    void SetRenderTarget(IVncRenderTarget renderTarget);
    Task SendPointerAsync(int x, int y, VncPointerButtons buttons, CancellationToken cancellationToken = default);
    Task SendKeyAsync(bool isDown, int keySymbol, CancellationToken cancellationToken = default);
}

public interface IVncRenderTarget : IRenderTarget
{
}

public interface IVncPasswordProvider
{
    Task<string?> GetPasswordAsync(CancellationToken cancellationToken);
}

[Flags]
public enum VncPointerButtons
{
    None = 0,
    Left = 1,
    Middle = 2,
    Right = 4,
    WheelUp = 8,
    WheelDown = 16,
    WheelLeft = 32,
    WheelRight = 64,
}

public sealed class VncSessionClosedEventArgs : EventArgs
{
    public VncSessionClosedEventArgs(bool isClean, string message, Exception? exception = null)
    {
        IsClean = isClean;
        Message = message;
        Exception = exception;
    }

    public bool IsClean { get; }
    public string Message { get; }
    public Exception? Exception { get; }
}

public sealed class VncAuthenticationCancelledException : UserInteractionCancelledException
{
    public VncAuthenticationCancelledException()
        : base("VNC authentication was cancelled.")
    {
    }
}
