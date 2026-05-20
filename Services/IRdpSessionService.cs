using System;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services;

public interface IRdpSessionService
{
    Task<IRdpSession> ConnectAsync(ConnectionProfile profile, string? password);
}

public interface IRdpSession : IDisposable
{
    IntPtr Hwnd { get; }
    void Disconnect();
}
