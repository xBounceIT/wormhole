using Wormhole.Models;

namespace Wormhole.Services;

public interface ISerialSessionService
{
    Task<ITerminalSession> ConnectAsync(
        ConnectionProfile profile,
        TerminalSize initialSize,
        CancellationToken cancellationToken = default);
}
