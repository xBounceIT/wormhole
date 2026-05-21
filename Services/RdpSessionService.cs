using Microsoft.Extensions.Logging;
using Wormhole.Models;

namespace Wormhole.Services;

public sealed class RdpSessionService : IRdpSessionService
{
    private readonly ILogger<RdpSessionService> _logger;

    public RdpSessionService(ILogger<RdpSessionService> logger)
    {
        _logger = logger;
    }

    public Task<IRdpSession> ConnectAsync(ConnectionProfile profile, string? password)
    {
        _logger.LogInformation("ConnectAsync placeholder for RDP {Host}:{Port}", profile.Host, profile.Port);
        throw new NotImplementedException(
            "RdpSessionService.ConnectAsync is a scaffold placeholder. Wire mstscax ActiveX host via Interop/Rdp/RdpHostForm in the RDP feature PR.");
    }
}
