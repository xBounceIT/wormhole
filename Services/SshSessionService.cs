using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Models;

namespace Wormhole.Services;

public sealed class SshSessionService : ISshSessionService
{
    private readonly ILogger<SshSessionService> _logger;

    public SshSessionService(ILogger<SshSessionService> logger)
    {
        _logger = logger;
    }

    public Task<ISshSession> ConnectAsync(
        ConnectionProfile profile,
        string? password,
        byte[]? privateKey,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("ConnectAsync placeholder for {Host}:{Port}", profile.Host, profile.Port);
        throw new NotImplementedException(
            "SshSessionService.ConnectAsync is a scaffold placeholder. Wire SSH.NET ShellStream here in the SSH feature PR.");
    }
}
