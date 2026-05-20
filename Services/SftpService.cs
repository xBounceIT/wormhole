using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Models;

namespace Wormhole.Services;

public sealed class SftpService : ISftpService
{
    private readonly ILogger<SftpService> _logger;

    public SftpService(ILogger<SftpService> logger)
    {
        _logger = logger;
    }

    public Task<ISftpSession> ConnectAsync(
        ConnectionProfile profile,
        string? password,
        byte[]? privateKey,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("ConnectAsync placeholder for SFTP {Host}:{Port}", profile.Host, profile.Port);
        throw new NotImplementedException(
            "SftpService.ConnectAsync is a scaffold placeholder. Wire SSH.NET SftpClient here in the SFTP feature PR.");
    }
}
