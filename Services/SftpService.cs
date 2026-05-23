using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Wormhole.Models;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;

namespace Wormhole.Services;

public sealed class SftpService : ISftpService
{
    private readonly ILogger<SftpService> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public SftpService(ILogger<SftpService> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public async Task<ISftpSession> ConnectAsync(
        ConnectionProfile profile,
        SshCredentials credentials,
        ITunnelInstance? tunnel = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(profile.Host))
            throw new ArgumentException("Connection profile must have a host.", nameof(profile));
        if (string.IsNullOrWhiteSpace(profile.Username))
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has no username; provide one before connecting.");

        var authMethods = SshAuthMethodsBuilder.Build(profile.Username!, credentials);
        if (authMethods.Count == 0)
        {
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has no usable credentials (password or private key).");
        }

        ConnectionInfo connectionInfo;
        if (tunnel is null)
        {
            connectionInfo = new ConnectionInfo(profile.Host, profile.Port, profile.Username, authMethods.ToArray());
        }
        else
        {
            // Same SOCKS5 reasoning as SshSessionService: a tunnel without SOCKS5 must
            // throw rather than silently leak bytes outside the tunnel.
            var socks = tunnel.Socks5Endpoint
                ?? throw new InvalidOperationException(
                    $"Tunnel for '{profile.Name}' does not expose a SOCKS5 endpoint; SFTP cannot route through it.");
            connectionInfo = new ConnectionInfo(
                profile.Host, profile.Port, profile.Username,
                ProxyTypes.Socks5, socks.Address.ToString(), socks.Port,
                proxyUsername: string.Empty, proxyPassword: string.Empty,
                authMethods.ToArray());
            _logger.LogDebug("Routing SFTP connect through SOCKS5 tunnel at {Endpoint}.", socks);
        }
        connectionInfo.Timeout = TimeSpan.FromSeconds(15);

        var client = new SftpClient(connectionInfo);
        string? capturedFingerprint = null;
        SshHostKeyMismatchException? mismatch = null;

        client.HostKeyReceived += (_, e) =>
        {
            capturedFingerprint = SshHostKeyValidator.ComputeFingerprint(e.HostKey);
            var decision = SshHostKeyValidator.Decide(profile.SshKnownHostFingerprint, capturedFingerprint);
            if (decision == HostKeyDecision.Mismatch)
            {
                e.CanTrust = false;
                mismatch = new SshHostKeyMismatchException(
                    profile.Host, profile.SshKnownHostFingerprint!, capturedFingerprint);
                return;
            }
            e.CanTrust = true;
        };

        try
        {
            await Task.Run(client.Connect).WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            SafeDispose(client);
            throw;
        }
        catch
        {
            SafeDispose(client);
            if (mismatch is not null) throw mismatch;
            throw;
        }

        if (mismatch is not null)
        {
            SafeDispose(client);
            throw mismatch;
        }

        _logger.LogInformation(
            "SFTP connected to {Host}:{Port} as {User}; fingerprint {Fingerprint}.",
            profile.Host, profile.Port, profile.Username, capturedFingerprint);

        return new SftpSession(client, capturedFingerprint, _loggerFactory.CreateLogger<SftpSession>());
    }

    private static void SafeDispose(SftpClient client)
    {
        try { client.Dispose(); } catch { /* best effort */ }
    }
}
