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
        var username = credentials.ResolveUsername(profile);
        if (string.IsNullOrWhiteSpace(username))
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has no username; provide one before connecting.");

        var authMethods = SshAuthMethodsBuilder.Build(username, credentials);
        if (authMethods.Length == 0)
        {
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has no usable credentials (password or private key).");
        }

        ConnectionInfo connectionInfo;
        if (tunnel is null)
        {
            connectionInfo = new ConnectionInfo(profile.Host, profile.Port, username, authMethods);
        }
        else
        {
            // Same SOCKS5 reasoning as SshSessionService: a tunnel without SOCKS5 must
            // throw rather than silently leak bytes outside the tunnel.
            var socks = tunnel.Socks5Endpoint
                ?? throw new InvalidOperationException(
                    $"Tunnel for '{profile.Name}' does not expose a SOCKS5 endpoint; SFTP cannot route through it.");
            connectionInfo = new ConnectionInfo(
                profile.Host, profile.Port, username,
                ProxyTypes.Socks5, socks.Address.ToString(), socks.Port,
                proxyUsername: string.Empty, proxyPassword: string.Empty,
                authMethods);
            _logger.LogDebug("Routing SFTP connect through SOCKS5 tunnel at {Endpoint}.", socks);
        }
        connectionInfo.Timeout = TimeSpan.FromSeconds(15);

        var client = new SftpClient(connectionInfo);
        // Keep-alive so a silently-dead peer (host reboot, power loss, network partition) is noticed
        // rather than leaving a zombie session. Matters most for the SSH-tab SFTP pre-warm, whose
        // staleness gate (SshSessionViewModel.TryConsumePrewarmedSftp) relies on IsConnected reflecting
        // reality — and without periodic traffic SSH.NET never learns the transport died. Same value
        // and rationale as SshSessionService; see the longer note there.
        client.KeepAliveInterval = TimeSpan.FromSeconds(30);
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
            // Pass CancellationToken.None to Task.Run on purpose: cancellation is handled by the
            // outer WaitAsync(cancellationToken) + the catch's SafeDispose(client), which tears
            // down the socket and terminates the inner blocking Connect. Forwarding the token to
            // Task.Run would only add a redundant pre-scheduling cancel check — and the SSH.NET
            // client cannot honor a token mid-Connect anyway. See Services/Ssh/SftpSession.cs
            // lines 175-187 for the team's analysis of the Task.Run(action, ct).WaitAsync(ct)
            // anti-pattern; this site is the documented exception because SafeDispose reliably
            // kills the orphaned worker.
            await Task.Run(client.Connect, CancellationToken.None).WaitAsync(cancellationToken).ConfigureAwait(false);
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
            profile.Host, profile.Port, username, capturedFingerprint);

        return new SftpSession(client, capturedFingerprint, _loggerFactory.CreateLogger<SftpSession>());
    }

    private static void SafeDispose(SftpClient client)
    {
        try { client.Dispose(); } catch { /* best effort */ }
    }
}
