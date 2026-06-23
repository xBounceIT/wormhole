using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Wormhole.Models;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;

namespace Wormhole.Services;

public sealed class SshSessionService : ISshSessionService
{
    private readonly ILogger<SshSessionService> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public SshSessionService(ILogger<SshSessionService> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public async Task<ISshSession> ConnectAsync(
        ConnectionProfile profile,
        SshCredentials credentials,
        TerminalSize initialSize,
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
            // SSH dials a stream-oriented socket: it needs a SOCKS5 endpoint to proxy through.
            // A tunnel kind that omits SOCKS5 (none exist yet, but future providers might)
            // must explicitly throw here rather than silently fall through to a non-tunneled
            // connect — that would leak the SSH bytes outside the tunnel.
            var socks = tunnel.Socks5Endpoint
                ?? throw new InvalidOperationException(
                    $"Tunnel for '{profile.Name}' does not expose a SOCKS5 endpoint; SSH cannot route through it.");
            connectionInfo = new ConnectionInfo(
                profile.Host, profile.Port, username,
                ProxyTypes.Socks5, socks.Address.ToString(), socks.Port,
                proxyUsername: string.Empty, proxyPassword: string.Empty,
                authMethods);
            _logger.LogDebug("Routing SSH connect through SOCKS5 tunnel at {Endpoint}.", socks);
        }
        connectionInfo.Timeout = TimeSpan.FromSeconds(15);

        var client = new SshClient(connectionInfo);
        // Send an SSH-level keep-alive on an otherwise idle connection so a silently-dead peer is
        // detected in tens of seconds instead of never. An abrupt host death (reboot, power loss,
        // network partition) sends no FIN/RST, so our blocked ShellStream read never returns and the
        // tab looks connected forever — the reported "appears open but nothing happens". The periodic
        // SSH_MSG_IGNORE forces TCP to keep transmitting; once the peer is gone TCP's retransmit
        // timeout errors the socket, SSH.NET's message loop raises a connection error and disconnects,
        // which disposes the ShellStream and unblocks the read pump (n == 0 -> Closed -> the VM's
        // failure overlay). A graceful sshd exit was already caught via EOF; this covers the ungraceful
        // case. As a bonus it also keeps NAT/firewall mappings from evicting a genuinely idle session.
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
            // Pass CancellationToken.None to Task.Run on purpose: SSH.NET's sync Connect ignores
            // CT once started. WaitAsync gives the awaiter an exit path; the catch block disposes
            // the client to interrupt the in-flight socket. Forwarding the token to Task.Run only
            // adds a redundant pre-scheduling cancel check and diverges from the SFTP connect path.
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

        ShellStream stream;
        try
        {
            var cols = initialSize.Columns == 0 ? TerminalSize.Default.Columns : initialSize.Columns;
            var rows = initialSize.Rows == 0 ? TerminalSize.Default.Rows : initialSize.Rows;
            stream = client.CreateShellStream("xterm-256color", cols, rows, 0, 0, 8192);
        }
        catch
        {
            SafeDispose(client);
            throw;
        }

        _logger.LogInformation(
            "SSH connected to {Host}:{Port} as {User}; fingerprint {Fingerprint}.",
            profile.Host, profile.Port, username, capturedFingerprint);

        return new SshSession(client, stream, capturedFingerprint!, _loggerFactory.CreateLogger<SshSession>());
    }

    private static void SafeDispose(SshClient client)
    {
        try { client.Dispose(); } catch { /* best effort */ }
    }
}
