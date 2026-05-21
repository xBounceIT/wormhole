using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
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
        if (string.IsNullOrWhiteSpace(profile.Username))
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has no username; provide one before connecting.");

        var authMethods = BuildAuthMethods(profile.Username!, credentials);
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
            // SSH dials a stream-oriented socket: it needs a SOCKS5 endpoint to proxy through.
            // A tunnel kind that omits SOCKS5 (none exist yet, but future providers might)
            // must explicitly throw here rather than silently fall through to a non-tunneled
            // connect — that would leak the SSH bytes outside the tunnel.
            var socks = tunnel.Socks5Endpoint
                ?? throw new InvalidOperationException(
                    $"Tunnel for '{profile.Name}' does not expose a SOCKS5 endpoint; SSH cannot route through it.");
            connectionInfo = new ConnectionInfo(
                profile.Host, profile.Port, profile.Username,
                ProxyTypes.Socks5, socks.Address.ToString(), socks.Port,
                proxyUsername: string.Empty, proxyPassword: string.Empty,
                authMethods.ToArray());
            _logger.LogDebug("Routing SSH connect through SOCKS5 tunnel at {Endpoint}.", socks);
        }
        connectionInfo.Timeout = TimeSpan.FromSeconds(15);

        var client = new SshClient(connectionInfo);
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
            // Task.Run's CT only governs scheduling; SSH.NET's sync Connect ignores CT once
            // started. WaitAsync gives the awaiter an exit path; the catch block disposes
            // the client to interrupt the in-flight socket.
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
            profile.Host, profile.Port, profile.Username, capturedFingerprint);

        return new SshSession(client, stream, capturedFingerprint!, _loggerFactory.CreateLogger<SshSession>());
    }

    private static List<AuthenticationMethod> BuildAuthMethods(string username, SshCredentials credentials)
    {
        var methods = new List<AuthenticationMethod>();
        if (credentials.PrivateKey is { Length: > 0 })
        {
            // KeyPassphrase is consumed locally to decrypt the key — never sent as a login
            // password. SSH.NET throws SshPassPhraseNullOrEmptyException at parse time if the
            // key is encrypted and we passed no passphrase; the VM catches and re-prompts.
            var keyFile = string.IsNullOrEmpty(credentials.KeyPassphrase)
                ? new PrivateKeyFile(new MemoryStream(credentials.PrivateKey))
                : new PrivateKeyFile(new MemoryStream(credentials.PrivateKey), credentials.KeyPassphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(username, keyFile));
        }
        if (!string.IsNullOrEmpty(credentials.Password))
        {
            methods.Add(new PasswordAuthenticationMethod(username, credentials.Password));
        }
        return methods;
    }

    private static void SafeDispose(SshClient client)
    {
        try { client.Dispose(); } catch { /* best effort */ }
    }
}
