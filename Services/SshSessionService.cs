using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Wormhole.Models;
using Wormhole.Services.Ssh;

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
        string? password,
        byte[]? privateKey,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(profile.Host))
            throw new ArgumentException("Connection profile must have a host.", nameof(profile));
        if (string.IsNullOrWhiteSpace(profile.Username))
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has no username; provide one before connecting.");

        var authMethods = BuildAuthMethods(profile.Username!, password, privateKey);
        if (authMethods.Count == 0)
        {
            throw new InvalidOperationException(
                $"Connection '{profile.Name}' has no usable credentials (password or private key).");
        }

        var connectionInfo = new ConnectionInfo(profile.Host, profile.Port, profile.Username, authMethods.ToArray())
        {
            Timeout = TimeSpan.FromSeconds(15),
        };

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
            await Task.Run(client.Connect, cancellationToken).WaitAsync(cancellationToken).ConfigureAwait(false);
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
            stream = client.CreateShellStream("xterm-256color", 80, 24, 0, 0, 8192);
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

    private static List<AuthenticationMethod> BuildAuthMethods(string username, string? password, byte[]? privateKey)
    {
        var methods = new List<AuthenticationMethod>();
        if (privateKey is not null)
        {
            // Treat the password (if any) as the key passphrase. SSH.NET surfaces a
            // SshPassPhraseNullOrEmptyException at parse time when the key is encrypted
            // and no passphrase was supplied; the VM catches that and re-prompts.
            var keyFile = string.IsNullOrEmpty(password)
                ? new PrivateKeyFile(new MemoryStream(privateKey))
                : new PrivateKeyFile(new MemoryStream(privateKey), password);
            methods.Add(new PrivateKeyAuthenticationMethod(username, keyFile));
        }
        if (!string.IsNullOrEmpty(password))
        {
            methods.Add(new PasswordAuthenticationMethod(username, password));
        }
        return methods;
    }

    private static void SafeDispose(SshClient client)
    {
        try { client.Dispose(); } catch { /* best effort */ }
    }
}
