using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Binds a TCP listener on 127.0.0.1 and forwards every accepted client through an
/// <see cref="ITunnelInstance"/> to a fixed target host:port. Used to give the RDP ActiveX
/// control (which opens its own socket from a hostname) a tunnel-aware endpoint to connect to.
/// </summary>
public sealed class LocalTcpForwarder : IAsyncDisposable
{
    private readonly ITunnelInstance _tunnel;
    private readonly string _targetHost;
    private readonly int _targetPort;
    private readonly ILogger _logger;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly HashSet<Task> _handlers = new();
    private readonly object _handlersGate = new();
    private Task? _acceptLoop;

    private LocalTcpForwarder(ITunnelInstance tunnel, string targetHost, int targetPort, TcpListener listener, ILogger logger)
    {
        _tunnel = tunnel;
        _targetHost = targetHost;
        _targetPort = targetPort;
        _listener = listener;
        _logger = logger;
    }

    public int LocalPort => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public static LocalTcpForwarder Start(ITunnelInstance tunnel, string targetHost, int targetPort, ILogger logger)
    {
        if (tunnel is null) throw new ArgumentNullException(nameof(tunnel));
        if (string.IsNullOrWhiteSpace(targetHost)) throw new ArgumentException("target host required", nameof(targetHost));
        if (targetPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(targetPort));

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var fwd = new LocalTcpForwarder(tunnel, targetHost, targetPort, listener, logger);
        fwd._acceptLoop = Task.Run(fwd.AcceptLoopAsync);
        return fwd;
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                var handler = Task.Run(() => HandleClientAsync(client, _cts.Token));
                lock (_handlersGate) _handlers.Add(handler);
                // Reap completed handlers from the tracking set so it doesn't grow unbounded
                // under a long-lived session.
                _ = handler.ContinueWith(t =>
                {
                    lock (_handlersGate) _handlers.Remove(t);
                }, TaskScheduler.Default);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Local tunnel forwarder accept loop on port {Port} crashed.", LocalPort);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using (client)
            {
                client.NoDelay = true;
                var clientStream = client.GetStream();
                Stream tunnelStream;
                try
                {
                    tunnelStream = await _tunnel.DialAsync(_targetHost, _targetPort, ct).ConfigureAwait(false);
                }
                catch (Exception dialEx)
                {
                    _logger.LogWarning(dialEx, "Forwarder failed to dial {Host}:{Port} through tunnel.", _targetHost, _targetPort);
                    return;
                }

                await using (tunnelStream)
                {
                    // Both directions are awaited so a half-open socket doesn't strand a copy
                    // loop. WhenAny + force-close-peer unblocks the loser cleanly.
                    var clientToTunnel = clientStream.CopyToAsync(tunnelStream, ct);
                    var tunnelToClient = tunnelStream.CopyToAsync(clientStream, ct);
                    await Task.WhenAny(clientToTunnel, tunnelToClient).ConfigureAwait(false);
                    try { client.Close(); } catch { /* unblock the other copy */ }
                    try { tunnelStream.Close(); } catch { /* unblock the other copy */ }
                    try { await Task.WhenAll(clientToTunnel, tunnelToClient).ConfigureAwait(false); }
                    catch { /* expected: one or both sides threw on the forced close */ }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Forwarded session to {Host}:{Port} ended with exception.", _targetHost, _targetPort);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try { _cts.Cancel(); } catch { /* best effort */ }
        try { _listener.Stop(); } catch { /* best effort */ }
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); } catch { /* swallowed in loop */ }
        }
        Task[] handlers;
        lock (_handlersGate) handlers = _handlers.ToArray();
        if (handlers.Length > 0)
        {
            try { await Task.WhenAll(handlers).ConfigureAwait(false); } catch { /* per-handler errors logged inside */ }
        }
        _cts.Dispose();
    }
}
