using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Generic <see cref="ITunnelInstance"/> backed by a local SOCKS5 endpoint. Any provider whose
/// userspace stack exposes SOCKS5 on 127.0.0.1 (current: wireguard-go sidecar; future: OpenVPN /
/// vendor sidecars; plain SOCKS5 / HTTP CONNECT external proxies) wraps itself in this.
/// </summary>
public sealed class SocksTunnelInstance : ITunnelInstance
{
    private readonly IPEndPoint _socksEndpoint;
    private readonly ILogger _logger;
    private readonly Func<ValueTask>? _onDispose;
    private readonly List<LocalTcpForwarder> _forwarders = new();
    private readonly object _gate = new();
    private int _disposedFlag;

    public SocksTunnelInstance(IPEndPoint socksEndpoint, ILogger logger, Func<ValueTask>? onDispose = null)
    {
        _socksEndpoint = socksEndpoint ?? throw new ArgumentNullException(nameof(socksEndpoint));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _onDispose = onDispose;
    }

    public TunnelState State => Volatile.Read(ref _disposedFlag) != 0 ? TunnelState.Closed : TunnelState.Up;

    public event EventHandler<TunnelStateChangedEventArgs>? StateChanged;

    public IPEndPoint? Socks5Endpoint => _socksEndpoint;

    public async Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        return await Socks5Client.ConnectAsync(_socksEndpoint, host, port, cancellationToken).ConfigureAwait(false);
    }

    public Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var fwd = LocalTcpForwarder.Start(this, host, port, _logger);
        lock (_gate) _forwarders.Add(fwd);
        return Task.FromResult(fwd.LocalPort);
    }

    public async ValueTask DisposeAsync()
    {
        // Interlocked guard makes DisposeAsync idempotent under concurrent calls — the
        // sidecar process tear-down (via _onDispose) must run exactly once.
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;

        LocalTcpForwarder[] fwds;
        lock (_gate) { fwds = _forwarders.ToArray(); _forwarders.Clear(); }
        foreach (var fwd in fwds)
        {
            try { await fwd.DisposeAsync().ConfigureAwait(false); } catch (Exception ex) { _logger.LogDebug(ex, "Forwarder dispose failed."); }
        }
        StateChanged?.Invoke(this, new TunnelStateChangedEventArgs(TunnelState.Closed));
        if (_onDispose is not null)
        {
            try { await _onDispose().ConfigureAwait(false); } catch (Exception ex) { _logger.LogWarning(ex, "Tunnel onDispose hook failed."); }
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposedFlag) != 0) throw new ObjectDisposedException(nameof(SocksTunnelInstance));
    }
}
