using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;
using Wormhole.Services.Tunneling;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// Recording <see cref="ITunnelInstance"/> fake shared by the tunnel test suites: counts disposals
/// (thread-safe — the pool disposes from worker threads), exposes a settable endpoint/state, can
/// raise <see cref="StateChanged"/>, and completes <see cref="Disposed"/> so tests can await a
/// disposal that happens on another thread instead of polling.
/// </summary>
internal sealed class RecordingTunnel : ITunnelInstance
{
    private int _disposeCount;
    public int DisposeCount => Volatile.Read(ref _disposeCount);

    public IPEndPoint? Endpoint;
    public TunnelState StateValue = TunnelState.Up;
    public (string Host, int Port)? LastBind;

    /// <summary>Completed by the first <see cref="DisposeAsync"/>.</summary>
    public TaskCompletionSource Disposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private EventHandler<TunnelStateChangedEventArgs>? _stateChanged;
    public int StateChangedSubscribers => _stateChanged?.GetInvocationList().Length ?? 0;

    public TunnelState State => StateValue;

    public event EventHandler<TunnelStateChangedEventArgs>? StateChanged
    {
        add => _stateChanged += value;
        remove => _stateChanged -= value;
    }

    public IPEndPoint? Socks5Endpoint => Endpoint;

    public void RaiseState(TunnelState state)
    {
        StateValue = state;
        _stateChanged?.Invoke(this, new TunnelStateChangedEventArgs(state));
    }

    public Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken) =>
        Task.FromResult<Stream>(new MemoryStream());

    public Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken)
    {
        LastBind = (host, port);
        return Task.FromResult(12345);
    }

    public ValueTask DisposeAsync()
    {
        Interlocked.Increment(ref _disposeCount);
        StateValue = TunnelState.Closed;
        Disposed.TrySetResult();
        return ValueTask.CompletedTask;
    }
}
