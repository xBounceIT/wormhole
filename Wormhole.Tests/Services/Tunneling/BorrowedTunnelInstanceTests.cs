using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class BorrowedTunnelInstanceTests
{
    [Fact]
    public async Task DisposeAsync_DoesNotDisposeInner()
    {
        var inner = new RecordingTunnel();
        var borrowed = new BorrowedTunnelInstance(inner);

        await borrowed.DisposeAsync();
        await borrowed.DisposeAsync(); // idempotent + still never touches the inner

        Assert.Equal(0, inner.DisposeCount);
    }

    [Fact]
    public void ForwardsEndpointAndState()
    {
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1080);
        var inner = new RecordingTunnel { Endpoint = endpoint, StateValue = TunnelState.Up };
        var borrowed = new BorrowedTunnelInstance(inner);

        Assert.Same(endpoint, borrowed.Socks5Endpoint);
        Assert.Equal(TunnelState.Up, borrowed.State);
    }

    [Fact]
    public async Task ForwardsBindLocalForwarder()
    {
        var inner = new RecordingTunnel();
        var borrowed = new BorrowedTunnelInstance(inner);

        var port = await borrowed.BindLocalForwarderAsync("host.example", 22, CancellationToken.None);

        Assert.Equal(("host.example", 22), inner.LastBind);
        Assert.Equal(12345, port);
    }

    [Fact]
    public void Ctor_NullInner_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new BorrowedTunnelInstance(null!));

    [Fact]
    public async Task DisposeAsync_InvokesOnDisposeExactlyOnce()
    {
        // onDispose carries TunnelManager's ref-count release — a double dispose (disconnect then
        // close walking the same teardown) must release exactly one ref and never touch the inner.
        var inner = new RecordingTunnel();
        int released = 0;
        var borrowed = new BorrowedTunnelInstance(inner, onDispose: () =>
        {
            Interlocked.Increment(ref released);
            return ValueTask.CompletedTask;
        });

        await borrowed.DisposeAsync();
        await borrowed.DisposeAsync();

        Assert.Equal(1, released);
        Assert.Equal(0, inner.DisposeCount);
    }

    [Fact]
    public async Task DisposeAsync_DetachesForwardedStateChangedHandlers()
    {
        // A borrower may subscribe to StateChanged through the borrow; disposing the borrow must unsubscribe
        // it from the (longer-lived) inner tunnel so the handler doesn't outlive the borrow.
        var inner = new RecordingTunnel();
        var borrowed = new BorrowedTunnelInstance(inner);
        void Handler(object? s, TunnelStateChangedEventArgs e) { }

        borrowed.StateChanged += Handler;
        Assert.Equal(1, inner.StateChangedSubscribers);

        await borrowed.DisposeAsync();
        Assert.Equal(0, inner.StateChangedSubscribers); // detached, even though the inner itself is not disposed
        Assert.Equal(0, inner.DisposeCount);
    }

}
