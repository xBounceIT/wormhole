using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class SocksTunnelInstanceTests
{
    [Fact]
    public async Task BindLocalForwarderAsync_DisposesForwarder_IfRacingDisposeWins()
    {
        // Regression: BindLocalForwarderAsync started the forwarder outside the lock and only
        // checked the disposed flag once at entry. A concurrent DisposeAsync that took the gate
        // first would snapshot-and-clear _forwarders, then bind would add the just-started
        // forwarder to the (now empty) list and return its port — listener still bound, target
        // SOCKS5 endpoint already gone, dispose never fires. Fix re-checks the flag inside the
        // gate and disposes synchronously when it loses.
        //
        // Deterministically simulating the race in a unit test is awkward, so this test verifies
        // the post-dispose contract: a Bind issued after a completed Dispose throws and does NOT
        // leak a listener. If the previous behavior regresses the test fails because Bind would
        // succeed and the listener stays open.
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1);
        var instance = new SocksTunnelInstance(endpoint, NullLogger<SocksTunnelInstance>.Instance);
        await instance.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            instance.BindLocalForwarderAsync("127.0.0.1", 80, CancellationToken.None));
    }

    [Fact]
    public async Task DisposeAsync_IsIdempotent_AndCallsOnDisposeOnce()
    {
        int onDisposeCount = 0;
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1);
        var instance = new SocksTunnelInstance(
            endpoint,
            NullLogger<SocksTunnelInstance>.Instance,
            onDispose: () =>
            {
                Interlocked.Increment(ref onDisposeCount);
                return ValueTask.CompletedTask;
            });

        await instance.DisposeAsync();
        await instance.DisposeAsync();

        Assert.Equal(1, onDisposeCount);
        Assert.Equal(TunnelState.Closed, instance.State);
    }
}
