using System;
using System.IO;
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
    public async Task FailureSignal_TransitionsToFailed_AndRejectsNewWork()
    {
        var failed = new TaskCompletionSource<int?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var changed = new TaskCompletionSource<TunnelStateChangedEventArgs>(TaskCreationOptions.RunContinuationsAsynchronously);
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1);
        var instance = new SocksTunnelInstance(
            endpoint,
            NullLogger<SocksTunnelInstance>.Instance,
            failureSignal: failed.Task);
        instance.StateChanged += (_, e) => changed.TrySetResult(e);

        failed.SetResult(42);

        var args = await changed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(TunnelState.Failed, args.State);
        Assert.NotNull(args.Message);
        Assert.Contains("42", args.Message);
        Assert.Equal(TunnelState.Failed, instance.State);
        await Assert.ThrowsAsync<IOException>(() =>
            instance.DialAsync("example.invalid", 443, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() =>
            instance.BindLocalForwarderAsync("example.invalid", 443, CancellationToken.None));

        await instance.DisposeAsync();
    }

    [Fact]
    public async Task DisposeAsync_BeforeFailureSignal_CompletesAsClosed()
    {
        var failed = new TaskCompletionSource<int?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var states = new System.Collections.Generic.List<TunnelState>();
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1);
        var instance = new SocksTunnelInstance(
            endpoint,
            NullLogger<SocksTunnelInstance>.Instance,
            failureSignal: failed.Task);
        instance.StateChanged += (_, e) => states.Add(e.State);

        await instance.DisposeAsync();
        failed.SetResult(42);
        await Task.Delay(50);

        Assert.Equal(TunnelState.Closed, instance.State);
        Assert.Equal(new[] { TunnelState.Closed }, states);
    }

    [Fact]
    public async Task BindLocalForwarderAsync_AfterDispose_Throws()
    {
        // Post-dispose contract: a Bind issued after a completed Dispose throws and binds no
        // listener (the disposed check runs under the same gate that guards the forwarder list,
        // so no listener can be created past it).
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1);
        var instance = new SocksTunnelInstance(endpoint, NullLogger<SocksTunnelInstance>.Instance);
        await instance.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            instance.BindLocalForwarderAsync("127.0.0.1", 80, CancellationToken.None));
    }

    [Fact]
    public async Task BindLocalForwarderAsync_ReusesListener_ForSameTarget()
    {
        // The tunnel instance is shared across connections (TunnelManager pools it per config), so
        // forwarders live for the whole tunnel's lifetime. Binding the same target twice must hand
        // back the existing listener instead of stacking a new one per connect.
        var endpoint = new IPEndPoint(IPAddress.Loopback, 1);
        var instance = new SocksTunnelInstance(endpoint, NullLogger<SocksTunnelInstance>.Instance);
        try
        {
            var port1 = await instance.BindLocalForwarderAsync("host.internal", 3389, CancellationToken.None);
            var samePort = await instance.BindLocalForwarderAsync("HOST.INTERNAL", 3389, CancellationToken.None);
            var otherPort = await instance.BindLocalForwarderAsync("host.internal", 22, CancellationToken.None);

            Assert.Equal(port1, samePort); // hostnames are case-insensitive
            Assert.NotEqual(port1, otherPort);
        }
        finally
        {
            await instance.DisposeAsync();
        }
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
