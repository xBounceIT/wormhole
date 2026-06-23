using Wormhole.Services;
using Xunit;

namespace Wormhole.Tests.Services;

public class VncSessionClosedEventReplayTests
{
    [Fact]
    public void Closed_ReplaysTerminalEventToLateSubscriber()
    {
        var sender = new object();
        var replay = new VncSessionClosedEventReplay(sender);
        var args = new VncSessionClosedEventArgs(isClean: true, "closed");

        Assert.True(replay.TryRaise(args));
        object? observedSender = null;
        VncSessionClosedEventArgs? observedArgs = null;
        replay.Closed += (s, e) =>
        {
            observedSender = s;
            observedArgs = e;
        };

        Assert.Same(sender, observedSender);
        Assert.Same(args, observedArgs);
    }

    [Fact]
    public void TryRaise_IgnoresLaterTerminalEvents()
    {
        var replay = new VncSessionClosedEventReplay(new object());
        var first = new VncSessionClosedEventArgs(isClean: true, "closed");
        var second = new VncSessionClosedEventArgs(isClean: false, "interrupted");
        var callCount = 0;
        VncSessionClosedEventArgs? observedArgs = null;
        replay.Closed += (_, e) =>
        {
            callCount++;
            observedArgs = e;
        };

        Assert.True(replay.TryRaise(first));
        Assert.False(replay.TryRaise(second));

        Assert.Equal(1, callCount);
        Assert.Same(first, observedArgs);
    }

    [Fact]
    public void Dispose_ClearsSubscribersAndSuppressesReplay()
    {
        var replay = new VncSessionClosedEventReplay(new object());
        var callCount = 0;
        replay.Closed += (_, _) => callCount++;

        replay.Dispose();

        Assert.False(replay.TryRaise(new VncSessionClosedEventArgs(isClean: true, "closed")));
        replay.Closed += (_, _) => callCount++;
        Assert.Equal(0, callCount);
    }
}
