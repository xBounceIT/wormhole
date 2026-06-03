using System;
using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalFlowControllerTests
{
    // Mirrors the watermarks TerminalBridge uses in production.
    private const int High = 512 * 1024;
    private const int Low = 128 * 1024;

    private static TerminalFlowController Create() => new(High, Low);

    [Fact]
    public void Constructor_RejectsNonPositiveHighWatermark()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalFlowController(0, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalFlowController(-1, -2));
    }

    [Fact]
    public void Constructor_RejectsLowWatermarkNotStrictlyBelowHigh()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalFlowController(100, 100));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalFlowController(100, 200));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalFlowController(100, -1));
    }

    [Fact]
    public void OnPosted_BelowHighWatermark_DoesNotPause()
    {
        var c = Create();

        Assert.False(c.OnPosted(High - 1));

        Assert.False(c.IsPaused);
        Assert.Equal((long)(High - 1), c.Outstanding);
    }

    [Fact]
    public void OnPosted_AtOrAboveHighWatermark_SignalsPauseExactlyOnce()
    {
        var c = Create();

        Assert.False(c.OnPosted(Low));     // accumulates below high
        Assert.True(c.OnPosted(High));     // crosses high -> pause transition
        Assert.True(c.IsPaused);

        // Already paused: further posts accumulate but must not re-signal a pause.
        Assert.False(c.OnPosted(High));
        Assert.True(c.IsPaused);
    }

    [Fact]
    public void OnAcked_WhileNotPaused_NeverSignalsResume()
    {
        var c = Create();
        c.OnPosted(Low);

        Assert.False(c.OnAcked(Low));

        Assert.False(c.IsPaused);
        Assert.Equal(0L, c.Outstanding);
    }

    [Fact]
    public void OnAcked_DrainingTowardLowWatermark_ResumesOnlyWhenItCrossesLow()
    {
        var c = Create();
        Assert.True(c.OnPosted(High + Low));   // 640 KiB outstanding -> paused
        Assert.True(c.IsPaused);

        Assert.False(c.OnAcked(400 * 1024));   // 240 KiB left, still > Low -> stay paused
        Assert.True(c.IsPaused);

        Assert.True(c.OnAcked(200 * 1024));    // 40 KiB left, <= Low -> resume transition
        Assert.False(c.IsPaused);

        Assert.False(c.OnAcked(40 * 1024));    // already running -> no re-signal
        Assert.False(c.IsPaused);
        Assert.Equal(0L, c.Outstanding);
    }

    [Fact]
    public void OnAcked_OverAck_ClampsOutstandingAtZero()
    {
        var c = Create();
        c.OnPosted(1000);

        c.OnAcked(5000);   // acked more than was outstanding

        Assert.Equal(0L, c.Outstanding);
        Assert.False(c.IsPaused);
    }

    [Fact]
    public void OnPostedAndOnAcked_IgnoreNonPositiveCounts()
    {
        var c = Create();

        Assert.False(c.OnPosted(0));
        Assert.False(c.OnPosted(-5));
        Assert.Equal(0L, c.Outstanding);

        c.OnPosted(1000);
        Assert.False(c.OnAcked(0));
        Assert.False(c.OnAcked(-5));
        Assert.Equal(1000L, c.Outstanding);
    }

    [Fact]
    public void Reset_WhenPaused_ReturnsTrueAndClears()
    {
        var c = Create();
        c.OnPosted(High);
        Assert.True(c.IsPaused);

        Assert.True(c.Reset());

        Assert.False(c.IsPaused);
        Assert.Equal(0L, c.Outstanding);
    }

    [Fact]
    public void Reset_WhenRunning_ReturnsFalseAndClears()
    {
        var c = Create();
        c.OnPosted(1000);

        Assert.False(c.Reset());

        Assert.False(c.IsPaused);
        Assert.Equal(0L, c.Outstanding);
    }

    [Fact]
    public void InteractiveEchoSizedTraffic_NeverPauses()
    {
        // The low-latency echo path: many tiny writes, each promptly acked. Must never trip the
        // high watermark, so flow control stays dormant during normal interactive use.
        var c = Create();

        for (var i = 0; i < 10_000; i++)
        {
            Assert.False(c.OnPosted(8));   // keystroke echo
            Assert.False(c.OnAcked(8));    // xterm parses it immediately
        }

        Assert.False(c.IsPaused);
        Assert.Equal(0L, c.Outstanding);
    }

    [Fact]
    public void SustainedBurst_PausesThenResumesAsXtermDrains()
    {
        // A flood: posts outrun acks until the window fills (pause), then acks drain it back below
        // the low mark (resume) — the throttle cycle that paces the SSH read pump under tcpdump.
        var c = Create();

        var paused = false;
        for (var i = 0; i < 8; i++)
        {
            if (c.OnPosted(100 * 1024)) paused = true;   // 8 x 100 KiB posted, no acks yet
        }
        Assert.True(paused);
        Assert.True(c.IsPaused);

        var resumed = false;
        for (var i = 0; i < 8; i++)
        {
            if (c.OnAcked(100 * 1024)) resumed = true;   // xterm catches up
        }
        Assert.True(resumed);
        Assert.False(c.IsPaused);
        Assert.Equal(0L, c.Outstanding);
    }
}
