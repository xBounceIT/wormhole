using System;
using System.Collections.Generic;
using System.Threading;
using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalOutputCoalescerTests
{
    private sealed class Recorder
    {
        public List<byte[]> Posts { get; } = new();
        public int DelayedArmCount;
        public int ImmediateArmCount;

        public bool Post(ReadOnlyMemory<byte> data)
        {
            Posts.Add(data.ToArray());
            return true;
        }

        public void ArmTimer() => DelayedArmCount++;
        public void ArmImmediateFlush() => ImmediateArmCount++;
    }

    [Fact]
    public void Append_SmallChunkArmsImmediateFlushButDoesNotPostInline()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);

        c.Append(new byte[] { 1, 2, 3 });

        Assert.Empty(recorder.Posts);
        Assert.True(c.HasPending);
        Assert.Equal(0, recorder.DelayedArmCount);
        Assert.Equal(1, recorder.ImmediateArmCount);
    }

    [Fact]
    public void Flush_PostsAccumulatedBytesAsSingleBatch()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);

        c.Append(new byte[] { 1, 2, 3 });
        c.Append(new byte[] { 4, 5 });
        c.Append(new byte[] { 6 });
        c.Flush();

        Assert.Single(recorder.Posts);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6 }, recorder.Posts[0]);
        Assert.False(c.HasPending);
    }

    [Fact]
    public void ImmediateFlush_PostsPromptBytesAndThenCoalescesFollowUpBurst()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);

        c.Append(new byte[] { 1 });
        c.FlushImmediately();

        Assert.Single(recorder.Posts);
        Assert.Equal(new byte[] { 1 }, recorder.Posts[0]);
        Assert.Equal(1, recorder.ImmediateArmCount);
        Assert.Equal(1, recorder.DelayedArmCount);

        c.Append(new byte[] { 2 });
        c.Append(new byte[] { 3 });
        Assert.Equal(1, recorder.DelayedArmCount);
        Assert.Equal(1, recorder.ImmediateArmCount);

        c.Flush();

        Assert.Equal(2, recorder.Posts.Count);
        Assert.Equal(new byte[] { 2, 3 }, recorder.Posts[1]);

        // After the delayed flush the next small append can take the low-latency path again.
        c.Append(new byte[] { 4 });
        Assert.Equal(2, recorder.ImmediateArmCount);
    }

    [Fact]
    public void LargeFirstAppend_ArmsDelayedFlush()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);

        c.Append(new byte[4096]);

        Assert.Empty(recorder.Posts);
        Assert.True(c.HasPending);
        Assert.Equal(1, recorder.DelayedArmCount);
        Assert.Equal(0, recorder.ImmediateArmCount);
    }

    [Fact]
    public void DelayedArm_IsCalledOnlyOnEmptyToBufferedTransition()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);
        var payload = new byte[4096];

        c.Append(payload);
        c.Append(new byte[] { 2 });
        c.Append(new byte[] { 3 });
        Assert.Equal(1, recorder.DelayedArmCount);

        c.Flush();
        Assert.Equal(1, recorder.DelayedArmCount);

        // After flush the next large append must re-arm: the dispatcher timer was a one-shot
        // and the coalescer's scheduled-flush flag was cleared.
        c.Append(payload);
        Assert.Equal(2, recorder.DelayedArmCount);
    }

    [Fact]
    public void Flush_WhenEmpty_IsNoOp()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);

        c.Flush();
        c.Flush();

        Assert.Empty(recorder.Posts);
        Assert.Equal(0, recorder.DelayedArmCount);
        Assert.Equal(0, recorder.ImmediateArmCount);
    }

    [Fact]
    public void Suspend_DropsBufferedBytesAndIgnoresSubsequentAppend()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);

        c.Append(new byte[] { 1, 2 });
        c.Suspend();
        c.Append(new byte[] { 3, 4 });
        c.Flush();

        Assert.Empty(recorder.Posts);
        Assert.False(c.HasPending);
    }

    [Fact]
    public void Resume_AfterSuspend_AcceptsNewAppends()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);

        c.Append(new byte[] { 1 });
        c.Suspend();
        c.Resume();
        c.Append(new byte[] { 9, 8, 7 });
        c.Flush();

        Assert.Single(recorder.Posts);
        Assert.Equal(new byte[] { 9, 8, 7 }, recorder.Posts[0]);
    }

    [Fact]
    public void Append_EmptySpan_IsNoOp()
    {
        var recorder = new Recorder();
        using var c = Create(recorder);

        c.Append(ReadOnlySpan<byte>.Empty);

        Assert.Empty(recorder.Posts);
        Assert.False(c.HasPending);
        Assert.Equal(0, recorder.DelayedArmCount);
        Assert.Equal(0, recorder.ImmediateArmCount);
    }

    [Fact]
    public void Dispose_DropsBufferedBytesAndFlushBecomesNoOp()
    {
        var recorder = new Recorder();
        var c = Create(recorder);

        c.Append(new byte[] { 1, 2, 3 });
        c.Dispose();
        c.Flush();
        c.Append(new byte[] { 4 });

        Assert.Empty(recorder.Posts);
        Assert.False(c.HasPending);
    }

    [Fact]
    public void Append_GrowsBufferToFitLargeBurst()
    {
        // Initial capacity is 8 KiB; a 64 KiB burst forces resizes. The point is that
        // all bytes are preserved in order, regardless of internal capacity growth.
        var recorder = new Recorder();
        using var c = Create(recorder);

        const int total = 64 * 1024;
        var payload = new byte[total];
        for (var i = 0; i < total; i++) payload[i] = (byte)(i & 0xFF);

        c.Append(payload);
        c.Flush();

        Assert.Single(recorder.Posts);
        Assert.Equal(payload, recorder.Posts[0]);
    }

    [Fact]
    public void Append_ConcurrentWritersFromMultipleThreads_AllBytesEventuallyFlushed()
    {
        // Sanity check that Append's locking holds under concurrent writers — mirrors
        // the SSH read-pump (single writer) plus a stray test/teardown call from the
        // UI thread.
        var recorder = new Recorder();
        using var c = Create(recorder);

        const int perThread = 1024;
        var t1Bytes = new byte[perThread];
        var t2Bytes = new byte[perThread];
        for (var i = 0; i < perThread; i++) t1Bytes[i] = 1;
        for (var i = 0; i < perThread; i++) t2Bytes[i] = 2;

        var t1 = new Thread(() => { foreach (var b in t1Bytes) c.Append(new[] { b }); });
        var t2 = new Thread(() => { foreach (var b in t2Bytes) c.Append(new[] { b }); });
        t1.Start(); t2.Start();
        t1.Join(); t2.Join();

        c.Flush();

        Assert.Single(recorder.Posts);
        var posted = recorder.Posts[0];
        Assert.Equal(perThread * 2, posted.Length);
        var ones = 0;
        var twos = 0;
        foreach (var b in posted)
        {
            if (b == 1) ones++;
            else if (b == 2) twos++;
            else Assert.Fail($"Unexpected byte value {b}");
        }
        Assert.Equal(perThread, ones);
        Assert.Equal(perThread, twos);
    }

    private static TerminalOutputCoalescer Create(Recorder recorder) =>
        new(recorder.Post, recorder.ArmTimer, recorder.ArmImmediateFlush);
}
