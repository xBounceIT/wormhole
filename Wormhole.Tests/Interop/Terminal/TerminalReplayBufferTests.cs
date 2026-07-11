using System;
using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalReplayBufferTests
{
    [Fact]
    public void Snapshot_EmptyBuffer_ReturnsEmpty()
    {
        var buffer = new TerminalReplayBuffer(16);

        Assert.Empty(buffer.Snapshot());
    }

    [Fact]
    public void Append_UnderCapacity_RetainsAllBytesInOrder()
    {
        var buffer = new TerminalReplayBuffer(16);

        buffer.Append(new byte[] { 1, 2, 3 });
        buffer.Append(new byte[] { 4, 5 });

        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, buffer.Snapshot());
    }

    [Fact]
    public void Append_ExactlyAtCapacity_FillsBufferLinearly()
    {
        var buffer = new TerminalReplayBuffer(4);

        buffer.Append(new byte[] { 1, 2, 3, 4 });

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, buffer.Snapshot());
    }

    [Fact]
    public void Append_OverflowingWrite_KeepsOnlyTail()
    {
        var buffer = new TerminalReplayBuffer(4);

        buffer.Append(new byte[] { 1, 2, 3, 4, 5, 6, 7 });

        Assert.Equal(new byte[] { 4, 5, 6, 7 }, buffer.Snapshot());
    }

    [Fact]
    public void Append_WrapsAcrossEndOfBuffer()
    {
        var buffer = new TerminalReplayBuffer(4);

        buffer.Append(new byte[] { 1, 2, 3 });
        buffer.Append(new byte[] { 4, 5 });

        // Wrapped: oldest is 2 (1 was evicted), newest is 5.
        Assert.Equal(new byte[] { 2, 3, 4, 5 }, buffer.Snapshot());
    }

    [Fact]
    public void Append_MultipleWrapsAroundBuffer()
    {
        var buffer = new TerminalReplayBuffer(4);

        for (byte b = 1; b <= 10; b++)
        {
            buffer.Append(new[] { b });
        }

        Assert.Equal(new byte[] { 7, 8, 9, 10 }, buffer.Snapshot());
    }

    [Fact]
    public void Append_EmptySpan_IsNoOp()
    {
        var buffer = new TerminalReplayBuffer(4);
        buffer.Append(new byte[] { 1, 2 });

        buffer.Append(ReadOnlySpan<byte>.Empty);

        Assert.Equal(new byte[] { 1, 2 }, buffer.Snapshot());
    }

    [Fact]
    public void Snapshot_ReturnsIndependentCopy()
    {
        var buffer = new TerminalReplayBuffer(4);
        buffer.Append(new byte[] { 1, 2, 3 });

        var snapshot = buffer.Snapshot();
        snapshot[0] = 99;

        Assert.Equal(new byte[] { 1, 2, 3 }, buffer.Snapshot());
    }

    [Fact]
    public void Clear_DropsAllRetainedBytes()
    {
        var buffer = new TerminalReplayBuffer(4);
        buffer.Append(new byte[] { 1, 2, 3 });

        buffer.Clear();

        Assert.Empty(buffer.Snapshot());
    }

    [Fact]
    public void Drain_ReturnsSnapshotAndClearsBuffer()
    {
        var buffer = new TerminalReplayBuffer(4);
        buffer.Append(new byte[] { 1, 2, 3 });

        var drained = buffer.Drain();

        Assert.Equal(new byte[] { 1, 2, 3 }, drained);
        Assert.Empty(buffer.Snapshot());
    }

    [Fact]
    public void Drain_AfterWrap_ReturnsBytesInOrder()
    {
        var buffer = new TerminalReplayBuffer(4);
        buffer.Append(new byte[] { 1, 2, 3 });
        buffer.Append(new byte[] { 4, 5 });

        var drained = buffer.Drain();

        Assert.Equal(new byte[] { 2, 3, 4, 5 }, drained);
        Assert.Empty(buffer.Snapshot());
    }

    [Fact]
    public void Clear_AfterWrap_AllowsCleanAppendAgain()
    {
        var buffer = new TerminalReplayBuffer(4);
        buffer.Append(new byte[] { 1, 2, 3, 4, 5 });

        buffer.Clear();
        buffer.Append(new byte[] { 9, 8 });

        Assert.Equal(new byte[] { 9, 8 }, buffer.Snapshot());
    }

    [Fact]
    public void TruncationFlag_DistinguishesExactReplayFromOverwrittenTailAndResets()
    {
        var buffer = new TerminalReplayBuffer(4);
        buffer.Append(new byte[] { 1, 2, 3, 4 });
        Assert.False(buffer.HasTruncated);

        buffer.Append(new byte[] { 5 });
        Assert.True(buffer.HasTruncated);
        Assert.Equal(new byte[] { 2, 3, 4, 5 }, buffer.Drain());
        Assert.False(buffer.HasTruncated);

        buffer.Append(new byte[] { 1, 2, 3, 4, 5 });
        Assert.True(buffer.HasTruncated);
        buffer.Clear();
        Assert.False(buffer.HasTruncated);
    }

    [Fact]
    public void Prepend_UnderCapacity_PlacesOlderBytesBeforeDetachedSuffix()
    {
        var buffer = new TerminalReplayBuffer(8);
        buffer.Append(new byte[] { 4, 5 });

        buffer.Prepend(new byte[] { 1, 2, 3 });

        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, buffer.Snapshot());
        Assert.False(buffer.HasTruncated);
    }

    [Fact]
    public void Prepend_Overflow_KeepsCombinedNewestTailAndMarksReplayInexact()
    {
        var buffer = new TerminalReplayBuffer(5);
        buffer.Append(new byte[] { 5, 6, 7 });

        buffer.Prepend(new byte[] { 1, 2, 3, 4 });

        Assert.Equal(new byte[] { 3, 4, 5, 6, 7 }, buffer.Snapshot());
        Assert.True(buffer.HasTruncated);
    }

    [Fact]
    public void Prepend_ToFullNewerSuffix_DropsOlderBytesAndPreservesSuffix()
    {
        var buffer = new TerminalReplayBuffer(4);
        buffer.Append(new byte[] { 5, 6, 7, 8 });

        buffer.Prepend(new byte[] { 1, 2 });

        Assert.Equal(new byte[] { 5, 6, 7, 8 }, buffer.Snapshot());
        Assert.True(buffer.HasTruncated);
    }

    [Fact]
    public void Append_AfterPrepend_PreservesFifoAndNormalRingTailSemantics()
    {
        var buffer = new TerminalReplayBuffer(6);
        buffer.Append(new byte[] { 4, 5 });
        buffer.Prepend(new byte[] { 1, 2, 3 });

        buffer.Append(new byte[] { 6, 7 });

        Assert.Equal(new byte[] { 2, 3, 4, 5, 6, 7 }, buffer.Snapshot());
        Assert.True(buffer.HasTruncated);
    }

    [Fact]
    public void EmptyPrepend_PreservesPriorTruncationState()
    {
        var buffer = new TerminalReplayBuffer(2);
        buffer.Append(new byte[] { 1, 2, 3 });
        Assert.True(buffer.HasTruncated);

        buffer.Prepend(ReadOnlySpan<byte>.Empty);

        Assert.True(buffer.HasTruncated);
        Assert.Equal(new byte[] { 2, 3 }, buffer.Snapshot());
    }

    [Fact]
    public void Constructor_RejectsNonPositiveCapacity()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalReplayBuffer(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TerminalReplayBuffer(-1));
    }

    [Fact]
    public void Append_LargeChunkedFill_RetainsTailWithCorrectByteValues()
    {
        // Larger pattern exercise: chunked fills crossing the wrap point produce a
        // snapshot equal to the tail of the cumulative input.
        const int capacity = 1024;
        const int chunkSize = 128;
        const int total = capacity + chunkSize * 3;
        var sent = new byte[total];
        for (var i = 0; i < total; i++) sent[i] = (byte)(i & 0xFF);

        var buffer = new TerminalReplayBuffer(capacity);
        for (var offset = 0; offset < total; offset += chunkSize)
        {
            buffer.Append(sent.AsSpan(offset, chunkSize));
        }

        var expectedTail = new byte[capacity];
        Array.Copy(sent, total - capacity, expectedTail, 0, capacity);
        Assert.Equal(expectedTail, buffer.Snapshot());
    }
}
