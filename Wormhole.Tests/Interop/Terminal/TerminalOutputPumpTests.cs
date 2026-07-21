using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalOutputPumpTests
{
    [Fact]
    public void Constructor_RejectsInvalidConfiguration()
    {
        static bool Sink(long _, ReadOnlyMemory<byte> __) => true;
        static void NoOp() { }

        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TerminalOutputPump(0, 0, 1, 0, Sink, NoOp, NoOp));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TerminalOutputPump(10, -1, 1, 0, Sink, NoOp, NoOp));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TerminalOutputPump(10, 10, 1, 0, Sink, NoOp, NoOp));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TerminalOutputPump(10, 2, 0, 0, Sink, NoOp, NoOp));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TerminalOutputPump(10, 2, 11, 0, Sink, NoOp, NoOp));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TerminalOutputPump(10, 2, 4, -1, Sink, NoOp, NoOp));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TerminalOutputPump(
                10, 2, 4, 1, Sink, NoOp, NoOp, maximumBacklogBytes: 9));
        Assert.Throws<ArgumentNullException>(
            () => new TerminalOutputPump(10, 2, 4, 1, null!, NoOp, NoOp));
        Assert.Throws<ArgumentNullException>(
            () => new TerminalOutputPump(10, 2, 4, 1, Sink, null!, NoOp));
        Assert.Throws<ArgumentNullException>(
            () => new TerminalOutputPump(10, 2, 4, 1, Sink, NoOp, null!));
    }

    [Fact]
    public void Seal_RejectsNewBytesButDrainsAndAcknowledgesAcceptedPrefix()
    {
        var posted = new List<(long Id, byte[] Data)>();
        var pump = new TerminalOutputPump(
            highWatermarkBytes: 16,
            lowWatermarkBytes: 4,
            maxFrameBytes: 4,
            immediateThresholdBytes: 4,
            (id, data) =>
            {
                posted.Add((id, data.ToArray()));
                return true;
            },
            () => { },
            () => { });

        Assert.Equal(
            TerminalDrainRequest.Delayed,
            pump.Enqueue(new byte[] { 1, 2, 3, 4, 5, 6 }));
        var acceptedSequence = pump.EnqueuedSequence;

        pump.Seal();

        Assert.True(pump.IsSealed);
        Assert.Equal(TerminalDrainRequest.None, pump.Enqueue(new byte[] { 7, 8 }));
        Assert.Equal(acceptedSequence, pump.EnqueuedSequence);

        pump.Drain();
        Assert.Equal(
            new byte[][] { new byte[] { 1, 2, 3, 4 }, new byte[] { 5, 6 } },
            posted.Select(frame => frame.Data));
        foreach (var frame in posted)
        {
            pump.Acknowledge(frame.Id);
        }

        Assert.Equal(0, pump.BacklogBytes);
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void HardBacklogFailure_IgnoresLateAcksAndStaysPausedUntilDispose()
    {
        var failures = new List<Exception>();
        var pauseCount = 0;
        var resumeCount = 0;
        var pump = new TerminalOutputPump(
            highWatermarkBytes: 4,
            lowWatermarkBytes: 1,
            maxFrameBytes: 4,
            immediateThresholdBytes: 4,
            (_, _) => true,
            () => pauseCount++,
            () => resumeCount++,
            failures.Add,
            maximumBacklogBytes: 4);

        Assert.Equal(TerminalDrainRequest.Immediate, pump.Enqueue(new byte[4]));
        Assert.Equal(TerminalDrainRequest.None, pump.Drain());
        Assert.True(pump.IsProducerPaused);
        Assert.Equal(1, pauseCount);

        Assert.Equal(TerminalDrainRequest.None, pump.Enqueue(new byte[1]));

        Assert.True(pump.IsFailed);
        Assert.IsType<IOException>(Assert.Single(failures));
        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(1));
        Assert.Equal(4, pump.InFlightBytes);
        Assert.True(pump.IsProducerPaused);
        Assert.Equal(0, resumeCount);
        Assert.Equal(TerminalDrainRequest.None, pump.Drain());

        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
        Assert.Equal(1, resumeCount);
    }
    [Fact]
    public void ProducerControlExceptions_AreReportedWithoutEscapingOrCorruptingState()
    {
        var failures = new List<Exception>();
        var pauseFailure = new IOException("pause failed");
        var pausePump = new TerminalOutputPump(
            4,
            1,
            4,
            4,
            (_, _) => true,
            () => throw pauseFailure,
            () => { },
            failures.Add);

        pausePump.Enqueue(new byte[4]);

        Assert.Same(pauseFailure, Assert.Single(failures));
        Assert.False(pausePump.IsProducerPaused);

        failures.Clear();
        var resumeFailure = new IOException("resume failed");
        var resumePump = new TerminalOutputPump(
            4,
            1,
            4,
            4,
            (_, _) => true,
            () => { },
            () => throw resumeFailure,
            failures.Add);
        resumePump.Enqueue(new byte[4]);
        resumePump.Drain();

        resumePump.Acknowledge(1);

        Assert.Same(resumeFailure, Assert.Single(failures));
        Assert.False(resumePump.IsProducerPaused);
    }
    [Fact]
    public void Enqueue_RequestsImmediateForSmallFirstBatchAndDelayedForLargeBatch()
    {
        var small = CreatePump(
            high: 1024,
            low: 256,
            maxFrame: 256,
            immediateThreshold: 8,
            (_, _) => true);

        Assert.Equal(TerminalDrainRequest.None, small.Enqueue(ReadOnlySpan<byte>.Empty));
        Assert.Equal(TerminalDrainRequest.Immediate, small.Enqueue(new byte[8]));
        Assert.Equal(
            TerminalDrainRequest.None,
            small.Enqueue(new byte[1])); // one drain is already scheduled
        Assert.Equal(9, small.DisposeAndTakeRetirementState().UnpostedOutput.Length);

        var large = CreatePump(
            high: 1024,
            low: 256,
            maxFrame: 256,
            immediateThreshold: 8,
            (_, _) => true);

        Assert.Equal(TerminalDrainRequest.Delayed, large.Enqueue(new byte[9]));
        Assert.Equal(9, large.DisposeAndTakeRetirementState().UnpostedOutput.Length);
    }

    [Fact]
    public void Drain_PreservesFifoHonorsCreditAndAcknowledgesFramesExactlyOnce()
    {
        var posted = new List<PostedFrame>();
        var pauseCount = 0;
        var resumeCount = 0;
        var pump = new TerminalOutputPump(
            highWatermarkBytes: 10,
            lowWatermarkBytes: 3,
            maxFrameBytes: 4,
            immediateThresholdBytes: 2,
            (id, data) =>
            {
                posted.Add(new PostedFrame(id, data.ToArray()));
                return true;
            },
            () => pauseCount++,
            () => resumeCount++);
        var payload = Enumerable.Range(1, 12).Select(i => (byte)i).ToArray();

        Assert.Equal(TerminalDrainRequest.Delayed, pump.Enqueue(payload));
        Assert.Equal(1, pauseCount);
        Assert.True(pump.IsProducerPaused);
        Assert.Equal((ulong)12, pump.EnqueuedSequence);
        Assert.Equal((ulong)0, pump.PostedSequence);
        Assert.Equal(0, pump.LastPostedFrameId);

        Assert.Equal(TerminalDrainRequest.None, pump.Drain());

        Assert.Equal(2, pump.QueuedBytes);
        Assert.Equal(10, pump.InFlightBytes);
        Assert.Equal(12, pump.BacklogBytes);
        Assert.Equal(3, pump.InFlightFrameCount);
        Assert.Equal((ulong)10, pump.PostedSequence);
        Assert.Equal(3, pump.LastPostedFrameId);
        Assert.True(pump.IsFrameInFlight(1));
        Assert.True(pump.IsFrameInFlight(2));
        Assert.True(pump.IsFrameInFlight(3));
        Assert.False(pump.IsFrameInFlight(0));
        Assert.False(pump.IsFrameInFlight(4));
        Assert.Equal(4, pump.NextFrameId);
        Assert.Collection(
            posted,
            f => AssertFrame(f, 1, 1, 2, 3, 4),
            f => AssertFrame(f, 2, 5, 6, 7, 8),
            f => AssertFrame(f, 3, 9, 10));

        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(999));
        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(0));
        Assert.Equal(TerminalDrainRequest.Immediate, pump.Acknowledge(2));
        Assert.False(pump.IsFrameInFlight(2));
        Assert.True(pump.IsFrameInFlight(1));
        Assert.True(pump.IsFrameInFlight(3));
        Assert.Equal(3, pump.LastPostedFrameId);
        Assert.Equal(6, pump.InFlightBytes);
        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(2)); // duplicate

        Assert.Equal(TerminalDrainRequest.None, pump.Drain());
        Assert.Collection(
            posted,
            f => AssertFrame(f, 1, 1, 2, 3, 4),
            f => AssertFrame(f, 2, 5, 6, 7, 8),
            f => AssertFrame(f, 3, 9, 10),
            f => AssertFrame(f, 4, 11, 12));
        Assert.Equal(0, pump.QueuedBytes);
        Assert.Equal((ulong)12, pump.PostedSequence);
        Assert.Equal(4, pump.LastPostedFrameId);
        Assert.True(pump.IsFrameInFlight(4));
        Assert.Equal(8, pump.InFlightBytes);

        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(1));
        Assert.True(pump.IsProducerPaused); // four bytes remain, still above low=3
        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(3));
        Assert.False(pump.IsProducerPaused);
        Assert.Equal(1, resumeCount);
        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(4));
        Assert.Equal(0, pump.InFlightBytes);
        Assert.Equal(5, pump.NextFrameId);
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void Drain_FalseAndThrowingPostsKeepBytesAndReuseFrameId()
    {
        var attempts = 0;
        var posted = new List<PostedFrame>();
        Exception? postFailure = null;
        var pump = CreatePump(
            high: 16,
            low: 4,
            maxFrame: 8,
            immediateThreshold: 2,
            (id, data) =>
            {
                attempts++;
                if (attempts == 1) return false;
                if (attempts == 2) throw new IOException("simulated WebView failure");
                posted.Add(new PostedFrame(id, data.ToArray()));
                return true;
            },
            ex => postFailure = ex);
        var payload = new byte[] { 1, 2, 3, 4 };

        Assert.Equal(TerminalDrainRequest.Delayed, pump.Enqueue(payload));

        Assert.Equal(TerminalDrainRequest.Delayed, pump.Drain());
        Assert.Equal(4, pump.QueuedBytes);
        Assert.Equal(0, pump.InFlightBytes);
        Assert.Equal(1, pump.NextFrameId);
        Assert.Equal(0, pump.LastPostedFrameId);
        Assert.False(pump.IsFrameInFlight(1));
        Assert.Null(postFailure);

        Assert.Equal(TerminalDrainRequest.Delayed, pump.Drain());
        Assert.IsType<IOException>(postFailure);
        Assert.Equal("simulated WebView failure", postFailure.Message);
        Assert.Equal(4, pump.QueuedBytes);
        Assert.Equal(0, pump.InFlightBytes);
        Assert.Equal(1, pump.NextFrameId);

        Assert.Equal(TerminalDrainRequest.None, pump.Drain());
        Assert.Collection(posted, f => AssertFrame(f, 1, 1, 2, 3, 4));
        Assert.Equal(0, pump.QueuedBytes);
        Assert.Equal(4, pump.InFlightBytes);
        Assert.Equal(2, pump.NextFrameId);
        Assert.Equal(1, pump.LastPostedFrameId);
        Assert.True(pump.IsFrameInFlight(1));

        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(1));
        Assert.False(pump.IsFrameInFlight(1));
        Assert.Equal(1, pump.LastPostedFrameId);
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void Drain_TinyFramesAreBoundedByCountAndOldestFrameTracksProgress()
    {
        var postedIds = new List<long>();
        var pump = CreatePump(
            high: 1024,
            low: 128,
            maxFrame: 1,
            immediateThreshold: 1,
            (id, _) =>
            {
                postedIds.Add(id);
                return true;
            });
        pump.Enqueue(new byte[100]);

        pump.Drain();

        Assert.Equal(TerminalOutputPump.MaximumInFlightFrames, pump.InFlightFrameCount);
        Assert.Equal(TerminalOutputPump.MaximumInFlightFrames, pump.InFlightBytes);
        Assert.Equal(68, pump.QueuedBytes);
        Assert.Equal(1, pump.OldestInFlightFrameId);

        // A later ACK frees credit but does not advance the oldest outstanding deadline.
        Assert.Equal(TerminalDrainRequest.Immediate, pump.Acknowledge(2));
        Assert.Equal(1, pump.OldestInFlightFrameId);
        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(1));
        Assert.Equal(3, pump.OldestInFlightFrameId);
        pump.Drain();
        Assert.Equal(TerminalOutputPump.MaximumInFlightFrames, pump.InFlightFrameCount);

        foreach (var id in postedIds.ToArray()) pump.Acknowledge(id);
        while (pump.QueuedBytes > 0)
        {
            var before = postedIds.Count;
            pump.Drain();
            foreach (var id in postedIds.Skip(before).ToArray()) pump.Acknowledge(id);
        }
        Assert.Null(pump.OldestInFlightFrameId);
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void Enqueue_CopiesCallerMemoryBeforeReturning()
    {
        PostedFrame? posted = null;
        var pump = CreatePump(
            high: 16,
            low: 4,
            maxFrame: 8,
            immediateThreshold: 8,
            (id, data) =>
            {
                posted = new PostedFrame(id, data.ToArray());
                return true;
            });
        var source = new byte[] { 1, 2, 3 };

        pump.Enqueue(source);
        source.AsSpan().Fill(99);
        pump.Drain();

        Assert.NotNull(posted);
        AssertFrame(posted, 1, 1, 2, 3);
        pump.Acknowledge(1);
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void Dispose_ReturnsOnlyUnpostedBytesResumesProducerAndIgnoresLateWork()
    {
        var posted = new List<PostedFrame>();
        var pauseCount = 0;
        var resumeCount = 0;
        var pump = new TerminalOutputPump(
            highWatermarkBytes: 8,
            lowWatermarkBytes: 2,
            maxFrameBytes: 4,
            immediateThresholdBytes: 2,
            (id, data) =>
            {
                posted.Add(new PostedFrame(id, data.ToArray()));
                return true;
            },
            () => pauseCount++,
            () => resumeCount++);
        var payload = Enumerable.Range(1, 12).Select(i => (byte)i).ToArray();

        pump.Enqueue(payload);
        pump.Drain();
        Assert.Equal(8, pump.InFlightBytes);
        Assert.Equal(4, pump.QueuedBytes);
        Assert.Equal(1, pauseCount);

        var retirement = pump.DisposeAndTakeRetirementState();

        Assert.Equal(new byte[] { 9, 10, 11, 12 }, retirement.UnpostedOutput);
        Assert.True(retirement.HadUnacknowledgedOutput);
        Assert.True(pump.IsDisposed);
        Assert.False(pump.IsProducerPaused);
        Assert.Equal(1, resumeCount);
        Assert.Equal(0, pump.QueuedBytes);
        Assert.Equal(0, pump.InFlightBytes);
        Assert.Equal(0, pump.InFlightFrameCount);
        Assert.Equal(TerminalDrainRequest.None, pump.Acknowledge(1));
        Assert.Equal(TerminalDrainRequest.None, pump.Enqueue(new byte[] { 99 }));
        Assert.Equal(TerminalDrainRequest.None, pump.Drain());
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void Drain_AllowsSynchronousAcknowledgementWithoutStrandingFutureData()
    {
        TerminalOutputPump? pump = null;
        var posted = new List<PostedFrame>();
        pump = new TerminalOutputPump(
            highWatermarkBytes: 32,
            lowWatermarkBytes: 8,
            maxFrameBytes: 8,
            immediateThresholdBytes: 8,
            (id, data) =>
            {
                posted.Add(new PostedFrame(id, data.ToArray()));
                Assert.Equal(TerminalDrainRequest.None, pump!.Acknowledge(id));
                return true;
            },
            static () => { },
            static () => { });

        Assert.Equal(TerminalDrainRequest.Immediate, pump.Enqueue(new byte[] { 1, 2, 3 }));
        Assert.Equal(TerminalDrainRequest.None, pump.Drain());
        Assert.Equal(0, pump.QueuedBytes);
        Assert.Equal(0, pump.InFlightBytes);
        Assert.Equal(2, pump.NextFrameId);

        Assert.Equal(TerminalDrainRequest.Immediate, pump.Enqueue(new byte[] { 4, 5 }));
        Assert.Equal(TerminalDrainRequest.None, pump.Drain());
        Assert.Collection(
            posted,
            f => AssertFrame(f, 1, 1, 2, 3),
            f => AssertFrame(f, 2, 4, 5));
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void RandomChunkingAndOutOfOrderAcks_PreserveExactByteStream()
    {
        const int totalBytes = 2 * 1024 * 1024;
        var random = new Random(0x5EED);
        var expected = new byte[totalBytes];
        random.NextBytes(expected);
        using var actual = new MemoryStream(totalBytes);
        var pendingIds = new List<long>();
        var allIds = new List<long>();
        var pump = CreatePump(
            high: 64 * 1024,
            low: 16 * 1024,
            maxFrame: 7 * 1024,
            immediateThreshold: 512,
            (id, data) =>
            {
                actual.Write(data.Span);
                pendingIds.Add(id);
                allIds.Add(id);
                return true;
            });

        for (var offset = 0; offset < expected.Length;)
        {
            var length = Math.Min(random.Next(1, 8193), expected.Length - offset);
            pump.Enqueue(expected.AsSpan(offset, length));
            offset += length;
        }

        var iterations = 0;
        while (pump.QueuedBytes > 0 || pump.InFlightBytes > 0)
        {
            Assert.True(iterations++ < 10_000, "Output pump failed to make progress.");
            pendingIds.Clear();
            pump.Drain();
            Assert.True(pump.InFlightBytes <= 64 * 1024);
            Assert.NotEmpty(pendingIds);

            for (var i = pendingIds.Count - 1; i > 0; i--)
            {
                var swapWith = random.Next(i + 1);
                (pendingIds[i], pendingIds[swapWith]) = (pendingIds[swapWith], pendingIds[i]);
            }
            foreach (var id in pendingIds) pump.Acknowledge(id);
        }

        Assert.Equal(expected, actual.ToArray());
        Assert.Equal(
            Enumerable.Range(1, allIds.Count).Select(i => (long)i),
            allIds);
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void Drain_SynchronousEnqueueAppendsBehindCurrentFrameWithoutExtraSchedule()
    {
        TerminalOutputPump? pump = null;
        var posted = new List<PostedFrame>();
        pump = new TerminalOutputPump(
            highWatermarkBytes: 16,
            lowWatermarkBytes: 4,
            maxFrameBytes: 2,
            immediateThresholdBytes: 2,
            (id, data) =>
            {
                posted.Add(new PostedFrame(id, data.ToArray()));
                if (id == 1)
                {
                    Assert.Equal(
                        TerminalDrainRequest.None,
                        pump!.Enqueue(new byte[] { 3, 4 }));
                }
                return true;
            },
            static () => { },
            static () => { });

        Assert.Equal(
            TerminalDrainRequest.Immediate,
            pump.Enqueue(new byte[] { 1, 2 }));

        Assert.Equal(TerminalDrainRequest.None, pump.Drain());

        Assert.Collection(
            posted,
            frame => AssertFrame(frame, 1, 1, 2),
            frame => AssertFrame(frame, 2, 3, 4));
        Assert.Equal(4, pump.InFlightBytes);
        pump.Acknowledge(1);
        pump.Acknowledge(2);
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public void HundredMegabyteBacklog_NeverExceedsCreditAndPreservesEveryByte()
    {
        static ulong PatternWord(ulong wordIndex) =>
            unchecked(wordIndex * 0x9E3779B97F4A7C15UL + 0xD1B54A32D192ED03UL);

        const int totalBytes = 100 * 1024 * 1024;
        const int sourceChunkBytes = 64 * 1024;
        const int high = 512 * 1024;
        const int low = 128 * 1024;
        const int maxFrame = 128 * 1024;
        var pendingIds = new List<long>();
        var allIds = new List<long>();
        long postedOffset = 0;
        var pauseCount = 0;
        var resumeCount = 0;
        var pump = new TerminalOutputPump(
            high,
            low,
            maxFrame,
            immediateThresholdBytes: 512,
            (id, data) =>
            {
                var span = data.Span;
                if (span.Length % sizeof(ulong) != 0)
                {
                    throw new InvalidDataException(
                        $"Frame {id} split the test's 64-bit sequence at {span.Length} bytes.");
                }

                for (var i = 0; i < span.Length; i += sizeof(ulong))
                {
                    var absoluteOffset = postedOffset + i;
                    var expected = PatternWord((ulong)absoluteOffset / sizeof(ulong));
                    var actual = BinaryPrimitives.ReadUInt64LittleEndian(
                        span.Slice(i, sizeof(ulong)));
                    if (actual != expected)
                    {
                        throw new InvalidDataException(
                            $"FIFO mismatch at byte {absoluteOffset}: expected {expected:X16}, got {actual:X16}.");
                    }
                }
                postedOffset += span.Length;
                pendingIds.Add(id);
                allIds.Add(id);
                return true;
            },
            () => pauseCount++,
            () => resumeCount++,
            maximumBacklogBytes: 128L * 1024 * 1024);
        var source = new byte[sourceChunkBytes];

        long enqueued = 0;
        while (enqueued < totalBytes)
        {
            for (var i = 0; i < source.Length; i += sizeof(ulong))
            {
                var absoluteOffset = enqueued + i;
                BinaryPrimitives.WriteUInt64LittleEndian(
                    source.AsSpan(i, sizeof(ulong)),
                    PatternWord((ulong)absoluteOffset / sizeof(ulong)));
            }
            pump.Enqueue(source);
            enqueued += source.Length;
        }

        Assert.Equal(totalBytes, pump.QueuedBytes);
        Assert.Equal(1, pauseCount);
        Assert.True(pump.IsProducerPaused);
        Assert.Equal((ulong)totalBytes, pump.EnqueuedSequence);
        Assert.Equal((ulong)0, pump.PostedSequence);
        Assert.Equal(0, pump.LastPostedFrameId);

        var iterations = 0;
        while (pump.QueuedBytes > 0 || pump.InFlightBytes > 0)
        {
            Assert.True(iterations++ < 1_000, "100 MB output pump failed to make progress.");
            pendingIds.Clear();
            pump.Drain();
            Assert.InRange(pump.InFlightBytes, 0, high);
            Assert.NotEmpty(pendingIds);
            foreach (var id in pendingIds) pump.Acknowledge(id);
        }

        Assert.Equal(totalBytes, postedOffset);
        Assert.Equal(
            Enumerable.Range(1, allIds.Count).Select(id => (long)id),
            allIds);
        Assert.Equal((ulong)totalBytes, pump.PostedSequence);
        Assert.Equal(0, pump.BacklogBytes);
        Assert.Equal(801, pump.NextFrameId);
        Assert.Equal(1, pauseCount);
        Assert.Equal(1, resumeCount);
        Assert.False(pump.IsProducerPaused);
        Assert.Empty(pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    [Fact]
    public async Task PauseAndConcurrentAck_AreAppliedInPhysicalOrder()
    {
        using var pauseEntered = new ManualResetEventSlim();
        using var releasePause = new ManualResetEventSlim();
        var ackStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var actions = new List<string>();
        var postedIds = new List<long>();
        var pump = new TerminalOutputPump(
            highWatermarkBytes: 8,
            lowWatermarkBytes: 4,
            maxFrameBytes: 4,
            immediateThresholdBytes: 4,
            (id, _) =>
            {
                postedIds.Add(id);
                return true;
            },
            () =>
            {
                actions.Add("pause");
                pauseEntered.Set();
                if (!releasePause.Wait(TimeSpan.FromSeconds(2)))
                {
                    throw new TimeoutException("Test did not release Pause callback.");
                }
            },
            () => actions.Add("resume"));

        pump.Enqueue(new byte[] { 1, 2, 3, 4 });
        pump.Drain();
        Assert.Equal(new long[] { 1 }, postedIds);
        Assert.Equal(4, pump.InFlightBytes);

        var enqueueTask = Task.Run(() => pump.Enqueue(new byte[] { 5, 6, 7, 8 }));
        Assert.True(pauseEntered.Wait(TimeSpan.FromSeconds(5)));
        var ackCompleted = new TaskCompletionSource<TerminalDrainRequest>(TaskCreationOptions.RunContinuationsAsynchronously);
        // Dedicated thread: on CI the thread pool can be saturated for >1s, which made
        // Task.Run-based ack scheduling flake with WaitAsync(1s) below.
        var ackThread = new Thread(() =>
        {
            ackStarted.TrySetResult();
            ackCompleted.SetResult(pump.Acknowledge(1));
        })
        {
            IsBackground = true,
        };
        ackThread.Start();
        await ackStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        try
        {
            await Task.Delay(50);
            Assert.False(ackCompleted.Task.IsCompleted);
        }
        finally
        {
            releasePause.Set();
        }

        Assert.Equal(TerminalDrainRequest.Immediate, await enqueueTask);
        Assert.Equal(TerminalDrainRequest.None, await ackCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Collection(
            actions,
            action => Assert.Equal("pause", action),
            action => Assert.Equal("resume", action));
        Assert.False(pump.IsProducerPaused);
        Assert.Equal(new byte[] { 5, 6, 7, 8 }, pump.DisposeAndTakeRetirementState().UnpostedOutput);
    }

    private static TerminalOutputPump CreatePump(
        int high,
        int low,
        int maxFrame,
        int immediateThreshold,
        Func<long, ReadOnlyMemory<byte>, bool> sink,
        Action<Exception>? onPostFailure = null) =>
        new(
            high,
            low,
            maxFrame,
            immediateThreshold,
            sink,
            static () => { },
            static () => { },
            onPostFailure);

    private static void AssertFrame(PostedFrame? frame, long expectedId, params byte[] expectedData)
    {
        Assert.NotNull(frame);
        Assert.Equal(expectedId, frame.Id);
        Assert.Equal(expectedData, frame.Data);
    }

    private sealed record PostedFrame(long Id, byte[] Data);
}
