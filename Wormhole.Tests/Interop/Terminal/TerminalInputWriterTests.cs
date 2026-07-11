using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalInputWriterTests
{
    [Fact]
    public async Task Enqueue_WritesBytesOnBackgroundWorker()
    {
        var writes = new List<byte[]>();
        using var writer = new TerminalInputWriter(
            data =>
            {
                writes.Add(data.ToArray());
                return Task.CompletedTask;
            },
            ex => throw ex);

        writer.Enqueue(new byte[] { 1, 2, 3 });

        await WaitForAsync(() => writes.Count == 1);
        Assert.Equal(new byte[] { 1, 2, 3 }, writes[0]);
        Assert.False(writer.HasPending);
    }

    [Fact]
    public async Task Enqueue_WhileWriteIsInFlight_CoalescesFollowUpBytes()
    {
        var firstWriteStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var writes = new List<byte[]>();
        using var writer = new TerminalInputWriter(
            async data =>
            {
                writes.Add(data.ToArray());
                if (writes.Count == 1)
                {
                    firstWriteStarted.SetResult();
                    await releaseFirstWrite.Task.ConfigureAwait(false);
                }
            },
            ex => throw ex);

        writer.Enqueue(new byte[] { 1 });
        await firstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        writer.Enqueue(new byte[] { 2 });
        writer.Enqueue(new byte[] { 3, 4 });
        releaseFirstWrite.SetResult();

        await WaitForAsync(() => writes.Count == 2);
        Assert.Equal(new byte[] { 1 }, writes[0]);
        Assert.Equal(new byte[] { 2, 3, 4 }, writes[1]);
    }

    [Fact]
    public async Task Dispose_DropsQueuedBytesAfterCurrentWrite()
    {
        var firstWriteStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var writes = new List<byte[]>();
        var writer = new TerminalInputWriter(
            async data =>
            {
                writes.Add(data.ToArray());
                if (writes.Count == 1)
                {
                    firstWriteStarted.TrySetResult();
                    await releaseFirstWrite.Task.ConfigureAwait(false);
                }
            },
            ex => throw ex);

        writer.Enqueue(new byte[] { 1 });
        await firstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        writer.Enqueue(new byte[] { 2 });
        writer.Dispose();
        releaseFirstWrite.SetResult();

        await Task.Delay(50);
        Assert.Single(writes);
        Assert.Equal(new byte[] { 1 }, writes[0]);
        Assert.False(writer.HasPending);
    }

    [Fact]
    public async Task PendingInputSafetyLimit_FailsClosedAndDropsQueuedBytes()
    {
        var firstWriteStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstWrite = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        Exception? reportedFailure = null;
        var writes = new List<byte[]>();
        using var writer = new TerminalInputWriter(
            async data =>
            {
                writes.Add(data.ToArray());
                firstWriteStarted.TrySetResult();
                await releaseFirstWrite.Task.ConfigureAwait(false);
            },
            ex => reportedFailure = ex);

        writer.Enqueue(new byte[] { 1 });
        await firstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        writer.Enqueue(new byte[TerminalInputWriter.MaximumPendingBytes]);

        writer.Enqueue(new byte[] { 2 });

        var overflow = Assert.IsType<IOException>(reportedFailure);
        Assert.Contains("safety limit", overflow.Message, StringComparison.Ordinal);
        Assert.False(writer.HasPending);

        releaseFirstWrite.TrySetResult();
        await Task.Delay(50);
        Assert.Single(writes);
    }
    [Fact]
    public async Task WriteFailure_DropsQueuedBytesAndReportsFailure()
    {
        var firstWriteStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseFirstWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var failureReported = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var writes = new List<byte[]>();
        var failure = new IOException("socket closed");
        using var writer = new TerminalInputWriter(
            async data =>
            {
                writes.Add(data.ToArray());
                firstWriteStarted.TrySetResult();
                await releaseFirstWrite.Task.ConfigureAwait(false);
                throw failure;
            },
            ex =>
            {
                Assert.Same(failure, ex);
                failureReported.SetResult();
            });

        writer.Enqueue(new byte[] { 1 });
        await firstWriteStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        writer.Enqueue(new byte[] { 2 });
        releaseFirstWrite.SetResult();

        await failureReported.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await Task.Delay(50);
        Assert.Single(writes);
        Assert.False(writer.HasPending);
    }

    [Fact]
    public async Task WriteFailure_CallbackExceptionStillAbortsWriter()
    {
        var callbackRan = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var writes = 0;
        using var writer = new TerminalInputWriter(
            _ =>
            {
                writes++;
                throw new IOException("write failed");
            },
            _ =>
            {
                callbackRan.TrySetResult();
                throw new InvalidOperationException("recovery callback failed");
            });

        writer.Enqueue(new byte[] { 1 });
        await callbackRan.Task.WaitAsync(TimeSpan.FromSeconds(1));
        writer.Enqueue(new byte[] { 2 });
        await Task.Delay(50);

        Assert.Equal(1, writes);
        Assert.False(writer.HasPending);
    }
    private static async Task WaitForAsync(Func<bool> condition)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        while (!condition())
        {
            cts.Token.ThrowIfCancellationRequested();
            await Task.Delay(10, cts.Token);
        }
    }
}
