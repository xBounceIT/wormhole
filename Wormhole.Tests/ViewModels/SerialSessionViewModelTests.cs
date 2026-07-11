using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Interop.Terminal;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class SerialSessionViewModelTests
{
    [Fact]
    public void DetachView_PreservedTerminal_KeepsSameWebViewNotFresh()
    {
        var vm = CreateViewModel();
        var webView = new object();
        vm.RegisterAttachedWebView(webView);

        vm.DetachView();

        Assert.False(vm.RegisterAttachedWebView(webView));
    }

    [Fact]
    public void DetachView_ReplacedTerminal_MakesSameWebViewFresh()
    {
        var vm = CreateViewModel();
        var webView = new object();
        vm.RegisterAttachedWebView(webView);

        vm.DetachView(preserveTerminalContents: false);

        Assert.True(vm.RegisterAttachedWebView(webView));
    }

    [Fact]
    public void RendererOwnership_FollowsExactPreservedOrReplacementPage()
    {
        var vm = CreateViewModel();
        var firstPage = new object();
        var replacementPage = new object();

        vm.RegisterAttachedWebView(firstPage);
        vm.DetachView();

        Assert.True(vm.OwnsTerminalRenderer(firstPage));

        vm.RegisterAttachedWebView(replacementPage);

        Assert.False(vm.OwnsTerminalRenderer(firstPage));
        Assert.True(vm.OwnsTerminalRenderer(replacementPage));

        vm.DetachView(preserveTerminalContents: false);

        Assert.False(vm.OwnsTerminalRenderer(replacementPage));
    }

    [Fact]
    public void ScopedDetach_StalePageCannotDetachReplacementRenderer()
    {
        var vm = CreateViewModel();
        var stalePage = new object();
        var replacementPage = new object();
        vm.RegisterAttachedWebView(stalePage);
        vm.RegisterAttachedWebView(replacementPage);

        vm.DetachView(stalePage, preserveTerminalContents: false);

        Assert.True(vm.OwnsTerminalRenderer(replacementPage));

        vm.DetachView(replacementPage, preserveTerminalContents: false);

        Assert.False(vm.OwnsTerminalRenderer(replacementPage));
    }

    [Fact]
    public async Task TryRendererFailure_StalePageCannotTearDownReplacementSession()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var stalePage = new object();
        var replacementPage = new object();
        vm.RegisterAttachedWebView(stalePage);
        vm.RegisterAttachedWebView(replacementPage);
        var lifecycleBefore = vm.CaptureTerminalRendererRecoveryLease();

        var recoveryLease = await vm
            .TryHandleTerminalRendererFailureAsync(stalePage, "stale renderer failed");

        Assert.Null(recoveryLease);
        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.Null(vm.ErrorMessage);
        Assert.Equal(0, session.DisposeCount);
        Assert.True(vm.IsTerminalRendererRecoveryCurrent(lifecycleBefore));
        Assert.True(vm.OwnsTerminalRenderer(replacementPage));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TryRendererFailure_UnassignedOrCurrentRendererOwnsFailure(
        bool registerRenderer)
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var renderer = new object();
        if (registerRenderer)
        {
            vm.RegisterAttachedWebView(renderer);
        }
        var lifecycleBefore = vm.CaptureTerminalRendererRecoveryLease();
        const string failureMessage = "authorized renderer failed";

        var recoveryLease = await vm
            .TryHandleTerminalRendererFailureAsync(renderer, failureMessage);

        Assert.NotNull(recoveryLease);
        Assert.False(vm.IsTerminalRendererRecoveryCurrent(lifecycleBefore));
        Assert.True(vm.IsTerminalRendererRecoveryCurrent(recoveryLease.Value));
        Assert.Equal(1, session.DisposeCount);
        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Equal(failureMessage, vm.ErrorMessage);
    }

    [Fact]
    public void DetachView_ReplaysPendingAndDetachedBytesExactlyOnce()
    {
        var vm = CreateViewModel();
        var sink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(sink);
        vm.AppendTerminalOutputForTesting((byte)'a');
        sink.PendingOnDispose = new byte[] { (byte)'a' };

        vm.DetachView();
        vm.AppendTerminalOutputForTesting((byte)'b');

        Assert.True(sink.IsDisposed);
        Assert.Equal(new byte[] { (byte)'a', (byte)'b' }, vm.PeekReplayBufferForTesting());
        Assert.Equal(new byte[] { (byte)'a', (byte)'b' }, vm.PeekDetachedReplayBufferForTesting());
        Assert.Equal(
            new byte[] { (byte)'a', (byte)'b' },
            vm.TakeReattachReplaySnapshotForTesting(xtermIsFresh: false));
        Assert.Null(vm.TakeReattachReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public void RetiringSink_PrependsOlderNativeQueueBeforeNewerRejectedOutput()
    {
        var vm = CreateViewModel();
        var sink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(sink);

        vm.AppendTerminalOutputForTesting((byte)'a');
        sink.PendingOnDispose = new byte[] { (byte)'a' };
        sink.AcceptsOutput = false;
        vm.AppendTerminalOutputForTesting((byte)'b');

        vm.DetachView();

        Assert.Equal(
            new byte[] { (byte)'a', (byte)'b' },
            vm.PeekDetachedReplayBufferForTesting());
    }

    [Fact]
    public void TruncatedDetachedHistory_IsRejectedInsteadOfReplayingPartialState()
    {
        var vm = CreateViewModel();
        vm.AppendTerminalOutputForTesting(new byte[SerialSessionViewModel.TerminalReplayCapacityBytes + 1]);

        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public void RejectedSinkOutput_IsCapturedForDetachedReplay()
    {
        var vm = CreateViewModel();
        var sink = new RecordingTerminalOutputSink { AcceptsOutput = false };
        vm.AttachTerminalOutputSinkForTesting(sink);

        vm.AppendTerminalOutputForTesting((byte)'x');

        Assert.Equal(new byte[] { (byte)'x' }, sink.Received);
        Assert.Equal(new byte[] { (byte)'x' }, vm.PeekDetachedReplayBufferForTesting());
    }

    [Fact]
    public void FreshReplay_SplitsHistoricalAndLiveDetachedOutput()
    {
        var vm = CreateViewModel();
        var sink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(sink);
        vm.AppendTerminalOutputForTesting((byte)'o', (byte)'l', (byte)'d');

        sink.AcceptsOutput = false;
        vm.AppendTerminalOutputForTesting((byte)'n', (byte)'e', (byte)'w');

        var plan = vm.TakeReattachReplayPlanForTesting(xtermIsFresh: true);

        Assert.Equal(new byte[] { (byte)'o', (byte)'l', (byte)'d' }, plan.HistoricalReplay);
        Assert.Equal(new byte[] { (byte)'n', (byte)'e', (byte)'w' }, plan.LiveDetachedReplay);
        Assert.Empty(vm.PeekDetachedReplayBufferForTesting());
    }

    [Fact]
    public async Task HistoricalReplay_ExactRetirementBeforeFocusPermitsSamePageReattach()
    {
        var vm = CreateViewModel();
        var replay = new byte[] { 0x1b, (byte)'[', (byte)'2', (byte)'J', (byte)'x' };
        vm.AppendReplayBufferForTesting(replay);
        var retirementRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sink = new RecordingTerminalOutputSink
        {
            RetirementRelease = retirementRelease,
        };

        vm.ReplayAndPublishTerminalOutputSinkForTesting(
            sink,
            replay,
            liveDetachedReplay: null);
        vm.DetachView();
        await sink.FirstRetire.Task.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(replay, vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));

        retirementRelease.TrySetResult();
        await vm.AwaitPendingTerminalSinkRetirementForTestingAsync();

        Assert.Null(vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task HistoricalReplay_UncertainRetirementBeforeFocusRejectsSessionlessReplay()
    {
        var vm = CreateViewModel();
        var replay = new byte[] { 0x1b, (byte)'[', (byte)'2', (byte)'J', (byte)'x' };
        vm.AppendReplayBufferForTesting(replay);
        var retirementRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sink = new RecordingTerminalOutputSink
        {
            RetirementRelease = retirementRelease,
            HadUncertainGeometryOnDispose = true,
        };

        vm.ReplayAndPublishTerminalOutputSinkForTesting(
            sink,
            replay,
            liveDetachedReplay: null);
        vm.DetachView();
        await sink.FirstRetire.Task.WaitAsync(TimeSpan.FromSeconds(2));
        retirementRelease.TrySetResult();
        await vm.AwaitPendingTerminalSinkRetirementForTestingAsync();

        Assert.Throws<InvalidOperationException>(
            () => vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task HistoricalReplay_UnacknowledgedButGeometryCertainRetirementReconstructs()
    {
        var vm = CreateViewModel();
        var replay = new byte[] { 0x1b, (byte)'[', (byte)'2', (byte)'J', (byte)'x' };
        vm.AppendReplayBufferForTesting(replay);
        var sink = new RecordingTerminalOutputSink
        {
            HasUnacknowledgedOutputOnDispose = true,
        };

        vm.ReplayAndPublishTerminalOutputSinkForTesting(
            sink,
            replay,
            liveDetachedReplay: null);
        vm.DetachView();
        await vm.AwaitPendingTerminalSinkRetirementForTestingAsync();

        Assert.Equal(replay, vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task ReplacementSink_UncertainRetirementDoesNotContaminateReplayGeometry()
    {
        var vm = CreateViewModel();
        vm.AppendReplayBufferForTesting((byte)'x');
        var retirementRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var retiredSink = new RecordingTerminalOutputSink
        {
            RetirementRelease = retirementRelease,
            HadUncertainGeometryOnDispose = true,
        };
        vm.AttachTerminalOutputSinkForTesting(retiredSink);

        vm.AttachTerminalOutputSinkForTesting(new RecordingTerminalOutputSink());
        await retiredSink.FirstRetire.Task.WaitAsync(TimeSpan.FromSeconds(2));
        retirementRelease.TrySetResult();
        await vm.AwaitPendingTerminalSinkRetirementForTestingAsync();

        Assert.Null(vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public void ConnectedWhileDetached_TreatsEntireNewSessionAsLive()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        session.RaiseData((byte)'n', (byte)'e', (byte)'w');
        vm.SetConnectedWhileDetachedForTesting();

        var plan = vm.TakeReattachReplayPlanForTesting(xtermIsFresh: false);

        Assert.Null(plan.HistoricalReplay);
        Assert.Equal(new byte[] { (byte)'n', (byte)'e', (byte)'w' }, plan.LiveDetachedReplay);
    }

    [Fact]
    public void FreshReplay_RejectsDetachedBytesOutsideFullHistory()
    {
        var vm = CreateViewModel();
        var sink = new RecordingTerminalOutputSink
        {
            PendingOnDispose = new byte[] { (byte)'x' },
        };
        vm.AttachTerminalOutputSinkForTesting(sink);
        vm.DetachView();

        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplayPlanForTesting(xtermIsFresh: true));
    }

    [Fact]
    public void DetachView_ReplacedPage_PreservesUnpostedOutputAsLiveReplay()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var sink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(sink);
        session.RaiseData((byte)'x');
        sink.PendingOnDispose = new byte[] { (byte)'x' };

        vm.DetachView(preserveTerminalContents: false);
        session.RaiseData((byte)'y');

        var plan = vm.TakeReattachReplayPlanForTesting(xtermIsFresh: true);
        Assert.Null(plan.HistoricalReplay);
        Assert.Equal(new byte[] { (byte)'x', (byte)'y' }, plan.LiveDetachedReplay);
    }

    [Fact]
    public void DetachView_ReplacedPage_RejectsFreshReplayWithUnacknowledgedFrames()
    {
        var vm = CreateViewModel();
        vm.AttachConnectedSessionForTesting(new FakeTerminalSession());
        var sink = new RecordingTerminalOutputSink
        {
            HasUnacknowledgedOutputOnDispose = true,
        };
        vm.AttachTerminalOutputSinkForTesting(sink);

        vm.DetachView(preserveTerminalContents: false);

        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplayPlanForTesting(xtermIsFresh: true));
    }
    [Fact]
    public void ReattachReplay_UnacknowledgedRetiredFrames_AreRejectedForEveryPage()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var retiredSink = new RecordingTerminalOutputSink
        {
            HasUnacknowledgedOutputOnDispose = true,
        };
        vm.AttachTerminalOutputSinkForTesting(retiredSink);
        session.RaiseData((byte)'x');
        vm.DetachView();

        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplayPlanForTesting(xtermIsFresh: true));
        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplayPlanForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task DetachView_KeepsBridgeAliveUntilAcceptedPrefixRetires()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var retirementRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sink = new RecordingTerminalOutputSink
        {
            RetirementRelease = retirementRelease,
        };
        vm.AttachTerminalOutputSinkForTesting(sink);
        session.RaiseData((byte)'a');
        sink.PendingOnDispose = new byte[] { (byte)'a' };

        vm.DetachView();
        await sink.FirstRetire.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(sink.IsDisposed);

        session.RaiseData((byte)'b');
        retirementRelease.TrySetResult();
        await vm.AwaitPendingTerminalSinkRetirementForTestingAsync();

        Assert.True(sink.IsDisposed);
        Assert.Equal(1, sink.RetireCount);
        Assert.Equal(
            new byte[] { (byte)'a', (byte)'b' },
            vm.TakeReattachReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task DetachViewAsync_AwaitsOnlyTheMatchingRendererRetirement()
    {
        var vm = CreateViewModel();
        vm.AttachConnectedSessionForTesting(new FakeTerminalSession());
        var rendererIdentity = new object();
        var retirementRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sink = new RecordingTerminalOutputSink
        {
            RetirementRelease = retirementRelease,
        };
        vm.AttachTerminalOutputSinkForTesting(sink, rendererIdentity);

        var retirement = vm.DetachViewAsync(
            rendererIdentity,
            preserveTerminalContents: false);
        await sink.FirstRetire.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var duplicateWait = vm.DetachViewAsync(
            rendererIdentity,
            preserveTerminalContents: false);
        var staleWait = vm.DetachViewAsync(
            new object(),
            preserveTerminalContents: false);

        Assert.False(retirement.IsCompleted);
        Assert.False(duplicateWait.IsCompleted);
        Assert.True(staleWait.IsCompletedSuccessfully);
        retirementRelease.TrySetResult();
        await Task.WhenAll(retirement, duplicateWait);

        Assert.True(sink.IsDisposed);
        Assert.Equal(1, sink.RetireCount);
    }
    [Fact]
    public void ReattachReplay_RetirementFailure_IsRejectedForEveryPage()
    {
        var vm = CreateViewModel();
        vm.AttachConnectedSessionForTesting(new FakeTerminalSession());
        var sink = new RecordingTerminalOutputSink
        {
            DisposeException = new InvalidOperationException("retirement failed"),
        };
        vm.AttachTerminalOutputSinkForTesting(sink);
        vm.DetachView();

        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplayPlanForTesting(xtermIsFresh: false));
        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplayPlanForTesting(xtermIsFresh: true));
    }

    [Fact]
    public void RendererRecoveryRequest_FromRetiredSink_IsDiscardedBeforeTake()
    {
        var vm = CreateViewModel();
        vm.AttachConnectedSessionForTesting(new FakeTerminalSession());
        var page = new object();
        vm.RegisterAttachedWebView(page);
        var retiredSink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(retiredSink);
        vm.SetPendingRendererRecoveryForTesting(page, "stale renderer failure");

        var replacementSink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(replacementSink);

        Assert.False(vm.TryTakeTerminalRendererRecoveryRequest(page, out _));
        Assert.False(replacementSink.IsDisposed);
    }

    [Fact]
    public void TerminalOutputFailure_FromRetiredSinkOnSamePage_IsIgnored()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var page = new object();
        vm.RegisterAttachedWebView(page);
        var retiredSink = new RecordingTerminalOutputSink();
        var currentSink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(retiredSink);
        vm.AttachTerminalOutputSinkForTesting(currentSink);

        vm.ReportTerminalOutputTransportFailureForTesting(
            retiredSink,
            page,
            "stale renderer failure");

        Assert.True(retiredSink.IsDisposed);
        Assert.False(currentSink.IsDisposed);
        Assert.Equal(0, session.DisposeCount);
        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public void ReplayFailure_DisposesUnpublishedSinkAndDoesNotClaimFailureOwnership()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var page = new object();
        vm.RegisterAttachedWebView(page);
        var replayFailure = new InvalidOperationException("replay failed");
        var sink = new RecordingTerminalOutputSink
        {
            ReplayException = replayFailure,
        };

        var thrown = Assert.Throws<InvalidOperationException>(() =>
            vm.ReplayAndPublishTerminalOutputSinkForTesting(
                sink,
                new byte[] { 0x1b, (byte)'[', (byte)'2', (byte)'J' },
                liveDetachedReplay: null));
        vm.ReportTerminalOutputTransportFailureForTesting(
            sink,
            page,
            "late replay failure");

        Assert.Same(replayFailure, thrown);
        Assert.True(sink.IsDisposed);
        Assert.Equal(1, sink.DisposeCount);
        Assert.Equal(0, session.DisposeCount);
        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public async Task TerminalInputFailure_ThrowingLoggerStillTearsDownSession()
    {
        var vm = CreateViewModel(loggerFactory: new ThrowingLoggerFactory());
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var failure = new IOException("serial input transport failed");

        vm.ReportTerminalInputWriteFailureForTesting(failure);

        await session.DisposeStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await WaitForAsync(() => vm.Status == SessionStatus.Failed);
        Assert.Equal(1, session.DisposeCount);
        Assert.Contains(failure.Message, vm.ErrorMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void TerminalInputFailure_ClosingSessionLetsClosedPathOwnTeardown()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession { IsClosing = true };
        vm.AttachConnectedSessionForTesting(session);

        vm.ReportTerminalInputWriteFailureForTesting(
            new IOException("write failed during remote close"));

        Assert.Equal(0, session.DisposeCount);
        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task ConnectedPublication_ReplacementSinkGetsItsOwnFocusBarrier()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        vm.Status = SessionStatus.Connecting;
        var firstFocusRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var firstSink = new RecordingTerminalOutputSink
        {
            FocusRelease = firstFocusRelease,
        };
        vm.AttachTerminalOutputSinkForTesting(firstSink);

        var publish = vm.CompleteConnectedAfterCurrentTerminalFocusForTestingAsync();
        await firstSink.FocusRequested.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var secondFocusRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var secondSink = new RecordingTerminalOutputSink
        {
            FocusRelease = secondFocusRelease,
        };
        vm.AttachTerminalOutputSinkForTesting(secondSink);
        firstFocusRelease.TrySetResult();

        await secondSink.FocusRequested.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(SessionStatus.Connecting, vm.Status);
        Assert.Equal(1, firstSink.FocusCount);
        Assert.Equal(1, secondSink.FocusCount);
        Assert.False(publish.IsCompleted);

        secondFocusRelease.TrySetResult();

        Assert.True(await publish);
        Assert.Equal(SessionStatus.Connected, vm.Status);
    }

    [Fact]
    public async Task ConnectedPublication_StaleFocusFailureAfterRendererHandoffCannotTearDownSession()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        vm.Status = SessionStatus.Connecting;
        var stalePage = new object();
        var replacementPage = new object();
        vm.RegisterAttachedWebView(stalePage);
        var focusRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var staleSink = new RecordingTerminalOutputSink
        {
            FocusRelease = focusRelease,
        };
        vm.AttachTerminalOutputSinkForTesting(staleSink);

        var publish = vm.CompleteConnectedAfterCurrentTerminalFocusForTestingAsync();
        await staleSink.FocusRequested.Task.WaitAsync(TimeSpan.FromSeconds(2));
        vm.RegisterAttachedWebView(replacementPage);
        focusRelease.TrySetException(new InvalidOperationException("stale focus failed"));

        Assert.False(await publish);
        Assert.Equal(0, session.DisposeCount);
        Assert.Equal(SessionStatus.Connecting, vm.Status);
        Assert.Null(vm.ErrorMessage);
        Assert.True(vm.OwnsTerminalRenderer(replacementPage));
    }

    [Fact]
    public async Task ConnectedPublication_ClosingSessionCannotBePromotedByReattach()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession { IsClosing = true };
        vm.AttachConnectedSessionForTesting(session);
        vm.Status = SessionStatus.Connecting;
        var sink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(sink);

        var published = await vm.CompleteConnectedAfterCurrentTerminalFocusForTestingAsync();

        Assert.False(published);
        Assert.Equal(SessionStatus.Connecting, vm.Status);
        Assert.Equal(0, sink.FocusCount);
    }

    [Fact]
    public async Task RemoteClose_LargeTailWaitsForXtermBarrierBeforeRetiringSink()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var flushRelease = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sink = new RecordingTerminalOutputSink
        {
            FlushRelease = flushRelease,
        };
        vm.AttachTerminalOutputSinkForTesting(sink);
        var tail = new byte[8 * 1024];
        Array.Fill(tail, (byte)'x');

        session.RaiseData(tail);
        session.RaiseClosed();

        await sink.FirstFlush.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(SessionStatus.Connecting, vm.Status);
        Assert.Equal(tail, sink.Received);
        Assert.False(sink.IsDisposed);
        Assert.Equal(0, session.DisposeCount);

        flushRelease.SetResult(true);
        await WaitForAsync(() => session.DisposeCount == 1);

        Assert.True(sink.IsDisposed);
        Assert.Equal(1, sink.FlushCount);
        Assert.Null(vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
        Assert.Equal(tail, vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: true));
    }

    [Fact]
    public async Task RemoteClose_WaitsForSinkRetirementBeforePublishingReplayCheckpoint()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var retirementRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var tail = new byte[8 * 1024];
        Array.Fill(tail, (byte)'p');
        var sink = new RecordingTerminalOutputSink
        {
            FlushResult = false,
            PendingOnDispose = tail,
            RetirementRelease = retirementRelease,
        };
        vm.AttachTerminalOutputSinkForTesting(sink);

        session.RaiseData(tail);
        session.RaiseClosed();
        await sink.FirstRetire.Task.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(1, session.DisposeCount);
        Assert.False(sink.IsDisposed);
        Assert.Equal(SessionStatus.Connecting, vm.Status);
        Assert.Empty(vm.PeekDetachedReplayBufferForTesting());
        Assert.Null(vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));

        retirementRelease.TrySetResult();
        await vm.AwaitPendingTerminalSinkRetirementForTestingAsync();
        await WaitForAsync(() => vm.Status == SessionStatus.Failed);

        Assert.True(sink.IsDisposed);
        Assert.Equal(tail, vm.PeekDetachedReplayBufferForTesting());
        Assert.Equal(tail, vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task RemoteClose_DisconnectDuringSinkRetirementDiscardsStaleReplayResult()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var retirementRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sink = new RecordingTerminalOutputSink
        {
            FlushResult = false,
            PendingOnDispose = new byte[] { (byte)'x' },
            RetirementRelease = retirementRelease,
            HadUncertainGeometryOnDispose = true,
        };
        vm.AttachTerminalOutputSinkForTesting(sink);

        session.RaiseData((byte)'x');
        session.RaiseClosed();
        await sink.FirstRetire.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await vm.DisconnectAsync();

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Empty(vm.PeekReplayBufferForTesting());
        retirementRelease.TrySetResult();
        await vm.AwaitPendingTerminalSinkRetirementForTestingAsync();

        Assert.True(sink.IsDisposed);
        Assert.Empty(vm.PeekReplayBufferForTesting());
        Assert.Empty(vm.PeekDetachedReplayBufferForTesting());
        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        vm.AppendReplayBufferForTesting((byte)'n');
        Assert.Equal(
            new byte[] { (byte)'n' }, vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: true));
    }

    [Fact]
    public async Task RemoteClose_FailedFlushPreservesUnpostedTailForRendererRecovery()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var tail = new byte[8 * 1024];
        Array.Fill(tail, (byte)'y');
        var sink = new RecordingTerminalOutputSink
        {
            FlushResult = false,
            PendingOnDispose = tail,
        };
        vm.AttachTerminalOutputSinkForTesting(sink);

        session.RaiseData(tail);
        session.RaiseClosed();

        await WaitForAsync(() => session.DisposeCount == 1);
        Assert.Equal(tail, vm.PeekReplayBufferForTesting());
        Assert.Equal(tail, vm.PeekDetachedReplayBufferForTesting());
        Assert.Equal(tail, vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task RemoteClose_WhileViewDetachedPreservesFinalTail()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var tail = new byte[8 * 1024];
        Array.Fill(tail, (byte)'z');

        session.RaiseData(tail);
        session.RaiseClosed();

        await WaitForAsync(() => session.DisposeCount == 1);
        Assert.Equal(tail, vm.PeekReplayBufferForTesting());
        Assert.Equal(tail, vm.PeekDetachedReplayBufferForTesting());
        Assert.Equal(tail, vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }
    [Fact]
    public async Task RemoteClose_RendererFailurePreservesClosedSessionReplay()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var tail = new byte[8 * 1024];
        Array.Fill(tail, (byte)'r');
        session.RaiseData(tail);
        session.RaiseClosed();
        await WaitForAsync(() => session.DisposeCount == 1);

        await vm.HandleTerminalRendererFailureAsync("renderer restarted after remote close");

        Assert.Equal(tail, vm.PeekReplayBufferForTesting());
        Assert.Equal(tail, vm.PeekDetachedReplayBufferForTesting());
        Assert.Equal(tail, vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: true));
    }
    [Fact]
    public async Task RemoteClose_SessionlessReplayRejectsChangedGeometry()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        session.RaiseData((byte)'x');
        vm.UpdateTerminalSize(new TerminalSize(120, 40));

        session.RaiseClosed();

        await WaitForAsync(() => session.DisposeCount == 1);
        Assert.Throws<InvalidOperationException>(
            () => vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task RemoteClose_ResizeFailureBeforeOutputRejectsSessionlessReplay()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var sourceGeneration = vm.CaptureTerminalRendererRecoveryLease().LifecycleGeneration;

        vm.UpdateTerminalSizeFromBridgeForTesting(
            session,
            sourceGeneration,
            new TerminalSize(120, 40),
            geometryIsUncertain: true);
        session.RaiseData((byte)'x');
        session.RaiseClosed();

        await WaitForAsync(() => session.DisposeCount == 1);
        Assert.Throws<InvalidOperationException>(
            () => vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public async Task RemoteClose_LateFailedResizeCompletionStillRejectsReplay()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var sourceGeneration = vm.CaptureTerminalRendererRecoveryLease().LifecycleGeneration;
        session.RaiseData((byte)'x');
        session.RaiseClosed();
        await WaitForAsync(() => session.DisposeCount == 1);

        vm.UpdateTerminalSizeFromBridgeForTesting(
            session,
            sourceGeneration,
            new TerminalSize(120, 40),
            geometryIsUncertain: true);

        Assert.Throws<InvalidOperationException>(
            () => vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }


    [Fact]
    public async Task RendererFailure_DelayedOldDisposeCannotClobberReplacementSession()
    {
        var vm = CreateViewModel();
        var first = new FakeTerminalSession
        {
            DisposeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously),
            DisposeRelease = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        vm.AttachConnectedSessionForTesting(first);

        var failureTask = vm.HandleTerminalRendererFailureAsync("old renderer failed");
        await first.DisposeStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var replacement = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(replacement);
        replacement.RaiseData((byte)'x');

        first.DisposeRelease.SetResult();
        var recoveryLease = await failureTask;

        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.Equal(new byte[] { (byte)'x' }, vm.PeekReplayBufferForTesting());
        Assert.Equal(0, replacement.DisposeCount);
        Assert.False(vm.IsTerminalRendererRecoveryCurrent(recoveryLease));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReattachReplay_GeometryChangeDuringDetachedEpochRejectsDeltaAndFull(bool xtermIsFresh)
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var sink = new RecordingTerminalOutputSink();
        vm.AttachTerminalOutputSinkForTesting(sink);
        session.RaiseData((byte)'x');

        vm.DetachView();
        vm.UpdateTerminalSize(new TerminalSize(120, 40));
        session.RaiseData((byte)'y');

        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplaySnapshotForTesting(xtermIsFresh));
    }

    [Fact]
    public async Task RemoteClose_RetiringBridgeGeometryAfterSessionNullRejectsSessionlessReplay()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        var sourceGeneration = vm.CaptureTerminalRendererRecoveryLease().LifecycleGeneration;
        var retirementRelease = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sink = new RecordingTerminalOutputSink
        {
            FlushResult = false,
            PendingOnDispose = new byte[] { (byte)'x' },
            RetirementRelease = retirementRelease,
        };
        vm.AttachTerminalOutputSinkForTesting(sink);
        session.RaiseData((byte)'x');

        session.RaiseClosed();
        await sink.FirstRetire.Task.WaitAsync(TimeSpan.FromSeconds(2));
        vm.UpdateTerminalSizeFromBridgeForTesting(
            session,
            sourceGeneration,
            new TerminalSize(120, 40));
        retirementRelease.TrySetResult();
        await vm.AwaitPendingTerminalSinkRetirementForTestingAsync();

        Assert.Throws<InvalidOperationException>(
            () => vm.CreateSessionlessReplaySnapshotForTesting(xtermIsFresh: false));
    }

    [Fact]
    public void StaleBridgeGeometryCallback_CannotInvalidateReplacementLifecycle()
    {
        var vm = CreateViewModel();
        var staleSession = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(staleSession);
        var staleGeneration = vm.CaptureTerminalRendererRecoveryLease().LifecycleGeneration;
        var replacement = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(replacement);
        replacement.RaiseData((byte)'x');

        vm.UpdateTerminalSizeFromBridgeForTesting(
            staleSession,
            staleGeneration,
            new TerminalSize(120, 40));

        Assert.Equal(
            new byte[] { (byte)'x' },
            vm.TakeReattachReplaySnapshotForTesting(xtermIsFresh: true));
        Assert.Equal(0, replacement.DisposeCount);
    }

    [Fact]
    public void FreshReplay_AfterOutputGeometryChange_IsRejected()
    {
        var vm = CreateViewModel();
        var session = new FakeTerminalSession();
        vm.AttachConnectedSessionForTesting(session);
        session.RaiseData((byte)'x');
        vm.UpdateTerminalSize(new TerminalSize(120, 40));

        Assert.Throws<InvalidOperationException>(
            () => vm.TakeReattachReplaySnapshotForTesting(xtermIsFresh: true));
    }

    [Fact]
    public void SessionlessRendererRecovery_AutomaticallyRetriesOnlyOnce()
    {
        var vm = CreateViewModel();
        var page = new object();
        vm.RegisterAttachedWebView(page);
        vm.Status = SessionStatus.Connecting;
        var requestCount = 0;
        vm.TerminalRendererRecoveryRequested += () => requestCount++;

        vm.RequestSessionlessRendererRecoveryForTesting(page, "sessionless renderer failed");

        Assert.Equal(1, requestCount);
        Assert.True(vm.TryTakeTerminalRendererRecoveryRequest(page, out var message));
        Assert.Equal("sessionless renderer failed", message);

        vm.RequestSessionlessRendererRecoveryForTesting(page, "renderer failed again");
        Assert.Equal(1, requestCount);
        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Contains("Retry", vm.ErrorMessage, StringComparison.Ordinal);
        Assert.False(vm.TryTakeTerminalRendererRecoveryRequest(page, out _));
    }
    [Fact]
    public void RendererRecoveryRequest_IsScopedToExactPageIdentity()
    {
        var vm = CreateViewModel();
        var failedPage = new object();
        vm.SetPendingRendererRecoveryForTesting(failedPage, "renderer failed");

        Assert.False(vm.TryTakeTerminalRendererRecoveryRequest(new object(), out _));

        vm.SetPendingRendererRecoveryForTesting(failedPage, "renderer failed");
        Assert.True(vm.TryTakeTerminalRendererRecoveryRequest(failedPage, out var message));
        Assert.Equal("renderer failed", message);
        Assert.False(vm.TryTakeTerminalRendererRecoveryRequest(failedPage, out _));

        vm.SetPendingRendererRecoveryForTesting(failedPage, "stale lifecycle");
        vm.AttachConnectedSessionForTesting(new FakeTerminalSession());
        Assert.False(vm.TryTakeTerminalRendererRecoveryRequest(failedPage, out _));
    }
    [Fact]
    public async Task DisconnectAsync_SuppressesReattachThroughoutSlowDisposal()
    {
        var vm = CreateViewModel();
        var releaseDispose = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var session = new FakeTerminalSession
        {
            DisposeRelease = releaseDispose,
        };
        vm.AttachConnectedSessionForTesting(session);

        var disconnectTask = vm.DisconnectAsync();
        await session.DisposeStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.True(vm.ShouldDeferAutoConnectOnReattach());
        vm.MarkConnecting();
        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.Equal(1, session.DisposeCount);

        releaseDispose.TrySetResult();
        await disconnectTask;

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.True(vm.ShouldDeferAutoConnectOnReattach());
    }
    [Fact]
    public async Task RendererFailureAfterExplicitDisconnect_PreservesDisconnectedState()
    {
        var vm = CreateViewModel();

        await vm.DisconnectAsync();
        await vm.HandleTerminalRendererFailureAsync("late renderer failure");

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Null(vm.ErrorMessage);
        Assert.True(vm.ShouldDeferAutoConnectOnReattach());
    }
    [Fact]
    public async Task DisconnectDuringRetryProfileRefresh_InvalidatesRetryContinuation()
    {
        var profile = new ConnectionProfile
        {
            NodeId = Guid.NewGuid(),
            Name = "serial",
            Protocol = ProtocolType.Serial,
            Host = "COM1",
            Port = 0,
        };
        var resolver = new BlockingProfileResolver();
        var vm = CreateViewModel(resolver);
        vm.Initialize(profile);
        vm.AttachConnectedSessionForTesting(new FakeTerminalSession());
        var retryEvents = 0;
        vm.InitializationRetryRequested += () => retryEvents++;

        var retryTask = vm.RetryAsync();
        await resolver.Started.Task.WaitAsync(TimeSpan.FromSeconds(2));

        await vm.DisconnectAsync();
        resolver.Complete(profile);
        await retryTask;

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.True(vm.ShouldDeferAutoConnectOnReattach());
        Assert.Equal(0, retryEvents);
    }

    private static SerialSessionViewModel CreateViewModel(
        IConnectionProfileResolver? profileResolver = null,
        ILoggerFactory? loggerFactory = null) =>
        new(
            null!,
            null!,
            profileResolver!,
            loggerFactory ?? NullLoggerFactory.Instance);

    private static async Task WaitForAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(1);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }

        Assert.True(condition(), "Condition did not become true before the timeout.");
    }

    private sealed class BlockingProfileResolver : IConnectionProfileResolver
    {
        private readonly TaskCompletionSource<ConnectionProfile?> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<ConnectionProfile?> ResolveAsync(
            Guid nodeId,
            CancellationToken cancellationToken = default)
        {
            Started.TrySetResult();
            return _completion.Task;
        }

        public void Complete(ConnectionProfile? profile) => _completion.TrySetResult(profile);
    }

    private sealed class FakeTerminalSession : ITerminalSession
    {
        public int DisposeCount { get; private set; }
        public TaskCompletionSource DisposeStarted { get; set; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource? DisposeRelease { get; set; }

        public event EventHandler<ReadOnlyMemory<byte>>? DataReceived;
        public event EventHandler? Closed;

        public bool IsClosing { get; set; }

        public void Start() { }
        public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
        public Task ResizeAsync(uint columns, uint rows) => Task.CompletedTask;
        public void PauseReading() { }
        public void ResumeReading() { }

        public void RaiseData(params byte[] data) => DataReceived?.Invoke(this, data);
        public void RaiseClosed() => Closed?.Invoke(this, EventArgs.Empty);

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            DisposeStarted.TrySetResult();
            return DisposeRelease is null
                ? ValueTask.CompletedTask
                : new ValueTask(DisposeRelease.Task);
        }
    }
    private sealed class RecordingTerminalOutputSink : ITerminalOutputSink
    {
        private readonly List<byte> _received = new();

        public bool AcceptsOutput { get; set; } = true;
        public bool FlushResult { get; set; } = true;
        public TaskCompletionSource<bool>? FlushRelease { get; set; }
        public TaskCompletionSource? FocusRelease { get; set; }
        public TaskCompletionSource? RetirementRelease { get; set; }
        public byte[] PendingOnDispose { get; set; } = Array.Empty<byte>();
        public bool HasUnacknowledgedOutputOnDispose { get; set; }
        public bool HadUncertainGeometryOnDispose { get; set; }
        public Exception? DisposeException { get; set; }
        public Exception? ReplayException { get; set; }
        public bool IsDisposed { get; private set; }
        public int DisposeCount { get; private set; }
        public int FlushCount { get; private set; }
        public int FocusCount { get; private set; }
        public int RetireCount { get; private set; }
        public byte[] Received => _received.ToArray();
        public TaskCompletionSource FirstFlush { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource FocusRequested { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource FirstRetire { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool TryAppendOutput(ReadOnlyMemory<byte> data)
        {
            _received.AddRange(data.ToArray());
            return AcceptsOutput;
        }

        public void Replay(ReadOnlyMemory<byte> data, bool suppressTerminalResponses)
        {
            if (ReplayException is not null) throw ReplayException;
        }
        public Task<bool> FlushOutputAsync(
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FlushCount++;
            FirstFlush.TrySetResult();
            return FlushRelease?.Task ?? Task.FromResult(FlushResult);
        }
        public Task RequestFocusAsync()
        {
            FocusCount++;
            FocusRequested.TrySetResult();
            return FocusRelease?.Task ?? Task.CompletedTask;
        }

        public Task<TerminalOutputRetirement> RetireAsync(
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RetireCount++;
            FirstRetire.TrySetResult();
            return RetirementRelease is null
                ? Task.FromResult(DisposeAndTakePendingOutput())
                : CompleteRetirementAsync(RetirementRelease.Task);
        }

        private async Task<TerminalOutputRetirement> CompleteRetirementAsync(Task release)
        {
            await release.ConfigureAwait(false);
            return DisposeAndTakePendingOutput();
        }

        public TerminalOutputRetirement DisposeAndTakePendingOutput()
        {
            MarkDisposed();
            if (DisposeException is not null) throw DisposeException;

            var retirement = new TerminalOutputRetirement(
                PendingOnDispose,
                HasUnacknowledgedOutputOnDispose,
                HadUncertainGeometryOnDispose);
            PendingOnDispose = Array.Empty<byte>();
            HasUnacknowledgedOutputOnDispose = false;
            HadUncertainGeometryOnDispose = false;
            return retirement;
        }

        public void Dispose() => MarkDisposed();

        private void MarkDisposed()
        {
            if (IsDisposed) return;
            IsDisposed = true;
            DisposeCount++;
        }
    }
}
