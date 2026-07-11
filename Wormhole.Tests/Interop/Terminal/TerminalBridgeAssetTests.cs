using System;
using System.IO;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalBridgeAssetTests
{
    [Fact]
    public void Bridge_ForwardsOnDataAsBase64RawBytes()
    {
        var js = ReadBridge();

        Assert.Contains("postInputFrame(inputToBase64(data), isUserInput);", js);
        var inputEncoderStart = js.IndexOf("function inputToBase64(data)", StringComparison.Ordinal);
        var inputEncoderEnd = js.IndexOf("function post(msg)", inputEncoderStart, StringComparison.Ordinal);
        Assert.True(inputEncoderStart >= 0 && inputEncoderEnd > inputEncoderStart);
        var inputEncoder = js[inputEncoderStart..inputEncoderEnd];
        Assert.Contains("return utf8ToBase64(data);", inputEncoder, StringComparison.Ordinal);
        Assert.Contains("return btoa(data);", inputEncoder, StringComparison.Ordinal);
        Assert.DoesNotContain("bin +=", inputEncoder, StringComparison.Ordinal);
        Assert.Contains(
            "const streamId = isUserInput ? focusedInputStreamId : activeParserStreamId;",
            js,
            StringComparison.Ordinal);
        Assert.Contains(
            "const origin = isUserInput ? \"u\" : \"p\";",
            js,
            StringComparison.Ordinal);
        Assert.Contains(
            "const frame = \"b:\" + streamId + \":\" + origin + \":\" + encodedPayload;",
            js,
            StringComparison.Ordinal);
        Assert.Contains("activeParserStreamId = operation.streamId;", js, StringComparison.Ordinal);
        Assert.Contains("focusedInputStreamId = operation.streamId;", js, StringComparison.Ordinal);
        Assert.DoesNotContain("post(\"d:\" + data);", js);
    }

    [Fact]
    public void Bridge_UsesOrderedFramedMessageChannelForTerminalOutput()
    {
        var js = ReadBridge();

        Assert.Contains("enqueueOutputFrame(parseOutputFrame(", js, StringComparison.Ordinal);
        Assert.Contains("msg.startsWith(\"q:\") ? \"replay\" : \"data\"", js, StringComparison.Ordinal);
        Assert.Contains("term.write(operation.bytes, function ()", js, StringComparison.Ordinal);
        Assert.Contains(
            "\"a:\" + operation.streamId + \":\" + operation.frameId,",
            js,
            StringComparison.Ordinal);
        Assert.Contains("isCanonicalPositiveInt64", js, StringComparison.Ordinal);
        Assert.Contains("CANONICAL_BASE64", js, StringComparison.Ordinal);
        Assert.DoesNotContain("sharedbufferreceived", js, StringComparison.Ordinal);
        Assert.DoesNotContain("releaseBuffer", js, StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_OrdersClearBehindWritesAndReportsFatalFailures()
    {
        var js = ReadBridge();

        var barrierIndex = js.IndexOf("term.write(emptyWriteBarrier, function ()", StringComparison.Ordinal);
        var resetIndex = js.IndexOf("term.reset();", barrierIndex, StringComparison.Ordinal);
        Assert.True(barrierIndex >= 0, "Clear must be queued through xterm's write callback.");
        Assert.True(resetIndex > barrierIndex, "Reset must run only after the write barrier completes.");
        Assert.Contains("fatal:protocol", js, StringComparison.Ordinal);
        Assert.Contains("fatal:write:", js, StringComparison.Ordinal);
        Assert.Contains("fatal:clear", js, StringComparison.Ordinal);
        Assert.DoesNotContain("xterm write discarded", js, StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_RepaintsAfterCtrlLWithoutSwallowingInput()
    {
        var js = ReadBridge();

        Assert.Contains("postInputBytes(data, isUserInput);", js);
        Assert.Contains("data.indexOf(\"\\x0c\") >= 0", js);
        Assert.Contains("scheduleControlKeyRepaint();", js);
    }

    [Fact]
    public void Bridge_RespectsSynchronizedOutputAndOrdersPasteBehindRemoteModes()
    {
        var js = ReadBridge();

        Assert.Contains("term.modes && term.modes.synchronizedOutputMode", js, StringComparison.Ordinal);
        Assert.Contains("finishPasteAssembly(msg);", js, StringComparison.Ordinal);
        Assert.Contains("kind: \"pasteRequest\"", js, StringComparison.Ordinal);
        Assert.Contains("kind: \"pasteApply\"", js, StringComparison.Ordinal);
        Assert.Contains("pendingPasteRequests.push(request);", js, StringComparison.Ordinal);
        Assert.Contains("writePasteRequestOperation(operation);", js, StringComparison.Ordinal);
        Assert.Contains("writePasteApplyOperation(operation);", js, StringComparison.Ordinal);
        Assert.Contains("paste-drain:", js, StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_DoesNotPasteOverTrackedMouseInput()
    {
        var js = ReadBridge();

        Assert.Contains("term.modes && term.modes.mouseTrackingMode", js, StringComparison.Ordinal);
        Assert.Contains("!forcePaste && mouseTrackingMode", js, StringComparison.Ordinal);
        Assert.Contains("!operation.force && mouseTrackingMode", js, StringComparison.Ordinal);
        var pasteRequestStart = js.IndexOf("function writePasteRequestOperation", StringComparison.Ordinal);
        var pasteRequestEnd = js.IndexOf("function releaseActivePasteGate", pasteRequestStart, StringComparison.Ordinal);
        Assert.True(pasteRequestStart >= 0 && pasteRequestEnd > pasteRequestStart);
        var pasteRequestBody = js[pasteRequestStart..pasteRequestEnd];
        Assert.Contains("postProtocolMessage(", pasteRequestBody, StringComparison.Ordinal);
        Assert.Contains(
            "\"p:\" + operation.requestId + \":\" + (operation.force ? \"1\" : \"0\")",
            pasteRequestBody,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_AssemblesBoundedPasteBeforeOneAtomicXtermPaste()
    {
        var js = ReadBridge();

        Assert.Contains("MAX_CLIPBOARD_PASTE_BYTES = 1024 * 1024", js, StringComparison.Ordinal);
        Assert.Contains("paste-begin:", js, StringComparison.Ordinal);
        Assert.Contains("paste-chunk:", js, StringComparison.Ordinal);
        Assert.Contains("paste-end:", js, StringComparison.Ordinal);
        Assert.Contains("assembly.receivedBytes !== assembly.expectedBytes", js, StringComparison.Ordinal);
        Assert.Equal(
            1,
            js.Split("term.paste(operation.text);", StringSplitOptions.None).Length - 1);
    }
    [Fact]
    public void Bridge_HoldsLaterInputBehindBoundedNativeOrContextPaste()
    {
        var js = ReadBridge();

        Assert.Contains("container.addEventListener(\"paste\"", js, StringComparison.Ordinal);
        Assert.Contains("e.preventDefault();", js, StringComparison.Ordinal);
        Assert.Contains("pendingPasteRequests.length > 0", js, StringComparison.Ordinal);
        Assert.Contains("outputOperations.push({ kind: \"input\", frame: frame });", js, StringComparison.Ordinal);
        Assert.Contains("completeActivePasteRequest(requestId, true, activePasteGateHeld);", js, StringComparison.Ordinal);
        Assert.Contains("activePasteRequest.requestId", js, StringComparison.Ordinal);
        Assert.Contains("removeQueuedPasteOperations(flushInput);", js, StringComparison.Ordinal);
        Assert.DoesNotContain("Dropped terminal input", js, StringComparison.Ordinal);
        Assert.Contains("paste-cancel:", js, StringComparison.Ordinal);
        Assert.Contains("term.onKey(function (event)", js, StringComparison.Ordinal);
        Assert.Contains("consumeExactInputMarker(data)", js, StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_CorrelatesImeExactlyAndExpiresMouseFocusScopeBeforeBackendTasks()
    {
        var js = ReadBridge();

        Assert.Contains("container.addEventListener(\"compositionend\", captureExactDomInput, true);", js, StringComparison.Ordinal);
        Assert.Contains("container.addEventListener(\"input\", captureExactDomInput, true);", js, StringComparison.Ordinal);
        Assert.Contains("consumeExactInputMarker(data)", js, StringComparison.Ordinal);
        Assert.Contains("queueMicrotaskSafe(function ()", js, StringComparison.Ordinal);
        Assert.Contains("synchronousDomUserInputDepth > 0", js, StringComparison.Ordinal);
        Assert.DoesNotContain("domUserInputActive", js, StringComparison.Ordinal);
        Assert.DoesNotContain("pendingUserKeyData", js, StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_CorrelatesPasteResponsesAndCancelsQueuedPasteWithoutInputLoss()
    {
        var js = ReadBridge();

        Assert.Contains("requestId !== activePasteRequest.requestId", js, StringComparison.Ordinal);
        Assert.Contains("requestId === activePasteRequest.requestId", js, StringComparison.Ordinal);
        Assert.Contains("Ignored stale paste-begin frame.", js, StringComparison.Ordinal);
        Assert.Contains("Ignored stale or malformed paste-cancel frame.", js, StringComparison.Ordinal);
        Assert.Contains("Cancelled a stalled paste transaction to preserve terminal input.", js, StringComparison.Ordinal);

        var overflowIndex = js.IndexOf(
            "Cancelled a stalled paste transaction to preserve terminal input.",
            StringComparison.Ordinal);
        var cancelIndex = js.IndexOf("cancelAllPasteRequests(true);", overflowIndex, StringComparison.Ordinal);
        var queueIndex = js.IndexOf(
            "outputOperations.push({ kind: \"input\", frame: frame });",
            cancelIndex,
            StringComparison.Ordinal);
        Assert.True(cancelIndex > overflowIndex);
        Assert.True(queueIndex > cancelIndex, "Current input must remain ordered after queued input.");
    }

    [Fact]
    public void Bridge_AcknowledgesOrderedFocusOnlyAfterPriorWritesAndFit()
    {
        var js = ReadBridge();

        Assert.Contains("function invalidateFocusOperations()", js, StringComparison.Ordinal);
        Assert.Contains("generation: generation", js, StringComparison.Ordinal);
        Assert.Contains("if (!isActiveFocusOperation(operation)) return;", js, StringComparison.Ordinal);
        Assert.Contains("writeFocusOperation(operation);", js, StringComparison.Ordinal);
        var focusMethod = js.IndexOf("function writeFocusOperation(operation)", StringComparison.Ordinal);
        var fitIndex = js.IndexOf("if (!fitNow(true, true, operation.streamId))", focusMethod, StringComparison.Ordinal);
        var terminalFocusIndex = js.IndexOf("term.focus();", fitIndex, StringComparison.Ordinal);
        var ackIndex = js.IndexOf("\"focus:\" + operation.streamId,", focusMethod, StringComparison.Ordinal);
        Assert.True(fitIndex > focusMethod, "Focus must wait for one usable fit.");
        Assert.True(terminalFocusIndex > fitIndex, "DEC focus input must follow the geometry report.");
        Assert.True(ackIndex > terminalFocusIndex, "Focus ACK must follow focus-generated input.");
        Assert.DoesNotContain("if (msg === \"f:\")", js, StringComparison.Ordinal);
    }
    [Fact]
    public void Bridge_FullReplaySuppressesHistoricalTerminalReplies()
    {
        var js = ReadBridge();

        Assert.Contains("msg.startsWith(\"q:\")", js, StringComparison.Ordinal);
        Assert.Contains("const isReplay = operation.kind === \"replay\";", js, StringComparison.Ordinal);
        Assert.Contains("replayInputSuppressed = true;", js, StringComparison.Ordinal);
        Assert.Contains("if (replayInputSuppressed) return;", js, StringComparison.Ordinal);
        Assert.Contains("replayInputSuppressed = false;", js, StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_SessionBoundariesAbortPasteAndDropDeferredInput()
    {
        var js = ReadBridge();

        var clearIndex = js.IndexOf("function enqueueClearBarrier(streamId)", StringComparison.Ordinal);
        var gateIndex = js.IndexOf("terminalUserInputEnabled = false;", clearIndex, StringComparison.Ordinal);
        var focusCancelIndex = js.IndexOf("invalidateFocusOperations();", clearIndex, StringComparison.Ordinal);
        var cancelIndex = js.IndexOf("cancelAllPasteRequests(false);", clearIndex, StringComparison.Ordinal);
        var resetIndex = js.IndexOf("outputOperations.push({ kind: \"clear\", streamId: streamId || null });", clearIndex, StringComparison.Ordinal);
        Assert.True(gateIndex > clearIndex);
        Assert.True(focusCancelIndex > gateIndex);
        Assert.True(cancelIndex > focusCancelIndex);
        Assert.True(resetIndex > cancelIndex);
        Assert.Contains("blurTerminalWithoutInput();", js, StringComparison.Ordinal);
        Assert.Contains("if (isUserInput && !terminalUserInputEnabled) return;", js, StringComparison.Ordinal);
        Assert.Contains("terminalUserInputEnabled = true;", js, StringComparison.Ordinal);
        Assert.Contains("removeQueuedPasteOperations(flushInput);", js, StringComparison.Ordinal);
        Assert.Contains("MAX_PENDING_PASTE_REQUESTS = 8", js, StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_BoundsAutomaticSelectionTransfer()
    {
        var js = ReadBridge();

        Assert.Contains("MAX_SELECTION_UTF8_BYTES = 4 * 1024 * 1024", js, StringComparison.Ordinal);
        Assert.Contains("utf8ToBase64(sel, MAX_SELECTION_UTF8_BYTES)", js, StringComparison.Ordinal);
        Assert.Contains("if (encoded === null)", js, StringComparison.Ordinal);
    }
    [Fact]
    public void Bridge_ReportsRealResizesWithoutDuplicateAlternateScreenReports()
    {
        var js = ReadBridge();

        Assert.Contains("if (!fitNow(true, true, operation.streamId))", js, StringComparison.Ordinal);
        Assert.Contains("scheduleFocusFit(operation);", js, StringComparison.Ordinal);
        Assert.Contains("\"r:\" + resizeStreamId + \":\" + fitted,", js, StringComparison.Ordinal);
        Assert.Contains("if (generation !== resizeOperationGeneration) return;", js, StringComparison.Ordinal);
        Assert.DoesNotContain("scheduleFit(100, true, true);", js, StringComparison.Ordinal);
        Assert.DoesNotContain("scheduleFit(300, true, true);", js, StringComparison.Ordinal);
        Assert.Contains("term.buffer.onBufferChange(function ()", js, StringComparison.Ordinal);
        Assert.Contains("scheduleFit(0, true, false);", js, StringComparison.Ordinal);
        Assert.DoesNotContain("scheduleFit(50, true, true);", js, StringComparison.Ordinal);
        Assert.Contains(
            "if (resized || (reportResize && (forceReport || fitted !== lastReportedGeometry)))",
            js,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_FailsClosedCriticalPostsAndRetriesReadyHandshake()
    {
        var js = ReadBridge();

        Assert.Contains("function postProtocolMessage(message, diagnostic)", js, StringComparison.Ordinal);
        Assert.Contains("""if (!postProtocolMessage(frame, "forwarding deferred terminal input")) break;""", js, StringComparison.Ordinal);
        Assert.Contains("""postProtocolMessage(frame, "forwarding terminal input");""", js, StringComparison.Ordinal);
        Assert.Contains("""if (!postProtocolMessage(frame, "forwarding batched terminal input")) break;""", js, StringComparison.Ordinal);
        Assert.Contains("""a:" + operation.streamId + ":" + operation.frameId,""", js, StringComparison.Ordinal);
        Assert.Contains("""focus:" + operation.streamId,""", js, StringComparison.Ordinal);
        Assert.Contains("""barrier:" + operation.streamId,""", js, StringComparison.Ordinal);
        Assert.Contains("""r:" + resizeStreamId + ":" + fitted,""", js, StringComparison.Ordinal);
        Assert.Contains("\"requesting an ordered clipboard paste\"", js, StringComparison.Ordinal);
        Assert.DoesNotContain("enterFatalOutputState", js, StringComparison.Ordinal);

        var readyStart = js.IndexOf("if (!readySent)", StringComparison.Ordinal);
        var readyPost = js.IndexOf("""if (!post("ready:" + fitted)) return false;""", readyStart, StringComparison.Ordinal);
        var readyCommit = js.IndexOf("readySent = true;", readyStart, StringComparison.Ordinal);
        var readyGeometryCommit = js.IndexOf("lastReportedGeometry = fitted;", readyStart, StringComparison.Ordinal);
        var readyTimerClear = js.IndexOf("window.clearTimeout(readyTimer);", readyStart, StringComparison.Ordinal);
        Assert.True(readyStart >= 0 && readyPost > readyStart);
        Assert.True(readyCommit > readyPost && readyGeometryCommit > readyCommit);
        Assert.True(readyTimerClear > readyGeometryCommit);
    }

    [Fact]
    public void Bridge_BoundsRetiredStreamsAndRejectsLateSameStreamFocus()
    {
        var js = ReadBridge();

        Assert.Contains("const MAX_RETIRED_STREAM_IDS = 64;", js, StringComparison.Ordinal);
        Assert.Contains("const retiredStreamIds = new Set();", js, StringComparison.Ordinal);
        Assert.Contains("rememberRetiredStream(streamId);", js, StringComparison.Ordinal);
        Assert.Contains("retiredStreamOrder.length > MAX_RETIRED_STREAM_IDS", js, StringComparison.Ordinal);
        Assert.Contains("retiredStreamIds.delete(retiredStreamOrder.shift());", js, StringComparison.Ordinal);
        Assert.Contains("if (outputFailed || retiredStreamIds.has(streamId)) return;", js, StringComparison.Ordinal);

        var retirementStart = js.IndexOf("function beginTerminalRetirement(streamId)", StringComparison.Ordinal);
        var rememberIndex = js.IndexOf("rememberRetiredStream(streamId);", retirementStart, StringComparison.Ordinal);
        var staleClaimGuard = js.IndexOf("if (claimedStreamId && claimedStreamId !== streamId) return;", retirementStart, StringComparison.Ordinal);
        Assert.True(retirementStart >= 0 && rememberIndex > retirementStart);
        Assert.True(staleClaimGuard > rememberIndex, "Even a stale x: must retire its own stream id.");
    }

    [Fact]
    public void Bridge_UsesTwoPhaseRetirementThatReleasesPasteAndRestartsDrain()
    {
        var js = ReadBridge();

        var retirementStart = js.IndexOf("function beginTerminalRetirement(streamId)", StringComparison.Ordinal);
        var retirementEnd = js.IndexOf("function enqueueFocus", retirementStart, StringComparison.Ordinal);
        Assert.True(retirementStart >= 0 && retirementEnd > retirementStart);
        var retirement = js[retirementStart..retirementEnd];

        var clearFocusIndex = retirement.IndexOf("focusedInputStreamId = null;", StringComparison.Ordinal);
        var freezeResizeIndex = retirement.IndexOf("freezePostReadyAutoFit();", StringComparison.Ordinal);
        var disableInputIndex = retirement.IndexOf("terminalUserInputEnabled = false;", StringComparison.Ordinal);
        var invalidateFocusIndex = retirement.IndexOf("invalidateFocusOperations();", StringComparison.Ordinal);
        var cancelPasteIndex = retirement.IndexOf("cancelAllPasteRequests(false);", StringComparison.Ordinal);
        var restartDrainIndex = retirement.IndexOf("drainOutputOperations();", StringComparison.Ordinal);
        Assert.True(clearFocusIndex >= 0 && freezeResizeIndex > clearFocusIndex);
        Assert.True(disableInputIndex > freezeResizeIndex);
        Assert.True(invalidateFocusIndex > disableInputIndex);
        Assert.True(cancelPasteIndex > invalidateFocusIndex);
        Assert.True(restartDrainIndex > cancelPasteIndex);
        Assert.DoesNotContain("enqueueParserBarrier(", retirement, StringComparison.Ordinal);
        Assert.DoesNotContain("fitNow(", retirement, StringComparison.Ordinal);

        var cancelStart = js.IndexOf("function cancelAllPasteRequests(flushInput)", StringComparison.Ordinal);
        var cancelEnd = js.IndexOf("function postInputFrame", cancelStart, StringComparison.Ordinal);
        Assert.True(cancelStart >= 0 && cancelEnd > cancelStart);
        Assert.Contains(
            "if (releaseHeldGate) outputWriteActive = false;",
            js[cancelStart..cancelEnd],
            StringComparison.Ordinal);

        var xHandlerIndex = js.IndexOf("if (msg.startsWith(\"x:\"))", StringComparison.Ordinal);
        var retirementCallIndex = js.IndexOf("beginTerminalRetirement(streamId);", xHandlerIndex, StringComparison.Ordinal);
        var kHandlerIndex = js.IndexOf("if (msg.startsWith(\"k:\"))", retirementCallIndex, StringComparison.Ordinal);
        Assert.True(xHandlerIndex >= 0 && retirementCallIndex > xHandlerIndex);
        Assert.True(kHandlerIndex > retirementCallIndex);
    }

    [Fact]
    public void NativeBridge_StaleCoalesceCallbacksCannotPostAfterTransportFailure()
    {
        var source = ReadNativeBridge();

        var timerStart = source.IndexOf("private void StartCoalesceTimer()", StringComparison.Ordinal);
        var drainStart = source.IndexOf("private void DrainOutput()", timerStart, StringComparison.Ordinal);
        var postStart = source.IndexOf("private bool PostOutputFrame(", drainStart, StringComparison.Ordinal);
        var watchdogStart = source.IndexOf("private void RestartOutputAcknowledgementWatchdog()", postStart, StringComparison.Ordinal);
        Assert.True(timerStart >= 0 && drainStart > timerStart && postStart > drainStart && watchdogStart > postStart);
        Assert.Contains(
            "if (_disposed || IsOutputTransportFailed) return;",
            source[timerStart..drainStart],
            StringComparison.Ordinal);
        Assert.Contains(
            "if (_disposed || IsOutputTransportFailed) return;",
            source[drainStart..postStart],
            StringComparison.Ordinal);
        Assert.Contains(
            "if (_disposed || IsOutputTransportFailed) return false;",
            source[postStart..watchdogStart],
            StringComparison.Ordinal);
    }
    [Fact]
    public void NativeBridge_DrainsMatchingResizeDuringRetirementBeforeParserBarrier()
    {
        var source = ReadNativeBridge();
        var handlerStart = source.IndexOf("private void OnWebMessageReceived(", StringComparison.Ordinal);
        var handlerEnd = source.IndexOf("private void StartWebMessageProcessor()", handlerStart, StringComparison.Ordinal);
        Assert.True(handlerStart >= 0 && handlerEnd > handlerStart);
        var handler = source[handlerStart..handlerEnd];

        var resizeIndex = handler.IndexOf("var isAcceptedResize = false;", StringComparison.Ordinal);
        var resizeParseIndex = handler.IndexOf("TryParseScopedGeometry(", resizeIndex, StringComparison.Ordinal);
        var barrierIndex = handler.IndexOf("var isRetirementBarrier =", resizeParseIndex, StringComparison.Ordinal);
        var filterIndex = handler.IndexOf("!isAcceptedResize", barrierIndex, StringComparison.Ordinal);
        var enqueueIndex = handler.IndexOf("_pendingWebMessages.Enqueue(msg);", filterIndex, StringComparison.Ordinal);
        Assert.True(resizeIndex >= 0 && resizeParseIndex > resizeIndex);
        Assert.True(barrierIndex > resizeParseIndex && filterIndex > barrierIndex && enqueueIndex > filterIndex);

        var processorStart = source.IndexOf("private async Task ProcessWebMessageQueueAsync()", StringComparison.Ordinal);
        var processorEnd = source.IndexOf("private bool TryHandleOutputControlMessage", processorStart, StringComparison.Ordinal);
        Assert.True(processorStart >= 0 && processorEnd > processorStart);
        Assert.Contains(
            "await ProcessWebMessageAsync(msg).ConfigureAwait(true);",
            source[processorStart..processorEnd],
            StringComparison.Ordinal);
    }

    [Fact]
    public void NativeBridge_OrdersRetirementBoundaryFlushAndParserProofUnderOneDeadline()
    {
        var source = ReadNativeBridge();
        var retirementStart = source.IndexOf(
            "private async Task<TerminalOutputRetirement> RetireCoreAsync(",
            StringComparison.Ordinal);
        var retirementEnd = source.IndexOf(
            "private static TimeSpan RemainingUntil",
            retirementStart,
            StringComparison.Ordinal);
        Assert.True(retirementStart >= 0 && retirementEnd > retirementStart);
        var retirement = source[retirementStart..retirementEnd];

        var completionIndex = retirement.IndexOf("ref _retirementInputCompletion,", StringComparison.Ordinal);
        var sealIndex = retirement.IndexOf("_outputPump.Seal()", StringComparison.Ordinal);
        var boundaryIndex = retirement.IndexOf("\"x:\" + _streamId", StringComparison.Ordinal);
        var flushIndex = retirement.IndexOf("await FlushOutputAsync(", StringComparison.Ordinal);
        var parserBarrierIndex = retirement.IndexOf("\"k:\" + _streamId", StringComparison.Ordinal);
        var waitIndex = retirement.IndexOf("await WaitForRetirementInputBarrierAsync(", StringComparison.Ordinal);
        Assert.True(completionIndex >= 0 && sealIndex > completionIndex);
        Assert.True(boundaryIndex > sealIndex);
        Assert.True(flushIndex > boundaryIndex);
        Assert.True(parserBarrierIndex > flushIndex);
        Assert.True(waitIndex > parserBarrierIndex);
        Assert.True(
            retirement.Split("RemainingUntil(deadline)", StringSplitOptions.None).Length - 1 >= 3,
            "Native flush and parser proof must share one caller-owned deadline.");
        Assert.True(
            source.Split("ShouldAcceptInputFrame(", StringSplitOptions.None).Length - 1 >= 3,
            "Input origin must be checked both on WebView admission and after FIFO queueing.");
    }
    [Fact]
    public void NativeBridge_MapsOnlyExactRetirementProofToCertainGeometry()
    {
        var source = ReadNativeBridge();
        var retirementStart = source.IndexOf(
            "private async Task<TerminalOutputRetirement> RetireCoreAsync(",
            StringComparison.Ordinal);
        var retirementEnd = source.IndexOf(
            "private static async Task<bool> WaitForRetirementInputBarrierAsync(",
            retirementStart,
            StringComparison.Ordinal);
        Assert.True(retirementStart >= 0 && retirementEnd > retirementStart);
        var retirement = source[retirementStart..retirementEnd];

        Assert.Contains(
            "hadUncertainGeometry: !exactRetirement",
            retirement,
            StringComparison.Ordinal);

        var publicDisposeStart = source.IndexOf(
            "public TerminalOutputRetirement DisposeAndTakePendingOutput() =>",
            StringComparison.Ordinal);
        var privateDisposeStart = source.IndexOf(
            "private TerminalOutputRetirement DisposeAndTakePendingOutput(",
            publicDisposeStart,
            StringComparison.Ordinal);
        Assert.True(publicDisposeStart >= 0 && privateDisposeStart > publicDisposeStart);
        Assert.Contains(
            "hadUncertainGeometry: true",
            source[publicDisposeStart..privateDisposeStart],
            StringComparison.Ordinal);
        Assert.Contains(
            "HadUncertainGeometry = hadUncertainGeometry",
            source[privateDisposeStart..],
            StringComparison.Ordinal);
    }


    [Fact]
    public void NativeBridge_WakesRetirementProofOnEveryFatalPageFailure()
    {
        var source = ReadNativeBridge();
        var failureStart = source.IndexOf("private void FailOutputTransport", StringComparison.Ordinal);
        var failureEnd = source.IndexOf("private void TryResumeProducerAfterFailure", failureStart, StringComparison.Ordinal);
        Assert.True(failureStart >= 0 && failureEnd > failureStart);
        var failure = source[failureStart..failureEnd];
        var retirementWakeIndex = failure.IndexOf(
            "Volatile.Read(ref _retirementInputCompletion)?.TrySetException(failure);",
            StringComparison.Ordinal);
        var oneShotFailureIndex = failure.IndexOf(
            "Interlocked.Exchange(ref _outputTransportFailed, 1)",
            StringComparison.Ordinal);
        Assert.True(oneShotFailureIndex >= 0 && retirementWakeIndex > oneShotFailureIndex);

        var retirementStart = source.IndexOf(
            "private async Task<TerminalOutputRetirement> RetireCoreAsync(",
            StringComparison.Ordinal);
        var retirementEnd = source.IndexOf(
            "private static TimeSpan RemainingUntil",
            retirementStart,
            StringComparison.Ordinal);
        Assert.True(retirementStart >= 0 && retirementEnd > retirementStart);
        var retirement = source[retirementStart..retirementEnd];
        var installIndex = retirement.IndexOf("ref _retirementInputCompletion,", StringComparison.Ordinal);
        var recheckIndex = retirement.IndexOf("if (IsOutputTransportFailed)", installIndex, StringComparison.Ordinal);
        var sealIndex = retirement.IndexOf("_outputPump.Seal()", recheckIndex, StringComparison.Ordinal);
        Assert.True(installIndex >= 0 && recheckIndex > installIndex && sealIndex > recheckIndex);

        var handlerStart = source.IndexOf("private bool TryHandleOutputControlMessage", StringComparison.Ordinal);
        var handlerEnd = source.IndexOf("private async Task ProcessWebMessageAsync", handlerStart, StringComparison.Ordinal);
        Assert.True(handlerStart >= 0 && handlerEnd > handlerStart);
        var handler = source[handlerStart..handlerEnd];
        var parserFailureIndex = handler.IndexOf("TryParseParserBarrierFailure(", StringComparison.Ordinal);
        var parserFailClosedIndex = handler.IndexOf("FailOutputTransport(", parserFailureIndex, StringComparison.Ordinal);
        var unknownFatalIndex = handler.IndexOf(
            "if (msg.StartsWith(\"fatal:\", StringComparison.Ordinal))",
            StringComparison.Ordinal);
        var unknownFailClosedIndex = handler.IndexOf("FailOutputTransport(", unknownFatalIndex, StringComparison.Ordinal);
        Assert.True(parserFailureIndex >= 0 && parserFailClosedIndex > parserFailureIndex);
        Assert.True(unknownFatalIndex > parserFailClosedIndex && unknownFailClosedIndex > unknownFatalIndex);
    }

    [Fact]
    public void NativeBridge_AllPasteCancellationPathsUseFailClosedHelper()
    {
        var source = ReadNativeBridge();
        var callbackStart = source.IndexOf(
            "private void StartClipboardPasteRequest(",
            StringComparison.Ordinal);
        var callbackEnd = source.IndexOf(
            "internal static void StartObservedOperation(",
            callbackStart,
            StringComparison.Ordinal);
        Assert.True(callbackStart >= 0 && callbackEnd > callbackStart);
        var callback = source[callbackStart..callbackEnd];
        Assert.Contains("PostClipboardPasteCancellation(", callback, StringComparison.Ordinal);
        Assert.DoesNotContain("\"paste-cancel:\"", callback, StringComparison.Ordinal);

        var processStart = source.IndexOf(
            "private async Task ProcessClipboardPasteRequestAsync(",
            StringComparison.Ordinal);
        var helperStart = source.IndexOf(
            "private void PostClipboardPasteCancellation(",
            processStart,
            StringComparison.Ordinal);
        Assert.True(processStart >= 0 && helperStart > processStart);
        var process = source[processStart..helperStart];
        Assert.Equal(
            2,
            process.Split("PostClipboardPasteCancellation(", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("\"paste-cancel:\"", process, StringComparison.Ordinal);

        var helperEnd = source.IndexOf(
            "private Task<bool> WaitForOutputBarrierAsync(",
            helperStart,
            StringComparison.Ordinal);
        Assert.True(helperEnd > helperStart);
        var helper = source[helperStart..helperEnd];
        var postIndex = helper.IndexOf("if (!PostStringToWebView(", StringComparison.Ordinal);
        var failIndex = helper.IndexOf("FailOutputTransport(operation);", StringComparison.Ordinal);
        Assert.True(postIndex >= 0 && failIndex > postIndex);
        Assert.Contains("\"paste-cancel:\" + pasteRequestId.ToString(", helper, StringComparison.Ordinal);
    }

    [Fact]
    public void Terminal_DoesNotEnableProposedXtermApis()
    {
        var js = ReadBridge();

        Assert.DoesNotContain("allowProposedApi", js, StringComparison.Ordinal);
    }

    [Fact]
    public void Terminal_UsesDefaultRenderer_NotWebglAddon()
    {
        var html = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Assets", "web", "terminal.html"));
        var js = ReadBridge();

        Assert.DoesNotContain("addon-webgl", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("WebglAddon", js, StringComparison.Ordinal);
        Assert.DoesNotContain("new Webgl", js, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("clearTextureAtlas", js, StringComparison.Ordinal);
        Assert.Contains("scrollback: 10000", js, StringComparison.Ordinal);
        Assert.DoesNotContain("padding: 4px;", html, StringComparison.Ordinal);
    }

    [Fact]
    public void WebAssetFetch_PrunesRetiredWebglAddon()
    {
        var script = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "scripts", "Fetch-WebAssets.ps1"));

        Assert.DoesNotContain("cdn.jsdelivr.net/npm/@xterm/addon-webgl", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ManifestPrefix = \"addon-webgl\\\"", script, StringComparison.Ordinal);
        Assert.Contains("Remove-Item -LiteralPath $retiredPath -Recurse -Force", script, StringComparison.Ordinal);
    }

    private static string ReadBridge()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Assets", "web", "bridge.js");
        return File.ReadAllText(path);
    }

    private static string ReadNativeBridge()
    {
        var path = Path.Combine(
            AppContext.BaseDirectory,
            "Interop",
            "Terminal",
            "TerminalBridge.cs.txt");
        return File.ReadAllText(path);
    }
}
