using System;
using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalBridgeMessagesTests
{
    [Theory]
    [InlineData("fatal:protocol")]
    [InlineData("fatal:unknown-page-failure")]
    [InlineData("fatal:write:999:1")]
    [InlineData("fatal:barrier:999")]
    [InlineData("fatal:clear:999")]
    public void IsPageFatalFrame_AcceptsEveryPageFatalFrame(string frame)
    {
        Assert.True(TerminalBridgeMessages.IsPageFatalFrame(frame.AsSpan()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("fatal")]
    [InlineData("Fatal:protocol")]
    [InlineData("barrier:1")]
    public void IsPageFatalFrame_RejectsNonFatalFrames(string frame)
    {
        Assert.False(TerminalBridgeMessages.IsPageFatalFrame(frame.AsSpan()));
    }

    [Theory]
    [InlineData("barrier:42", "Ready")]
    [InlineData("barrier:41", "Ignore")]
    [InlineData("focus:42", "Ignore")]
    [InlineData("fatal:write:42:1", "CurrentFailure")]
    [InlineData("fatal:barrier:42", "CurrentFailure")]
    [InlineData("fatal:clear:42", "CurrentFailure")]
    [InlineData("fatal:write:41:1", "RecoverableFatal")]
    [InlineData("fatal:barrier:41", "RecoverableFatal")]
    [InlineData("fatal:clear:41", "RecoverableFatal")]
    [InlineData("fatal:protocol", "RecoverableFatal")]
    [InlineData("fatal:clear", "RecoverableFatal")]
    [InlineData("fatal:unknown-page-failure", "RecoverableFatal")]
    [InlineData("fatal:write:42:0", "RecoverableFatal")]
    [InlineData("ready:42", "Ignore")]
    public void ClassifySessionlessReplayMessage_ScopesCompletionAndFailure(
        string frame,
        string expected)
    {
        Assert.Equal(
            expected,
            TerminalBridgeMessages.ClassifySessionlessReplayMessage(frame.AsSpan(), 42).ToString());
    }

    [Fact]
    public void RecoverableFatalFrames_CanBeSupersededByCurrentBarrier()
    {
        Assert.Equal(
            TerminalSessionlessReplayMessageDisposition.RecoverableFatal,
            TerminalBridgeMessages.ClassifySessionlessReplayMessage(
                "fatal:write:41:1".AsSpan(),
                42));
        Assert.Equal(
            TerminalSessionlessReplayMessageDisposition.RecoverableFatal,
            TerminalBridgeMessages.ClassifySessionlessReplayMessage(
                "fatal:protocol".AsSpan(),
                42));
        Assert.Equal(
            TerminalSessionlessReplayMessageDisposition.Ready,
            TerminalBridgeMessages.ClassifySessionlessReplayMessage(
                "barrier:42".AsSpan(),
                42));
    }

    [Fact]
    public void DecodeBase64Bytes_PreservesNanoWriteOutEnterSequence()
    {
        var bytes = TerminalBridgeMessages.DecodeBase64Bytes("Dw0=".AsSpan());

        Assert.Equal(new byte[] { 0x0f, 0x0d }, bytes);
    }

    [Fact]
    public void DecodeBase64Bytes_PreservesCtrlLClearScreen()
    {
        var bytes = TerminalBridgeMessages.DecodeBase64Bytes("DA==".AsSpan());

        Assert.Equal(new byte[] { 0x0c }, bytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad")]
    [InlineData("!!!!")]
    public void DecodeBase64Bytes_RejectsMalformedPayloads(string payload)
    {
        if (payload.Length == 0)
        {
            Assert.Empty(TerminalBridgeMessages.DecodeBase64Bytes(payload.AsSpan()));
            return;
        }

        Assert.Throws<FormatException>(() => TerminalBridgeMessages.DecodeBase64Bytes(payload.AsSpan()));
    }

    [Theory]
    [InlineData("p:1:0", 1, false)]
    [InlineData("p:9223372036854775807:1", long.MaxValue, true)]
    public void TryParsePasteRequest_AcceptsCanonicalBoundedRequest(
        string frame,
        long expectedId,
        bool expectedForce)
    {
        Assert.True(TerminalBridgeMessages.TryParsePasteRequest(
            frame.AsSpan(),
            out var requestId,
            out var force));
        Assert.Equal(expectedId, requestId);
        Assert.Equal(expectedForce, force);
    }

    [Theory]
    [InlineData("p:")]
    [InlineData("p:1")]
    [InlineData("p:0:0")]
    [InlineData("p:01:0")]
    [InlineData("p:+1:0")]
    [InlineData("p:1:2")]
    [InlineData("p:1:0:extra")]
    [InlineData("p:9223372036854775808:0")]
    [InlineData("paste:1:0")]
    public void TryParsePasteRequest_RejectsMalformedRequest(string frame)
    {
        Assert.False(TerminalBridgeMessages.TryParsePasteRequest(
            frame.AsSpan(),
            out var requestId,
            out var force));
        Assert.Equal(0, requestId);
        Assert.False(force);
    }
    [Fact]
    public void TryParseParserBarrierFailure_AcceptsCanonicalStream()
    {
        Assert.True(TerminalBridgeMessages.TryParseParserBarrierFailure(
            "fatal:barrier:42".AsSpan(),
            out var streamId));
        Assert.Equal(42, streamId);
    }

    [Theory]
    [InlineData("fatal:barrier:")]
    [InlineData("fatal:barrier:0")]
    [InlineData("fatal:barrier:01")]
    [InlineData("fatal:barrier:1:2")]
    public void TryParseParserBarrierFailure_RejectsMalformedMessage(string message)
    {
        Assert.False(TerminalBridgeMessages.TryParseParserBarrierFailure(
            message.AsSpan(),
            out var streamId));
        Assert.Equal(0, streamId);
    }

    [Fact]
    public void TryParseTerminalClearFailure_AcceptsCanonicalStream()
    {
        Assert.True(TerminalBridgeMessages.TryParseTerminalClearFailure(
            "fatal:clear:42".AsSpan(),
            out var streamId));
        Assert.Equal(42, streamId);
    }

    [Theory]
    [InlineData("fatal:clear:")]
    [InlineData("fatal:clear:0")]
    [InlineData("fatal:clear:01")]
    [InlineData("fatal:clear:+1")]
    [InlineData("fatal:clear:1:2")]
    [InlineData("fatal:clear")]
    [InlineData("clear:42")]
    public void TryParseTerminalClearFailure_RejectsMalformedMessage(string message)
    {
        Assert.False(TerminalBridgeMessages.TryParseTerminalClearFailure(
            message.AsSpan(),
            out var streamId));
        Assert.Equal(0, streamId);
    }

    [Fact]
    public void TryParseParserBarrierReady_AcceptsCanonicalStream()
    {
        Assert.True(TerminalBridgeMessages.TryParseParserBarrierReady(
            "barrier:42".AsSpan(),
            out var streamId));
        Assert.Equal(42, streamId);
    }

    [Theory]
    [InlineData("barrier:")]
    [InlineData("barrier:0")]
    [InlineData("barrier:01")]
    [InlineData("barrier:+1")]
    [InlineData("barrier:1:2")]
    [InlineData("focus:1")]
    public void TryParseParserBarrierReady_RejectsMalformedStream(string frame)
    {
        Assert.False(TerminalBridgeMessages.TryParseParserBarrierReady(
            frame.AsSpan(),
            out var streamId));
        Assert.Equal(0, streamId);
    }
    [Fact]
    public void TryParseFocusReady_AcceptsCanonicalStream()
    {
        Assert.True(TerminalBridgeMessages.TryParseFocusReady(
            "focus:42".AsSpan(),
            out var streamId));
        Assert.Equal(42, streamId);
    }

    [Theory]
    [InlineData("focus:")]
    [InlineData("focus:0")]
    [InlineData("focus:01")]
    [InlineData("focus:+1")]
    [InlineData("focus:1:2")]
    [InlineData("f:1")]
    public void TryParseFocusReady_RejectsMalformedStream(string frame)
    {
        Assert.False(TerminalBridgeMessages.TryParseFocusReady(frame.AsSpan(), out var streamId));
        Assert.Equal(0, streamId);
    }
    [Theory]
    [InlineData("b:128:u:Gw==", "u")]
    [InlineData("b:128:p:Gw==", "p")]
    public void TryParseInputFrame_AcceptsCanonicalStreamOriginAndReturnsPayloadOffset(
        string frame,
        string expectedOriginToken)
    {
        var ok = TerminalBridgeMessages.TryParseInputFrame(
            frame.AsSpan(),
            out var streamId,
            out var origin,
            out var encodedPayloadOffset);

        Assert.True(ok);
        Assert.Equal(128, streamId);
        Assert.Equal(
            expectedOriginToken == "u" ? TerminalInputOrigin.User : TerminalInputOrigin.Parser,
            origin);
        Assert.Equal("Gw==", frame[encodedPayloadOffset..]);
    }

    [Theory]
    [InlineData("b:")]
    [InlineData("b:1")]
    [InlineData("b:1:Gw==")]
    [InlineData("b:0:u:Gw==")]
    [InlineData("b:+1:u:Gw==")]
    [InlineData("b:01:u:Gw==")]
    [InlineData("b:1:")]
    [InlineData("b:1:u:")]
    [InlineData("b:1:x:Gw==")]
    [InlineData("b:1:U:Gw==")]
    [InlineData("b:1:user:Gw==")]
    [InlineData("b:1:u:Gw==:late")]
    [InlineData("a:1:u:Gw==")]
    public void TryParseInputFrame_RejectsMalformedUnscopedOrUnknownOriginFrames(string frame)
    {
        Assert.False(TerminalBridgeMessages.TryParseInputFrame(
            frame.AsSpan(),
            out var streamId,
            out var origin,
            out var encodedPayloadOffset));
        Assert.Equal(0, streamId);
        Assert.Equal(default, origin);
        Assert.Equal(0, encodedPayloadOffset);
    }

    [Theory]
    [InlineData(128, false, 128, "u", true)]
    [InlineData(128, false, 128, "p", true)]
    [InlineData(128, true, 128, "p", true)]
    [InlineData(128, true, 128, "u", false)]
    [InlineData(128, false, 129, "u", false)]
    [InlineData(128, true, 129, "p", false)]
    public void InputAcceptance_ScopesOriginAcrossActiveAndRetiringBridges(
        long bridgeStreamId,
        bool retiring,
        long inputStreamId,
        string originToken,
        bool expected)
    {
        Assert.Equal(
            expected,
            TerminalBridge.ShouldAcceptInputFrame(
                bridgeStreamId,
                retiring,
                inputStreamId,
                originToken == "u" ? TerminalInputOrigin.User : TerminalInputOrigin.Parser));
    }

    [Fact]
    public void TryParseOutputAck_AcceptsScopedFrameAck()
    {
        var ok = TerminalBridgeMessages.TryParseOutputAck(
            "a:128:42".AsSpan(),
            out var streamId,
            out var frameId);

        Assert.True(ok);
        Assert.Equal(128, streamId);
        Assert.Equal(42, frameId);
    }

    [Theory]
    [InlineData("a:")]
    [InlineData("a:1")]
    [InlineData("a:0:1")]
    [InlineData("a:1:0")]
    [InlineData("a:-1:2")]
    [InlineData("a:1:-2")]
    [InlineData("a:1:2:3")]
    [InlineData("a:bad:2")]
    [InlineData("a:+1:2")]
    [InlineData("a:01:2")]
    [InlineData("a:1:02")]
    [InlineData("a: 1:2")]
    [InlineData("b:1:2")]
    public void TryParseOutputAck_RejectsMalformedFrames(string frame)
    {
        var ok = TerminalBridgeMessages.TryParseOutputAck(
            frame.AsSpan(),
            out var streamId,
            out var frameId);

        Assert.False(ok);
        Assert.Equal(0, streamId);
        Assert.Equal(0, frameId);
    }

    [Fact]
    public void TryParseOutputWriteFailure_AcceptsScopedFrameFailure()
    {
        var ok = TerminalBridgeMessages.TryParseOutputWriteFailure(
            "fatal:write:128:42".AsSpan(),
            out var streamId,
            out var frameId);

        Assert.True(ok);
        Assert.Equal(128, streamId);
        Assert.Equal(42, frameId);
    }

    [Theory]
    [InlineData("fatal:write:")]
    [InlineData("fatal:write:1")]
    [InlineData("fatal:write:0:1")]
    [InlineData("fatal:write:1:0")]
    [InlineData("fatal:write:+1:2")]
    [InlineData("fatal:protocol")]
    [InlineData("a:1:2")]
    public void TryParseOutputWriteFailure_RejectsMalformedFrames(string frame)
    {
        Assert.False(TerminalBridgeMessages.TryParseOutputWriteFailure(
            frame.AsSpan(),
            out var streamId,
            out var frameId));
        Assert.Equal(0, streamId);
        Assert.Equal(0, frameId);
    }

    [Fact]
    public void EncodeOutputFrame_PreservesArbitraryTerminalBytes()
    {
        var frame = TerminalBridgeMessages.EncodeOutputFrame(
            streamId: 7,
            frameId: 9,
            new byte[] { 0x1b, 0x00, 0xff, 0xf0, 0x9f, 0x98, 0x80 });

        Assert.Equal("d:7:9:GwD/8J+YgA==", frame);
    }

    [Fact]
    public void EncodeReplayFrame_UsesSideEffectFreeReplayChannel()
    {
        var frame = TerminalBridgeMessages.EncodeReplayFrame(
            streamId: 7,
            frameId: 9,
            new byte[] { 0x1b, 0x00, 0xff });

        Assert.Equal("q:7:9:GwD/", frame);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 0)]
    [InlineData(-1, 1)]
    [InlineData(1, -1)]
    public void EncodeOutputFrame_RejectsNonPositiveIdentifiers(long streamId, long frameId)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => TerminalBridgeMessages.EncodeOutputFrame(streamId, frameId, new byte[] { 1 }));
    }
    [Fact]
    public void TryParseScopedGeometry_AcceptsCanonicalUsableResizeFrame()
    {
        var ok = TerminalBridgeMessages.TryParseScopedGeometry(
            "r:42:132x43".AsSpan(),
            minimumColumns: 20,
            minimumRows: 8,
            out var streamId,
            out var columns,
            out var rows);

        Assert.True(ok);
        Assert.Equal(42, streamId);
        Assert.Equal((uint)132, columns);
        Assert.Equal((uint)43, rows);
    }

    [Theory]
    [InlineData("r:42:19x43")]
    [InlineData("r:42:132x7")]
    [InlineData("r:42:132")]
    [InlineData("r:132x43")]
    [InlineData("r:0:132x43")]
    [InlineData("r:01:132x43")]
    [InlineData("r:+1:132x43")]
    [InlineData("r: 1:132x43")]
    [InlineData("r:9223372036854775808:132x43")]
    [InlineData("r:42:0132x43")]
    [InlineData("r:42:+132x43")]
    [InlineData("r:42:132x043")]
    [InlineData("r:42:132x+43")]
    [InlineData("r:42:132x43 ")]
    [InlineData("r:42:132x43:1")]
    [InlineData("r:42:132x43x1")]
    [InlineData("ready:42:132x43")]
    public void TryParseScopedGeometry_RejectsNonCanonicalCollapsedOrMalformedFrame(string frame)
    {
        var ok = TerminalBridgeMessages.TryParseScopedGeometry(
            frame.AsSpan(),
            minimumColumns: 20,
            minimumRows: 8,
            out var streamId,
            out var columns,
            out var rows);

        Assert.False(ok);
        Assert.Equal(0, streamId);
        Assert.Equal((uint)0, columns);
        Assert.Equal((uint)0, rows);
    }
    [Fact]
    public void BuildSessionlessReplayMessages_UsesChunkedSideEffectFreeFramesAndNeutralBarrier()
    {
        const long streamId = 73;
        var payload = new byte[(128 * 1024 * 2) + 17];
        for (var i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 251);

        var messages = TerminalBridge.BuildSessionlessReplayMessages(streamId, payload);

        Assert.Equal("clear:73", messages[0]);
        Assert.Equal("k:73", messages[^1]);
        Assert.Equal(5, messages.Count);
        var decoded = new List<byte>();
        for (var i = 1; i < messages.Count - 1; i++)
        {
            var prefix = $"q:{streamId}:{i}:";
            Assert.StartsWith(prefix, messages[i], StringComparison.Ordinal);
            var frame = Convert.FromBase64String(messages[i][prefix.Length..]);
            Assert.InRange(frame.Length, 1, 128 * 1024);
            decoded.AddRange(frame);
        }
        Assert.Equal(payload, decoded);
    }
}
