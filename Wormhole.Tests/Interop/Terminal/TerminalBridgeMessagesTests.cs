using System;
using Wormhole.Interop.Terminal;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalBridgeMessagesTests
{
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

    [Fact]
    public void TryParseOutputAck_AcceptsBase64AckWithoutSharedBufferId()
    {
        var ok = TerminalBridgeMessages.TryParseOutputAck("a:128".AsSpan(), out var bytes, out var sharedBufferId);

        Assert.True(ok);
        Assert.Equal(128, bytes);
        Assert.Null(sharedBufferId);
    }

    [Fact]
    public void TryParseOutputAck_AcceptsSharedBufferAckWithId()
    {
        var ok = TerminalBridgeMessages.TryParseOutputAck("a:4096:42".AsSpan(), out var bytes, out var sharedBufferId);

        Assert.True(ok);
        Assert.Equal(4096, bytes);
        Assert.Equal(42, sharedBufferId);
    }

    [Theory]
    [InlineData("a:")]
    [InlineData("a:0")]
    [InlineData("a:-1")]
    [InlineData("a:128:0")]
    [InlineData("a:128:bad")]
    [InlineData("b:128")]
    public void TryParseOutputAck_RejectsMalformedFrames(string frame)
    {
        var ok = TerminalBridgeMessages.TryParseOutputAck(frame.AsSpan(), out var bytes, out var sharedBufferId);

        Assert.False(ok);
        Assert.Equal(0, bytes);
        Assert.Null(sharedBufferId);
    }

    [Fact]
    public void TryParseGeometry_AcceptsUsableResizeFrame()
    {
        var ok = TerminalBridgeMessages.TryParseGeometry(
            "r:132x43".AsSpan(),
            minimumColumns: 20,
            minimumRows: 8,
            out var columns,
            out var rows);

        Assert.True(ok);
        Assert.Equal((uint)132, columns);
        Assert.Equal((uint)43, rows);
    }

    [Theory]
    [InlineData("r:19x43")]
    [InlineData("r:132x7")]
    [InlineData("r:132")]
    [InlineData("ready:132x43")]
    public void TryParseGeometry_RejectsCollapsedOrMalformedResizeFrame(string frame)
    {
        var ok = TerminalBridgeMessages.TryParseGeometry(
            frame.AsSpan(),
            minimumColumns: 20,
            minimumRows: 8,
            out var columns,
            out var rows);

        Assert.False(ok);
        Assert.Equal((uint)0, columns);
        Assert.Equal((uint)0, rows);
    }
}
