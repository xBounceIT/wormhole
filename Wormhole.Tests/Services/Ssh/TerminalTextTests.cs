using Wormhole.Services.Ssh;
using Xunit;

namespace Wormhole.Tests.Services.Ssh;

public sealed class TerminalTextTests
{
    [Fact]
    public void StripAnsi_RemovesCsiColorCodes()
    {
        Assert.Equal("green", TerminalText.StripAnsi("\x1b[32mgreen\x1b[0m"));
    }

    [Fact]
    public void StripAnsi_RemovesCsiCursorMoves()
    {
        Assert.Equal("ab", TerminalText.StripAnsi("a\x1b[2J\x1b[Hb"));
    }

    [Fact]
    public void StripAnsi_RemovesBelTerminatedOsc()
    {
        // Window-title OSC (ESC ] 0 ; title BEL) should vanish, leaving only the body text.
        Assert.Equal("text", TerminalText.StripAnsi("\x1b]0;my title\x07text"));
    }

    [Fact]
    public void StripAnsi_RemovesStTerminatedOscHyperlinks()
    {
        // OSC 8 hyperlink wrappers terminated by ST (ESC \) around the visible "link".
        var input = "\x1b]8;;http://example.com\x1b\\link\x1b]8;;\x1b\\";
        Assert.Equal("link", TerminalText.StripAnsi(input));
    }

    [Fact]
    public void StripAnsi_CollapsesCrlfToLf()
    {
        Assert.Equal("a\nb", TerminalText.StripAnsi("a\r\nb"));
    }

    [Fact]
    public void StripAnsi_DropsBareCarriageReturns()
    {
        // Bare CRs are removed (not emulated as cursor-to-column-0 overwrites — StripAnsi
        // flattens control sequences, it doesn't render a screen).
        Assert.Equal("50%100%done", TerminalText.StripAnsi("50%\r100%done"));
    }

    [Fact]
    public void StripAnsi_LeavesPlainTextUntouched()
    {
        Assert.Equal("hello world", TerminalText.StripAnsi("hello world"));
    }

    [Fact]
    public void StripAnsi_EmptyInput_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, TerminalText.StripAnsi(string.Empty));
    }
}
