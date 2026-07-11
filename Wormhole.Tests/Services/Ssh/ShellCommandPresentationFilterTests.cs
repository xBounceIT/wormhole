using System.Text;
using Wormhole.Services.Ssh;
using Xunit;

namespace Wormhole.Tests.Services.Ssh;

public sealed class ShellCommandPresentationFilterTests
{
    private const string Command = "echo hi";
    private const string Payload =
        "printf '@@WHS_%s@@\\n' tok; eval 'echo hi'; __wh_rc=$?; printf '@@WHE_%s_%d@@\\n' tok \"$__wh_rc\"\r";

    [Fact]
    public void Filter_ReplacesExactWrapperEchoAndMarkersAfterStartProof()
    {
        var filter = CreateFilter();
        var input =
            Payload[..^1] + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "hi\r\n" +
            "@@WHE_tok_0@@\r\n" +
            "$ ";

        var output = Apply(filter, input);

        Assert.Equal("echo hi\r\nhi\r\n$ ", output);
        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void Filter_HandlesEchoAndMarkersSplitAcrossEveryByte()
    {
        var filter = CreateFilter();
        var input =
            Payload[..^1] + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "hello\r\n" +
            "@@WHE_tok_0@@\r\n" +
            "$ ";
        var output = new List<byte>();

        foreach (var value in Encoding.UTF8.GetBytes(input))
        {
            output.AddRange(filter.Filter(new byte[] { value }));
        }

        Assert.Equal("echo hi\r\nhello\r\n$ ", Encoding.UTF8.GetString(output.ToArray()));
        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void Filter_LongByteSplitEcho_IsComparedOnlyOncePerByte()
    {
        var echoBody = new string('x', 16 * 1024);
        var filter = new ShellCommandPresentationFilter(
            Command,
            echoBody + "\r",
            "@@WHS_tok@@",
            "@@WHE_tok_");
        var input =
            echoBody + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "ok\r\n" +
            "@@WHE_tok_0@@\r\n" +
            "$ ";
        var output = new List<byte>();

        foreach (var value in Encoding.UTF8.GetBytes(input))
        {
            output.AddRange(filter.Filter(new byte[] { value }));
        }

        Assert.Equal("echo hi\r\nok\r\n$ ", Encoding.UTF8.GetString(output.ToArray()));
        Assert.Equal(Encoding.UTF8.GetByteCount(echoBody), filter.EchoComparisonCountForTesting);
        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void Filter_FailsOpenImmediatelyForEditorRepaintWithoutStartMarker()
    {
        var filter = CreateFilter();
        var repaint = "\x1b[H\x1b[2Jnano repaint\r\n";

        var output = Apply(filter, repaint);

        Assert.Equal(repaint, output);
        Assert.True(filter.IsComplete);
        Assert.Empty(filter.DrainPending());
    }

    [Fact]
    public void Filter_FailsOpenLosslesslyWhenEchoPrefixLaterMismatches()
    {
        var filter = CreateFilter();
        var prefix = Payload[..20];

        Assert.Equal(string.Empty, Apply(filter, prefix));
        Assert.Equal(prefix + "\x1b[Hvim repaint", Apply(filter, "\x1b[Hvim repaint"));
        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void DrainPending_RestoresExactEchoWhenStartMarkerNeverArrives()
    {
        var filter = CreateFilter();
        var echo = Payload[..^1] + "\r\n";

        Assert.Equal(string.Empty, Apply(filter, echo));

        Assert.Equal(echo, Encoding.UTF8.GetString(filter.DrainPending()));
        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void DrainPending_ReleasesPartialEndMarkerOnTimeout()
    {
        var filter = CreateFilter();
        var prefix =
            Payload[..^1] + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "partial @@WHE_to";

        Assert.Equal("echo hi\r\npartial ", Apply(filter, prefix));
        Assert.Equal("@@WHE_to", Encoding.UTF8.GetString(filter.DrainPending()));
    }

    [Fact]
    public void Filter_SkipsFalsePrefixBeforeRealEndMarkerInSameChunk()
    {
        var filter = CreateFilter();
        var input =
            Payload[..^1] + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "prima @oops dopo @@WHE_tok_0@@\r\n" +
            "$ ";

        Assert.Equal("echo hi\r\nprima @oops dopo $ ", Apply(filter, input));
        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void Filter_SkipsByteSplitFalsePrefixBeforeRealEndMarker()
    {
        var filter = CreateFilter();
        var input =
            Payload[..^1] + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "prima @oops dopo @@WHE_tok_0@@\r\n" +
            "$ ";
        var output = new List<byte>();

        foreach (var value in Encoding.UTF8.GetBytes(input))
        {
            output.AddRange(filter.Filter(new byte[] { value }));
        }

        Assert.Equal(
            "echo hi\r\nprima @oops dopo $ ",
            Encoding.UTF8.GetString(output.ToArray()));
        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void Filter_PreservesPromptAfterEndMarkerInSameChunk()
    {
        var filter = CreateFilter();
        var input =
            Payload[..^1] + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "ok\r\n@@WHE_tok_2@@\r\nuser@host:~$ ";

        Assert.Equal("echo hi\r\nok\r\nuser@host:~$ ", Apply(filter, input));
    }

    [Fact]
    public void Filter_PassesFutureOutputAfterCompletion()
    {
        var filter = CreateFilter();
        var input =
            Payload[..^1] + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "ok\r\n@@WHE_tok_0@@\r\n";

        Assert.Equal("echo hi\r\nok\r\n", Apply(filter, input));
        Assert.Equal("next\r\n", Apply(filter, "next\r\n"));
    }

    [Fact]
    public void Filter_DoesNotBufferUnboundedInvalidEndMarkerDigits()
    {
        var filter = CreateFilter();
        var input =
            Payload[..^1] + "\r\n" +
            "@@WHS_tok@@\r\n" +
            "@@WHE_tok_" + new string('9', 100);

        var visible = Apply(filter, input) + Encoding.UTF8.GetString(filter.DrainPending());

        Assert.Equal("echo hi\r\n@@WHE_tok_" + new string('9', 100), visible);
    }

    [Fact]
    public void Filter_OversizedPayloadStartsInFailOpenMode()
    {
        var payload = new string('x', 70_000) + "\r";
        var filter = new ShellCommandPresentationFilter(Command, payload, "@@WHS_tok@@", "@@WHE_tok_");

        Assert.Equal("raw\r\n", Apply(filter, "raw\r\n"));
        Assert.True(filter.IsComplete);
    }

    private static ShellCommandPresentationFilter CreateFilter() =>
        new(Command, Payload, "@@WHS_tok@@", "@@WHE_tok_");

    private static string Apply(ShellCommandPresentationFilter filter, string text) =>
        Encoding.UTF8.GetString(filter.Filter(Encoding.UTF8.GetBytes(text)));
}
