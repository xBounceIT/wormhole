using System.Text;
using Wormhole.Services.Ssh;
using Xunit;

namespace Wormhole.Tests.Services.Ssh;

public sealed class ShellCommandPresentationFilterTests
{
    [Fact]
    public void Filter_RemovesWrapperEchoAndMarkers()
    {
        var filter = CreateFilter();
        var input =
            "printf '@@WHS_%s@@\\n' tok; eval 'echo hi'; __wh_rc=$?; printf '@@WHE_%s_%d@@\\n' tok \"$__wh_rc\"\r\n" +
            "@@WHS_tok@@\r\n" +
            "hi\r\n" +
            "@@WHE_tok_0@@\r\n" +
            "$ ";

        var output = Apply(filter, input);

        Assert.Equal("hi\r\n$ ", output);
        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void Filter_RemovesMarkersSplitAcrossChunks()
    {
        var filter = CreateFilter();

        Assert.Equal("", Apply(filter, "printf hidden\r\n@@WHS_"));
        Assert.Equal("he", Apply(filter, "tok@@\r\nhe"));
        Assert.Equal("llo\r\n", Apply(filter, "llo\r\n@@WHE_to"));
        Assert.Equal("$ ", Apply(filter, "k_0@@\r\n$ "));

        Assert.True(filter.IsComplete);
    }

    [Fact]
    public void Filter_PreservesPromptAfterEndMarkerInSameChunk()
    {
        var filter = CreateFilter();

        var output = Apply(filter, "echoed\r\n@@WHS_tok@@\r\nok\r\n@@WHE_tok_2@@\r\nuser@host:~$ ");

        Assert.Equal("ok\r\nuser@host:~$ ", output);
    }

    [Fact]
    public void Filter_PassesFutureOutputAfterCompletion()
    {
        var filter = CreateFilter();

        Assert.Equal("ok\r\n", Apply(filter, "echoed\r\n@@WHS_tok@@\r\nok\r\n@@WHE_tok_0@@\r\n"));
        Assert.Equal("next\r\n", Apply(filter, "next\r\n"));
    }

    [Fact]
    public void Filter_IncompleteCommandDoesNotCompleteOrLeakWrapper()
    {
        var filter = CreateFilter();

        Assert.Equal("partial ", Apply(filter, "printf hidden\r\n@@WHS_tok@@\r\npartial @@WHE_to"));

        Assert.False(filter.IsComplete);
    }

    private static ShellCommandPresentationFilter CreateFilter() =>
        new("@@WHS_tok@@", "@@WHE_tok_");

    private static string Apply(ShellCommandPresentationFilter filter, string text) =>
        Encoding.UTF8.GetString(filter.Filter(Encoding.UTF8.GetBytes(text)));
}
