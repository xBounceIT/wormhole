using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class TerminalRendererOwnershipAssetTests
{
    [Theory]
    [InlineData("SshSessionViewModel.cs.txt")]
    [InlineData("SerialSessionViewModel.cs.txt")]
    public void InternalRendererFailurePaths_UseTheSinkBoundRendererIdentity(string assetName)
    {
        var code = File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "ViewModels", "Sessions", assetName))
            .ReplaceLineEndings("\n");
        var attach = ExtractMethod(
            code,
            "public async Task AttachAsync(",
            "internal bool ShouldDeferAutoConnectOnReattach()");
        var focus = ExtractMethod(
            code,
            "private async Task<bool> CompleteConnectedAfterCurrentTerminalFocusAsync(",
            "private bool IsConnectionAwaitingTerminalFocus(");

        Assert.Contains(
            "TryHandleTerminalRendererFailureAsync(\n                    webView,",
            attach,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "await HandleTerminalRendererFailureAsync(",
            attach,
            StringComparison.Ordinal);

        Assert.Contains(
            "focusRendererIdentity = _bridgeRendererIdentity;",
            focus,
            StringComparison.Ordinal);
        Assert.Contains(
            "TryHandleTerminalRendererFailureAsync(\n                    focusRendererIdentity,",
            focus,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "await HandleTerminalRendererFailureAsync(",
            focus,
            StringComparison.Ordinal);
    }

    private static string ExtractMethod(string code, string startMarker, string endMarker)
    {
        var start = code.IndexOf(startMarker, StringComparison.Ordinal);
        var end = code.IndexOf(endMarker, start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        return code[start..end];
    }
}
