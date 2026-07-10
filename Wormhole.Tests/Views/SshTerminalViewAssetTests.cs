using System;
using System.IO;
using Xunit;

namespace Wormhole.Tests.Views;

public sealed class SshTerminalViewAssetTests
{
    [Fact]
    public void Initialization_MasksButDoesNotCollapseWebView()
    {
        var xaml = ReadAsset("SshTerminalView.xaml");
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        var webViewIndex = xaml.IndexOf("<controls:WebView2", StringComparison.Ordinal);
        Assert.True(webViewIndex >= 0, "The terminal WebView2 must remain declared in the view.");

        var maskIndex = xaml.IndexOf("<Border x:Name=\"TerminalContentMask\"", StringComparison.Ordinal);
        Assert.True(maskIndex > webViewIndex, "The terminal mask must render above WebView2.");

        var maskEndIndex = xaml.IndexOf("/>", maskIndex, StringComparison.Ordinal);
        Assert.True(maskEndIndex > maskIndex, "The terminal mask declaration must be complete.");

        var baseCoverIndex = xaml.IndexOf("<!-- Base cover:", StringComparison.Ordinal);
        Assert.True(baseCoverIndex > maskEndIndex, "Status overlays must remain above the terminal mask.");
        Assert.Contains("Visibility=\"Visible\"", xaml[maskIndex..maskEndIndex], StringComparison.Ordinal);

        const string visibleAssignment = "TerminalView.Visibility = Visibility.Visible;";
        const string collapsedAssignment = "TerminalView.Visibility = Visibility.Collapsed;";
        const string unloadMethod = "private void OnUnloaded";

        var unloadIndex = code.IndexOf(unloadMethod, StringComparison.Ordinal);
        var collapsedIndex = code.IndexOf(collapsedAssignment, StringComparison.Ordinal);

        Assert.Contains(visibleAssignment, code, StringComparison.Ordinal);
        Assert.True(unloadIndex >= 0, "The unload lifecycle hook must remain present.");
        Assert.True(
            collapsedIndex > unloadIndex,
            "WebView2 may be collapsed only after entering OnUnloaded; initialization needs real bounds.");
        Assert.Equal(
            collapsedIndex,
            code.LastIndexOf(collapsedAssignment, StringComparison.Ordinal));
        Assert.Contains(
            "TerminalContentMask.Visibility = Visibility.Visible;",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "TerminalContentMask.Visibility = Visibility.Collapsed;",
            code,
            StringComparison.Ordinal);
    }

    private static string ReadAsset(string fileName) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Views", "Sessions", fileName));
}
