using System;
using System.IO;
using Xunit;

namespace Wormhole.Tests.Views;

public sealed class WebBrowserViewAssetTests
{
    [Fact]
    public void InitialBitwardenSynchronization_IsBestEffortAndDoesNotPollutePageHistory()
    {
        var code = ReadAsset();
        var create = Slice(
            code,
            "private async Task CreateAndNavigateAsync(HttpConnectionTarget target)",
            "private async Task<BrowserEnvironmentSelection> ResolveEnvironmentAsync");
        var bridge = Slice(
            code,
            "private async Task TrySynchronizeBitwardenStorageBeforeInitialNavigationAsync(",
            "private async Task CaptureBitwardenStorageAsync(CoreWebView2 core)");

        var synchronizeIndex = create.IndexOf(
            "await TrySynchronizeBitwardenStorageBeforeInitialNavigationAsync(",
            StringComparison.Ordinal);
        var navigateIndex = create.IndexOf(
            "core.Navigate(target.NavigateUri.ToString());",
            StringComparison.Ordinal);

        Assert.True(synchronizeIndex >= 0 && navigateIndex > synchronizeIndex);
        Assert.DoesNotContain(
            "SynchronizeBitwardenStorageAsync(core, extensionUserDataFolder)",
            create,
            StringComparison.Ordinal);
        Assert.Contains(
            "var bridgeWebView = new WinUIWebView2 { Visibility = Visibility.Collapsed };",
            bridge,
            StringComparison.Ordinal);
        Assert.Contains("WebViewHost.Children.Add(bridgeWebView);", bridge, StringComparison.Ordinal);
        Assert.Contains("await bridgeWebView.EnsureCoreWebView2Async(environment);", bridge, StringComparison.Ordinal);
        Assert.Contains(
            "await SynchronizeBitwardenStorageAsync(bridgeCore, userDataFolder).ConfigureAwait(true);",
            bridge,
            StringComparison.Ordinal);
        Assert.Contains("catch (Exception ex)", bridge, StringComparison.Ordinal);
        Assert.Contains("finally", bridge, StringComparison.Ordinal);
        Assert.Contains("bridgeWebView.Close();", bridge, StringComparison.Ordinal);
        Assert.Contains("WebViewHost.Children.Remove(bridgeWebView);", bridge, StringComparison.Ordinal);
    }

    private static string Slice(string source, string startMarker, string endMarker)
    {
        var start = source.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.True(start >= 0, $"Start marker not found: {startMarker}");
        var end = source.IndexOf(endMarker, start, StringComparison.Ordinal);
        Assert.True(end > start, $"End marker not found after start: {endMarker}");
        return source[start..end];
    }

    private static string ReadAsset() =>
        File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory,
            "Views",
            "Sessions",
            "WebBrowserView.xaml.cs.txt"));
}
