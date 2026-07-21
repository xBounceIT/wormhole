using System;
using System.IO;
using Xunit;

namespace Wormhole.Tests.Views;

public sealed class SessionsPageAssetTests
{
    [Fact]
    public void SessionSurface_IsHostedOutsideTabViewItems()
    {
        var xaml = ReadAsset("Views", "Pages", "SessionsPage.xaml");
        var code = ReadAsset("Views", "Pages", "SessionsPage.xaml.cs.txt");

        var selectedHostIndex = xaml.IndexOf("x:Name=\"SelectedSessionHost\"", StringComparison.Ordinal);
        Assert.True(selectedHostIndex >= 0, "Selected session surface must be a dedicated host.");
        Assert.Contains(
            "Content=\"{x:Bind ViewModel.SelectedTab, Mode=OneWay}\"",
            xaml,
            StringComparison.Ordinal);
        Assert.Contains(
            "ContentTemplateSelector=\"{StaticResource SessionContentSelector}\"",
            xaml,
            StringComparison.Ordinal);

        var tabItemTemplateIndex = xaml.IndexOf("<TabView.TabItemTemplate>", StringComparison.Ordinal);
        Assert.True(tabItemTemplateIndex >= 0, "Tab headers still need a TabItemTemplate.");
        var tabItemTemplateEnd = xaml.IndexOf("</TabView.TabItemTemplate>", tabItemTemplateIndex, StringComparison.Ordinal);
        Assert.True(tabItemTemplateEnd > tabItemTemplateIndex);

        var tabItemTemplate = xaml[tabItemTemplateIndex..tabItemTemplateEnd];
        Assert.DoesNotContain(
            "ContentTemplateSelector=\"{StaticResource SessionContentSelector}\"",
            tabItemTemplate,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "x:Name=\"SelectedSessionHost\"",
            tabItemTemplate,
            StringComparison.Ordinal);

        Assert.True(
            selectedHostIndex > tabItemTemplateEnd,
            "SelectedSessionHost must sit outside TabViewItem content so sibling tab removal cannot unload it.");

        Assert.Contains("EnsureTabViewHeaderOnlyLayout", code, StringComparison.Ordinal);
        Assert.Contains("root.RowDefinitions[1].Height = new GridLength(0);", code, StringComparison.Ordinal);
    }

    [Fact]
    public void RdpSurfaceHost_RebindsOnDataContextChangeWhileLoaded()
    {
        var code = ReadAsset("Views", "Sessions", "RdpSurfaceHost.xaml.cs.txt");
        Assert.Contains("DataContextChanged += OnDataContextChanged;", code, StringComparison.Ordinal);
        Assert.Contains(
            "private async void OnDataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)",
            code,
            StringComparison.Ordinal);
        Assert.Contains("if (!IsLoaded) return;", code, StringComparison.Ordinal);
        Assert.Contains("_viewModel.DetachView();", code, StringComparison.Ordinal);
        Assert.Contains("await attachingVm.AttachAsync(_ownerHwnd, bounds);", code, StringComparison.Ordinal);
        Assert.Contains("private int _attachGeneration;", code, StringComparison.Ordinal);
        Assert.Contains("CompleteAttachIfCurrent(attachGeneration, attachingVm);", code, StringComparison.Ordinal);
        Assert.Contains("attachingVm.DetachView();", code, StringComparison.Ordinal);
    }

    private static string ReadAsset(params string[] relativeParts) =>
        File.ReadAllText(Path.Combine(new[] { AppContext.BaseDirectory }.Concat(relativeParts).ToArray()));
}
