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

        var layoutHostIndex = xaml.IndexOf("x:Name=\"SessionLayout\"", StringComparison.Ordinal);
        Assert.True(layoutHostIndex >= 0, "Session layout host must be a dedicated multi-pane host.");
        Assert.Contains(
            "Controller=\"{x:Bind ViewModel.Layout, Mode=OneWay}\"",
            xaml,
            StringComparison.Ordinal);
        Assert.Contains("sessionViews:SessionLayoutHost", xaml, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Content=\"{x:Bind ViewModel.SelectedTab, Mode=OneWay}\"",
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
            "x:Name=\"SessionLayout\"",
            tabItemTemplate,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "sessionViews:SessionLayoutHost",
            tabItemTemplate,
            StringComparison.Ordinal);

        Assert.True(
            layoutHostIndex > tabItemTemplateEnd,
            "SessionLayout must sit outside TabViewItem content so sibling tab removal cannot unload it.");

        Assert.Contains("EnsureTabViewHeaderOnlyLayout", code, StringComparison.Ordinal);
        Assert.Contains("root.RowDefinitions[1].Height = new GridLength(0);", code, StringComparison.Ordinal);
        Assert.Contains("SessionTabs_TabDragStarting", code, StringComparison.Ordinal);
        Assert.Contains("SessionTabs_TabStripDrop", code, StringComparison.Ordinal);
        Assert.Contains("RestoreTabToFullView", code, StringComparison.Ordinal);
        Assert.Contains("UpdateGlobalTabStripVisibility", code, StringComparison.Ordinal);
        Assert.Contains("SyncSessionSurfaces", code, StringComparison.Ordinal);

        var paneHost = ReadAsset("Views", "Sessions", "SessionPaneHost.xaml.txt");
        Assert.Contains("TitleChip", paneHost, StringComparison.Ordinal);
        Assert.Contains("FileTransferButton", paneHost, StringComparison.Ordinal);
        Assert.Contains("HeaderContextFlyout", paneHost, StringComparison.Ordinal);
        Assert.Contains("StartDragAsync", ReadAsset("Views", "Sessions", "SessionPaneHost.xaml.cs.txt"), StringComparison.Ordinal);
        Assert.Contains("ConnectionHeaderDrop", ReadAsset("Views", "Sessions", "SessionPaneHost.xaml.cs.txt"), StringComparison.Ordinal);
        Assert.Contains("MoveOntoLeaf", ReadAsset("Views", "Sessions", "SessionLayoutHost.xaml.cs.txt"), StringComparison.Ordinal);
        Assert.Contains("OnConnectionHeaderDrop", ReadAsset("Views", "Sessions", "SessionLayoutHost.xaml.cs.txt"), StringComparison.Ordinal);

        var layoutHost = ReadAsset("Views", "Sessions", "SessionLayoutHost.xaml.cs.txt");
        Assert.Contains("SyncSurfaces", layoutHost, StringComparison.Ordinal);
        Assert.Contains("SetSessionSurfaceActive", layoutHost, StringComparison.Ordinal);
        Assert.Contains("ResolveTemplate", layoutHost, StringComparison.Ordinal);
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
        Assert.Contains("_lastNegotiatedWidthPx = 0;", code, StringComparison.Ordinal);
        Assert.Contains("_lastNegotiatedHeightPx = 0;", code, StringComparison.Ordinal);
        Assert.Contains("ISessionSurfaceActivation", code, StringComparison.Ordinal);
        Assert.Contains("SetSessionSurfaceActive", code, StringComparison.Ordinal);
    }

    [Fact]
    public void WebBrowserView_RebindsOnDataContextChangeWhileLoaded()
    {
        var code = ReadAsset("Views", "Sessions", "WebBrowserView.xaml.cs.txt");
        Assert.Contains("DataContextChanged += OnDataContextChanged;", code, StringComparison.Ordinal);
        Assert.Contains(
            "private async void OnDataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)",
            code,
            StringComparison.Ordinal);
        Assert.Contains("AttachCurrentViewModelAsync", code, StringComparison.Ordinal);
        Assert.Contains("if (!IsLoaded) return;", code, StringComparison.Ordinal);
        Assert.Contains("ISessionSurfaceActivation", code, StringComparison.Ordinal);
        Assert.Contains("SetSessionSurfaceActive", code, StringComparison.Ordinal);
    }

    [Fact]
    public void SshTerminalView_KeepsBridgeAliveWhenSurfaceDeactivated()
    {
        var code = ReadAsset("Views", "Sessions", "SshTerminalView.xaml.cs.txt");
        Assert.Contains("ISessionSurfaceActivation", code, StringComparison.Ordinal);
        Assert.Contains("public void SetSessionSurfaceActive(bool isActive)", code, StringComparison.Ordinal);
        Assert.Contains(
            "keep the TerminalBridge attached so switching back does",
            code,
            StringComparison.Ordinal);

        var body = GetSetSessionSurfaceActiveBody(code);
        Assert.Contains("if (_sessionSurfaceActive == isActive) return;", body, StringComparison.Ordinal);
        Assert.DoesNotContain("DetachView", body, StringComparison.Ordinal);
        Assert.Contains("TerminalView.Visibility = Visibility.Collapsed", body, StringComparison.Ordinal);
    }

    private static string GetSetSessionSurfaceActiveBody(string code)
    {
        var start = code.IndexOf("public void SetSessionSurfaceActive(bool isActive)", StringComparison.Ordinal);
        Assert.True(start >= 0);
        var end = code.IndexOf("private async void OnLoaded", start, StringComparison.Ordinal);
        Assert.True(end > start);
        return code[start..end];
    }

    private static string ReadAsset(params string[] relativeParts) =>
        File.ReadAllText(Path.Combine(new[] { AppContext.BaseDirectory }.Concat(relativeParts).ToArray()));
}
