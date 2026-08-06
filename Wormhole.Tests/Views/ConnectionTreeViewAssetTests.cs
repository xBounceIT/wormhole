using System;
using System.IO;
using Xunit;

namespace Wormhole.Tests.Views;

public sealed class ConnectionTreeViewAssetTests
{
    [Fact]
    public void ExpansionState_FlowsOneWayIntoMaterializedTreeItems()
    {
        var xaml = ReadAsset("ConnectionTreeView.xaml");
        Assert.Contains("<TreeViewItem ItemsSource=", xaml, StringComparison.Ordinal);
        Assert.Contains(
            "IsExpanded=\"{x:Bind IsExpanded, Mode=OneWay}\"",
            xaml,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IsExpanded=\"{x:Bind IsExpanded, Mode=TwoWay}\"",
            xaml,
            StringComparison.Ordinal);
    }

    [Fact]
    public void UserExpansion_IsExplicitlySynchronizedBackToTheViewModel()
    {
        var xaml = ReadAsset("ConnectionTreeView.xaml");
        var code = ReadAsset("ConnectionTreeView.xaml.cs.txt");

        Assert.Contains("Expanding=\"OnTreeExpanding\"", xaml, StringComparison.Ordinal);
        Assert.Contains("Collapsed=\"OnTreeCollapsed\"", xaml, StringComparison.Ordinal);
        Assert.Contains("SetNodeExpanded(args.Node, true);", code, StringComparison.Ordinal);
        Assert.Contains("SetNodeExpanded(args.Node, false);", code, StringComparison.Ordinal);
        Assert.Contains("node.Content is TreeNodeViewModel vm", code, StringComparison.Ordinal);
        Assert.Contains("vm.IsExpanded != expanded", code, StringComparison.Ordinal);
        Assert.Contains("!ViewModel.IsApplyingTreeProjection", code, StringComparison.Ordinal);
        Assert.Contains("item.IsLoaded", code, StringComparison.Ordinal);
        Assert.Contains("_materializingTreeItems.ContainsKey(item)", code, StringComparison.Ordinal);
        Assert.Contains("_materializingTreeItems[item] = materialization;", code, StringComparison.Ordinal);
        Assert.Contains("CompleteTreeItemMaterialization(item, materialization)", code, StringComparison.Ordinal);
        Assert.Contains("_materializingTreeItems.Remove(item);", code, StringComparison.Ordinal);
        Assert.DoesNotContain("IsUserExpansionGesture", code, StringComparison.Ordinal);
        Assert.Contains("vm.IsExpanded = expanded;", code, StringComparison.Ordinal);
    }

    [Fact]
    public void HostTooltip_StaysOnTheSidebarSideOfEmbeddedWebViews()
    {
        var xaml = ReadAsset("ConnectionTreeView.xaml");

        Assert.Contains(
            "ToolTipService.Placement=\"Left\"",
            xaml,
            StringComparison.Ordinal);
    }

    private static string ReadAsset(string fileName) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Views", "Controls", fileName));
}
