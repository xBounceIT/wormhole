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
        Assert.Contains("IsUserExpansionGesture(node)", code, StringComparison.Ordinal);
        Assert.Contains("ReferenceEquals(_hoveredTreeItem, item)", code, StringComparison.Ordinal);
        Assert.Contains("VirtualKey.LeftButton", code, StringComparison.Ordinal);
        Assert.Contains("VirtualKey.Left", code, StringComparison.Ordinal);
        Assert.Contains("VirtualKey.Right", code, StringComparison.Ordinal);
        Assert.Contains("vm.IsExpanded = expanded;", code, StringComparison.Ordinal);
    }

    private static string ReadAsset(string fileName) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Views", "Controls", fileName));
}
