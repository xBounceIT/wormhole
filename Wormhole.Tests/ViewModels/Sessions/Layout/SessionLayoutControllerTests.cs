using Wormhole.ViewModels.Sessions.Layout;
using Xunit;

namespace Wormhole.Tests.ViewModels.Sessions.Layout;

public sealed class SessionLayoutControllerTests
{
    [Fact]
    public void EnsureSingle_CreatesFocusedLeaf()
    {
        var layout = new SessionLayoutController();
        var tab = new StubSessionTab("a");

        layout.EnsureSingle(tab);

        Assert.Equal(1, layout.LeafCount);
        Assert.Same(tab, layout.FocusedTab);
        Assert.True(layout.FocusedLeaf!.IsFocused);
        Assert.Same(tab, Assert.IsType<SessionLeafNode>(layout.Root).Tab);
    }

    [Fact]
    public void EnsureSingle_Null_Clears()
    {
        var layout = new SessionLayoutController();
        layout.EnsureSingle(new StubSessionTab("a"));

        layout.EnsureSingle(null);

        Assert.Null(layout.Root);
        Assert.Null(layout.FocusedLeaf);
        Assert.Equal(0, layout.LeafCount);
    }

    [Theory]
    [InlineData(SessionLayoutEdge.Left, SessionSplitOrientation.Horizontal)]
    [InlineData(SessionLayoutEdge.Right, SessionSplitOrientation.Horizontal)]
    [InlineData(SessionLayoutEdge.Top, SessionSplitOrientation.Vertical)]
    [InlineData(SessionLayoutEdge.Bottom, SessionSplitOrientation.Vertical)]
    public void DropOn_SplitsTargetOnAllEdges(SessionLayoutEdge edge, SessionSplitOrientation expectedOrientation)
    {
        var layout = new SessionLayoutController();
        var a = new StubSessionTab("a");
        var b = new StubSessionTab("b");
        layout.EnsureSingle(a);
        var target = layout.FocusedLeaf!;

        Assert.True(layout.DropOn(target, edge, b));

        var split = Assert.IsType<SessionSplitNode>(layout.Root);
        Assert.Equal(expectedOrientation, split.Orientation);
        Assert.Equal(2, layout.LeafCount);
        Assert.Same(b, layout.FocusedTab);

        var first = Assert.IsType<SessionLeafNode>(split.First);
        var second = Assert.IsType<SessionLeafNode>(split.Second);
        if (edge is SessionLayoutEdge.Left or SessionLayoutEdge.Top)
        {
            Assert.Same(b, first.Tab);
            Assert.Same(a, second.Tab);
        }
        else
        {
            Assert.Same(a, first.Tab);
            Assert.Same(b, second.Tab);
        }
    }

    [Fact]
    public void DropOn_SameTab_IsNoOp()
    {
        var layout = new SessionLayoutController();
        var a = new StubSessionTab("a");
        layout.EnsureSingle(a);
        var version = layout.StructureVersion;

        Assert.False(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Right, a));
        Assert.Equal(1, layout.LeafCount);
        Assert.Equal(version, layout.StructureVersion);
    }

    [Fact]
    public void DropOn_RejectsWhenAtMaxLeaves()
    {
        var layout = new SessionLayoutController();
        var tabs = Enumerable.Range(0, 4).Select(i => new StubSessionTab($"t{i}")).ToArray();
        layout.EnsureSingle(tabs[0]);
        Assert.True(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Right, tabs[1]));
        var left = layout.FindLeaf(tabs[0])!;
        Assert.True(layout.DropOn(left, SessionLayoutEdge.Bottom, tabs[2]));
        var right = layout.FindLeaf(tabs[1])!;
        Assert.True(layout.DropOn(right, SessionLayoutEdge.Bottom, tabs[3]));
        Assert.Equal(4, layout.LeafCount);

        var extra = new StubSessionTab("extra");
        Assert.False(layout.CanDropOn(layout.FocusedLeaf!, extra));
        Assert.False(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Left, extra));
        Assert.Equal(4, layout.LeafCount);
    }

    [Fact]
    public void DropOn_CanMoveExistingLeafWhenAtMax()
    {
        var layout = new SessionLayoutController();
        var tabs = Enumerable.Range(0, 4).Select(i => new StubSessionTab($"t{i}")).ToArray();
        layout.EnsureSingle(tabs[0]);
        Assert.True(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Right, tabs[1]));
        Assert.True(layout.DropOn(layout.FindLeaf(tabs[0])!, SessionLayoutEdge.Bottom, tabs[2]));
        Assert.True(layout.DropOn(layout.FindLeaf(tabs[1])!, SessionLayoutEdge.Bottom, tabs[3]));

        var target = layout.FindLeaf(tabs[3])!;
        Assert.True(layout.DropOn(target, SessionLayoutEdge.Left, tabs[0]));
        Assert.Equal(4, layout.LeafCount);
        Assert.Same(tabs[0], layout.FocusedTab);
        Assert.NotNull(layout.FindLeaf(tabs[0]));
    }

    [Fact]
    public void RemoveTab_CollapsesSplitToSibling()
    {
        var layout = new SessionLayoutController();
        var a = new StubSessionTab("a");
        var b = new StubSessionTab("b");
        layout.EnsureSingle(a);
        Assert.True(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Right, b));

        layout.RemoveTab(b);

        Assert.Equal(1, layout.LeafCount);
        Assert.Same(a, Assert.IsType<SessionLeafNode>(layout.Root).Tab);
        Assert.Same(a, layout.FocusedTab);
    }

    [Fact]
    public void RemoveTab_LastLeaf_Clears()
    {
        var layout = new SessionLayoutController();
        var a = new StubSessionTab("a");
        layout.EnsureSingle(a);

        layout.RemoveTab(a);

        Assert.Null(layout.Root);
        Assert.Equal(0, layout.LeafCount);
    }

    [Fact]
    public void SelectTab_FocusesExistingLeaf()
    {
        var layout = new SessionLayoutController();
        var a = new StubSessionTab("a");
        var b = new StubSessionTab("b");
        layout.EnsureSingle(a);
        Assert.True(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Right, b));

        layout.SelectTab(a);

        Assert.Same(a, layout.FocusedTab);
        Assert.Equal(2, layout.LeafCount);
    }

    [Fact]
    public void SelectTab_ReplacesFocusedLeafWhenNotVisible()
    {
        var layout = new SessionLayoutController();
        var a = new StubSessionTab("a");
        var b = new StubSessionTab("b");
        var c = new StubSessionTab("c");
        layout.EnsureSingle(a);
        Assert.True(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Right, b));
        layout.SelectTab(a);
        var version = layout.StructureVersion;

        layout.SelectTab(c);

        Assert.Equal(2, layout.LeafCount);
        Assert.Same(c, layout.FindLeaf(c)!.Tab);
        Assert.Null(layout.FindLeaf(a));
        Assert.Same(c, layout.FocusedTab);
        Assert.NotNull(layout.FindLeaf(b));
        Assert.True(layout.StructureVersion > version);
    }

    [Fact]
    public void DropOn_MoveReusesTabIdentityAcrossLeaves()
    {
        var layout = new SessionLayoutController();
        var a = new StubSessionTab("a");
        var b = new StubSessionTab("b");
        layout.EnsureSingle(a);
        Assert.True(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Right, b));

        Assert.True(layout.DropOn(layout.FindLeaf(b)!, SessionLayoutEdge.Left, a));

        Assert.Equal(2, layout.LeafCount);
        Assert.Same(a, layout.FocusedTab);
        Assert.NotNull(layout.FindLeaf(a));
        Assert.NotNull(layout.FindLeaf(b));
    }

    [Fact]
    public void SetRatio_Clamps()
    {
        var layout = new SessionLayoutController();
        var a = new StubSessionTab("a");
        var b = new StubSessionTab("b");
        layout.EnsureSingle(a);
        Assert.True(layout.DropOn(layout.FocusedLeaf!, SessionLayoutEdge.Right, b));
        var split = Assert.IsType<SessionSplitNode>(layout.Root);

        SessionLayoutController.SetRatio(split, 0.01);
        Assert.Equal(SessionLayoutController.MinRatio, split.Ratio);

        SessionLayoutController.SetRatio(split, 0.99);
        Assert.Equal(SessionLayoutController.MaxRatio, split.Ratio);

        SessionLayoutController.SetRatio(split, 0.4);
        Assert.Equal(0.4, split.Ratio);
    }

    [Theory]
    [InlineData(10, 50, 200, 100, SessionLayoutEdge.Left)]
    [InlineData(190, 50, 200, 100, SessionLayoutEdge.Right)]
    [InlineData(100, 10, 200, 100, SessionLayoutEdge.Top)]
    [InlineData(100, 90, 200, 100, SessionLayoutEdge.Bottom)]
    [InlineData(100, 50, 200, 100, null)]
    public void HitTestEdge_ResolvesBands(double x, double y, double w, double h, SessionLayoutEdge? expected)
    {
        Assert.Equal(expected, SessionLayoutController.HitTestEdge(x, y, w, h));
    }
}
