using CommunityToolkit.Mvvm.ComponentModel;

namespace Wormhole.ViewModels.Sessions.Layout;

public abstract class SessionLayoutNode : ObservableObject
{
    public SessionSplitNode? Parent { get; set; }
}

public partial class SessionLeafNode : SessionLayoutNode
{
    public SessionLeafNode(SessionTabViewModel tab)
    {
        Tab = tab;
    }

    [ObservableProperty]
    private SessionTabViewModel tab;

    [ObservableProperty]
    private bool isFocused;
}

public partial class SessionSplitNode : SessionLayoutNode
{
    public SessionSplitNode(
        SessionSplitOrientation orientation,
        SessionLayoutNode first,
        SessionLayoutNode second,
        double ratio = 0.5)
    {
        Orientation = orientation;
        Ratio = ratio;
        First = first;
        Second = second;
        first.Parent = this;
        second.Parent = this;
    }

    [ObservableProperty]
    private SessionSplitOrientation orientation;

    [ObservableProperty]
    private double ratio = 0.5;

    [ObservableProperty]
    private SessionLayoutNode first = null!;

    [ObservableProperty]
    private SessionLayoutNode second = null!;
}
