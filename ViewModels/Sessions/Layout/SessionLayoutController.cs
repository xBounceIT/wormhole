using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Wormhole.ViewModels.Sessions.Layout;

/// <summary>
/// In-memory binary-tree layout of visible session panes. Open tabs remain on
/// <c>ShellViewModel.Tabs</c>; this controller only tracks which subset is tiled
/// and how they are split.
/// </summary>
public partial class SessionLayoutController : ObservableObject
{
    public const int MaxLeaves = 4;
    public const double MinRatio = 0.15;
    public const double MaxRatio = 0.85;

    private int _structureVersion;

    [ObservableProperty]
    private SessionLayoutNode? root;

    [ObservableProperty]
    private SessionLeafNode? focusedLeaf;

    /// <summary>
    /// Bumped whenever the tree topology changes (split / collapse / root replace).
    /// UI hosts subscribe to rebuild the visual tree.
    /// </summary>
    public int StructureVersion => _structureVersion;

    public int LeafCount => EnumerateLeaves(Root).Count();

    public IEnumerable<SessionLeafNode> Leaves => EnumerateLeaves(Root);

    public SessionTabViewModel? FocusedTab => FocusedLeaf?.Tab;

    public void Clear()
    {
        if (FocusedLeaf is not null)
        {
            FocusedLeaf.IsFocused = false;
        }

        FocusedLeaf = null;
        Root = null;
        BumpStructure();
    }

    public void EnsureSingle(SessionTabViewModel? tab)
    {
        if (tab is null)
        {
            Clear();
            return;
        }

        var leaf = new SessionLeafNode(tab);
        Root = leaf;
        Focus(leaf);
        BumpStructure();
    }

    public void Focus(SessionLeafNode? leaf)
    {
        if (leaf is not null && !Contains(Root, leaf))
        {
            return;
        }

        if (ReferenceEquals(FocusedLeaf, leaf))
        {
            if (leaf is not null)
            {
                leaf.IsFocused = true;
            }

            return;
        }

        if (FocusedLeaf is not null)
        {
            FocusedLeaf.IsFocused = false;
        }

        FocusedLeaf = leaf;
        if (leaf is not null)
        {
            leaf.IsFocused = true;
        }
    }

    /// <summary>
    /// If <paramref name="tab"/> is already visible in a leaf, focus that leaf.
    /// Otherwise assign it to the focused leaf (or create a single-leaf layout).
    /// </summary>
    public void SelectTab(SessionTabViewModel? tab)
    {
        if (tab is null)
        {
            Clear();
            return;
        }

        var existing = FindLeaf(tab);
        if (existing is not null)
        {
            Focus(existing);
            return;
        }

        if (FocusedLeaf is not null)
        {
            FocusedLeaf.Tab = tab;
            // Surface hosts are keyed by tab; bump so the layout host remaps without
            // waiting for a topology change.
            BumpStructure();
            return;
        }

        EnsureSingle(tab);
    }

    public bool CanDropOn(SessionLeafNode target, SessionTabViewModel dragged)
    {
        if (ReferenceEquals(target.Tab, dragged))
        {
            return false;
        }

        var existing = FindLeaf(dragged);
        if (existing is not null)
        {
            return !ReferenceEquals(existing, target);
        }

        return LeafCount < MaxLeaves;
    }

    public bool DropOn(SessionLeafNode target, SessionLayoutEdge edge, SessionTabViewModel dragged)
    {
        if (!CanDropOn(target, dragged))
        {
            return false;
        }

        var existing = FindLeaf(dragged);
        if (existing is not null)
        {
            // Moving an already-visible tab: detach first so leaf count stays stable.
            if (!DetachLeaf(existing))
            {
                return false;
            }

            // Target may have been promoted (e.g. was sibling of existing) but the
            // leaf object remains valid as long as it was not the detached node.
            if (!Contains(Root, target))
            {
                // Degenerate: layout emptied somehow — start fresh with a split of one.
                EnsureSingle(target.Tab);
                target = FocusedLeaf!;
            }
        }

        var incoming = new SessionLeafNode(dragged);
        SplitLeaf(target, edge, incoming);
        Focus(incoming);
        BumpStructure();
        return true;
    }

    public void RemoveTab(SessionTabViewModel tab)
    {
        var leaf = FindLeaf(tab);
        if (leaf is null)
        {
            return;
        }

        if (leaf.Parent is null)
        {
            Clear();
            return;
        }

        var wasFocused = ReferenceEquals(FocusedLeaf, leaf);
        DetachLeaf(leaf);
        BumpStructure();

        if (wasFocused || FocusedLeaf is null || !Contains(Root, FocusedLeaf))
        {
            Focus(FirstLeaf(Root));
        }
    }

    public static void SetRatio(SessionSplitNode split, double ratio)
    {
        split.Ratio = ClampRatio(ratio);
    }

    public SessionLeafNode? FindLeaf(SessionTabViewModel tab)
    {
        foreach (var leaf in EnumerateLeaves(Root))
        {
            if (ReferenceEquals(leaf.Tab, tab))
            {
                return leaf;
            }
        }

        return null;
    }

    public static double ClampRatio(double ratio)
    {
        if (ratio < MinRatio) return MinRatio;
        if (ratio > MaxRatio) return MaxRatio;
        return ratio;
    }

    public static SessionLayoutEdge? HitTestEdge(double x, double y, double width, double height)
    {
        if (width <= 0 || height <= 0)
        {
            return null;
        }

        var leftBand = width * 0.25;
        var rightBand = width * 0.75;
        var topBand = height * 0.25;
        var bottomBand = height * 0.75;

        // Prefer edges when the pointer is clearly in a band; corner ambiguity
        // resolves to the nearer axis by relative distance into the band.
        var distLeft = x;
        var distRight = width - x;
        var distTop = y;
        var distBottom = height - y;

        var inLeft = x < leftBand;
        var inRight = x > rightBand;
        var inTop = y < topBand;
        var inBottom = y > bottomBand;

        if (!inLeft && !inRight && !inTop && !inBottom)
        {
            return null;
        }

        SessionLayoutEdge? best = null;
        var bestDist = double.MaxValue;

        if (inLeft && distLeft < bestDist)
        {
            best = SessionLayoutEdge.Left;
            bestDist = distLeft;
        }

        if (inRight && distRight < bestDist)
        {
            best = SessionLayoutEdge.Right;
            bestDist = distRight;
        }

        if (inTop && distTop < bestDist)
        {
            best = SessionLayoutEdge.Top;
            bestDist = distTop;
        }

        if (inBottom && distBottom < bestDist)
        {
            best = SessionLayoutEdge.Bottom;
        }

        return best;
    }

    private void SplitLeaf(SessionLeafNode target, SessionLayoutEdge edge, SessionLeafNode incoming)
    {
        var orientation = edge is SessionLayoutEdge.Left or SessionLayoutEdge.Right
            ? SessionSplitOrientation.Horizontal
            : SessionSplitOrientation.Vertical;

        SessionLayoutNode first;
        SessionLayoutNode second;
        switch (edge)
        {
            case SessionLayoutEdge.Left:
            case SessionLayoutEdge.Top:
                first = incoming;
                second = target;
                break;
            default:
                first = target;
                second = incoming;
                break;
        }

        // Capture the pre-split parent, then detach the target. SessionSplitNode's ctor
        // assigns Parent on its children; if we left target.Parent pointing at the old
        // parent (or let the ctor set it to the new split first), ReplaceNode would see
        // the wrong parent and corrupt the tree.
        var oldParent = target.Parent;
        target.Parent = null;

        var split = new SessionSplitNode(orientation, first, second);
        if (oldParent is null)
        {
            Root = split;
            split.Parent = null;
            return;
        }

        if (ReferenceEquals(oldParent.First, target))
        {
            oldParent.First = split;
        }
        else
        {
            oldParent.Second = split;
        }

        split.Parent = oldParent;
    }

    /// <summary>
    /// Removes <paramref name="leaf"/> and promotes its sibling. Returns false if the
    /// leaf was the sole root (layout cleared).
    /// </summary>
    private bool DetachLeaf(SessionLeafNode leaf)
    {
        if (leaf.Parent is null)
        {
            if (ReferenceEquals(Root, leaf))
            {
                if (ReferenceEquals(FocusedLeaf, leaf))
                {
                    leaf.IsFocused = false;
                    FocusedLeaf = null;
                }

                Root = null;
            }

            return false;
        }

        var parent = leaf.Parent;
        var sibling = ReferenceEquals(parent.First, leaf) ? parent.Second : parent.First;
        sibling.Parent = parent.Parent;
        ReplaceNode(parent, sibling);

        if (ReferenceEquals(FocusedLeaf, leaf))
        {
            leaf.IsFocused = false;
            FocusedLeaf = null;
        }

        return true;
    }

    private void ReplaceNode(SessionLayoutNode oldNode, SessionLayoutNode replacement)
    {
        var parent = oldNode.Parent;
        if (parent is null)
        {
            Root = replacement;
            replacement.Parent = null;
            return;
        }

        if (ReferenceEquals(parent.First, oldNode))
        {
            parent.First = replacement;
        }
        else
        {
            parent.Second = replacement;
        }

        replacement.Parent = parent;
    }

    private void BumpStructure()
    {
        _structureVersion++;
        OnPropertyChanged(nameof(StructureVersion));
        OnPropertyChanged(nameof(LeafCount));
    }

    partial void OnRootChanged(SessionLayoutNode? value) => OnPropertyChanged(nameof(LeafCount));

    partial void OnFocusedLeafChanged(SessionLeafNode? value) => OnPropertyChanged(nameof(FocusedTab));

    private static SessionLeafNode? FirstLeaf(SessionLayoutNode? node) =>
        EnumerateLeaves(node).FirstOrDefault();

    private static bool Contains(SessionLayoutNode? root, SessionLayoutNode needle)
    {
        if (root is null) return false;
        if (ReferenceEquals(root, needle)) return true;
        if (root is SessionSplitNode split)
        {
            return Contains(split.First, needle) || Contains(split.Second, needle);
        }

        return false;
    }

    private static IEnumerable<SessionLeafNode> EnumerateLeaves(SessionLayoutNode? node)
    {
        if (node is null)
        {
            yield break;
        }

        if (node is SessionLeafNode leaf)
        {
            yield return leaf;
            yield break;
        }

        if (node is SessionSplitNode split)
        {
            foreach (var child in EnumerateLeaves(split.First))
            {
                yield return child;
            }

            foreach (var child in EnumerateLeaves(split.Second))
            {
                yield return child;
            }
        }
    }
}
