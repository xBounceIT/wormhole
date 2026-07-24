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

    /// <summary>
    /// Drop onto another pane's connection row: move <paramref name="dragged"/> into that pane.
    /// If it was already tiled elsewhere, that source pane is collapsed (displaced tab stays open
    /// but leaves the layout). A background tab replaces the target's visible tab.
    /// </summary>
    public bool MoveOntoLeaf(SessionLeafNode target, SessionTabViewModel dragged)
    {
        if (ReferenceEquals(target.Tab, dragged))
        {
            return false;
        }

        var source = FindLeaf(dragged);
        if (source is null)
        {
            // Background tab → this pane (previous occupant leaves the layout).
            target.Tab = dragged;
            Focus(target);
            BumpStructure();
            return true;
        }

        if (ReferenceEquals(source, target))
        {
            return false;
        }

        // Move out of source pane first. Detach promotes the sibling (often <paramref name="target"/>)
        // so the tree stays valid; the displaced tab is no longer in any leaf.
        if (!DetachLeaf(source))
        {
            return false;
        }

        if (!Contains(Root, target))
        {
            // Source detach removed the split that held target — target was promoted to root.
            var survivor = FirstLeaf(Root);
            if (survivor is null)
            {
                return false;
            }

            target = survivor;
        }

        target.Tab = dragged;
        Focus(target);
        BumpStructure();
        return true;
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

        // Resolve to the nearest edge so the entire pane is a valid drop target.
        // Narrow 25% bands left a large dead center that rejected drops and confused placement.
        var distLeft = x;
        var distRight = width - x;
        var distTop = y;
        var distBottom = height - y;

        var best = SessionLayoutEdge.Left;
        var bestDist = distLeft;

        if (distRight < bestDist)
        {
            best = SessionLayoutEdge.Right;
            bestDist = distRight;
        }

        if (distTop < bestDist)
        {
            best = SessionLayoutEdge.Top;
            bestDist = distTop;
        }

        if (distBottom < bestDist)
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
