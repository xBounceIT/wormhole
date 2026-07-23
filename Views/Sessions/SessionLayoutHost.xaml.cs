using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Wormhole.ViewModels.Sessions;
using Wormhole.ViewModels.Sessions.Layout;
using Wormhole.Views.Controls;

namespace Wormhole.Views.Sessions;

/// <summary>
/// Renders the session layout tree. Keeps one realized protocol surface per open tab (same parent
/// for life) and tiles visible leaves on a Canvas so splits/moves do not Unload WebView2 / RDP.
/// </summary>
public sealed partial class SessionLayoutHost : UserControl
{
    public const string DragTabFormat = "Wormhole.SessionTab";
    private const double GripThickness = 6;

    public static readonly DependencyProperty ControllerProperty =
        DependencyProperty.Register(
            nameof(Controller),
            typeof(SessionLayoutController),
            typeof(SessionLayoutHost),
            new PropertyMetadata(null, OnControllerChanged));

    public static readonly DependencyProperty ContentTemplateSelectorProperty =
        DependencyProperty.Register(
            nameof(ContentTemplateSelector),
            typeof(DataTemplateSelector),
            typeof(SessionLayoutHost),
            new PropertyMetadata(null));

    private SessionLayoutController? _controller;
    private readonly Dictionary<SessionTabViewModel, FrameworkElement> _surfaces = new();
    private readonly Dictionary<SessionLeafNode, SessionPaneHost> _paneHosts = new();
    private readonly Dictionary<SessionSplitNode, PaneSplitter> _splitters = new();
    private readonly Dictionary<SessionLeafNode, Rect> _leafBounds = new();
    private SessionPaneHost? _previewPane;
    private SessionLayoutEdge? _previewEdge;
    private SessionTabViewModel? _draggedTab;
    private readonly Canvas _canvas = new();

    public SessionLayoutHost()
    {
        InitializeComponent();
        LayoutRoot.Children.Add(_canvas);
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        SizeChanged += (_, _) => Relayout();
    }

    public SessionLayoutController? Controller
    {
        get => (SessionLayoutController?)GetValue(ControllerProperty);
        set => SetValue(ControllerProperty, value);
    }

    public DataTemplateSelector? ContentTemplateSelector
    {
        get => (DataTemplateSelector?)GetValue(ContentTemplateSelectorProperty);
        set => SetValue(ContentTemplateSelectorProperty, value);
    }

    public SessionTabViewModel? DraggedTab
    {
        get => _draggedTab;
        set => _draggedTab = value;
    }

    public event EventHandler<SessionLeafNode>? PaneActivateRequested;

    /// <summary>
    /// Ensure one realized surface per open tab; show/position those in layout leaves and
    /// collapse the rest without Unloading (preserves SSH TerminalBridge / RDP overlays).
    /// </summary>
    public void SyncSurfaces(
        ObservableCollection<SessionTabViewModel> tabs,
        SessionContentSelector selector)
    {
        foreach (var tab in tabs)
        {
            if (_surfaces.ContainsKey(tab)) continue;
            var surface = CreateSessionSurface(tab, selector);
            _surfaces[tab] = surface;
            _canvas.Children.Insert(0, surface);
        }

        foreach (var orphan in _surfaces.Keys.Where(tab => !tabs.Contains(tab)).ToList())
        {
            if (_surfaces.Remove(orphan, out var surface))
            {
                _canvas.Children.Remove(surface);
            }
        }

        SyncHostsAndRelayout();
    }

    private static FrameworkElement CreateSessionSurface(
        SessionTabViewModel tab,
        SessionContentSelector selector)
    {
        var template = selector.ResolveTemplate(tab)
            ?? throw new InvalidOperationException($"No session template for {tab.GetType().Name}.");
        if (template.LoadContent() is not FrameworkElement surface)
        {
            throw new InvalidOperationException(
                $"Session template for {tab.GetType().Name} did not produce a FrameworkElement.");
        }

        surface.DataContext = tab;
        surface.HorizontalAlignment = HorizontalAlignment.Left;
        surface.VerticalAlignment = VerticalAlignment.Top;
        return surface;
    }

    private static void OnControllerChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SessionLayoutHost host)
        {
            host.AttachController(e.OldValue as SessionLayoutController, e.NewValue as SessionLayoutController);
        }
    }

    private void AttachController(SessionLayoutController? oldController, SessionLayoutController? newController)
    {
        if (oldController is not null)
        {
            oldController.PropertyChanged -= OnControllerPropertyChanged;
        }

        _controller = newController;
        if (newController is not null && IsLoaded)
        {
            newController.PropertyChanged += OnControllerPropertyChanged;
        }

        SyncHostsAndRelayout();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_controller is null) return;
        _controller.PropertyChanged -= OnControllerPropertyChanged;
        _controller.PropertyChanged += OnControllerPropertyChanged;
        SyncHostsAndRelayout();
    }

    private void OnControllerPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(SessionLayoutController.StructureVersion)
            or nameof(SessionLayoutController.Root)
            or nameof(SessionLayoutController.FocusedLeaf)
            or nameof(SessionLayoutController.LeafCount))
        {
            SyncHostsAndRelayout();
        }
    }

    private void SyncHostsAndRelayout()
    {
        ClearPreview();
        if (_controller is null)
        {
            foreach (var leaf in _paneHosts.Keys.ToList())
            {
                RemovePaneHost(leaf);
            }

            ClearSplitters();
            foreach (var surface in _surfaces.Values)
            {
                surface.Visibility = Visibility.Collapsed;
                if (surface is ISessionSurfaceActivation activation)
                {
                    activation.SetSessionSurfaceActive(false);
                }
            }

            return;
        }

        var liveLeaves = _controller.Leaves.ToHashSet();
        foreach (var orphan in _paneHosts.Keys.Where(leaf => !liveLeaves.Contains(leaf)).ToList())
        {
            RemovePaneHost(orphan);
        }

        foreach (var leaf in liveLeaves)
        {
            if (!_paneHosts.ContainsKey(leaf))
            {
                AddPaneHost(leaf);
            }
            else
            {
                _paneHosts[leaf].RefreshFocusChrome(_controller.LeafCount);
            }
        }

        Relayout();
    }

    private void AddPaneHost(SessionLeafNode leaf)
    {
        var pane = new SessionPaneHost
        {
            Leaf = leaf,
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Top,
            IsHitTestVisible = false,
        };
        pane.PaneActivateRequested += OnPaneActivateRequested;
        pane.RefreshFocusChrome(_controller?.LeafCount ?? 1);
        _paneHosts[leaf] = pane;
        _canvas.Children.Add(pane);
    }

    private void RemovePaneHost(SessionLeafNode leaf)
    {
        if (!_paneHosts.Remove(leaf, out var pane)) return;
        pane.PaneActivateRequested -= OnPaneActivateRequested;
        _canvas.Children.Remove(pane);
    }

    private void OnPaneActivateRequested(object? sender, SessionLeafNode leaf) =>
        PaneActivateRequested?.Invoke(this, leaf);

    private void Relayout()
    {
        _leafBounds.Clear();
        if (_controller?.Root is null || ActualWidth <= 0 || ActualHeight <= 0)
        {
            ClearSplitters();
            ApplySurfaceVisibility(visibleTabs: null);
            return;
        }

        _canvas.Width = ActualWidth;
        _canvas.Height = ActualHeight;

        var liveSplits = new HashSet<SessionSplitNode>();
        LayoutNode(_controller.Root, new Rect(0, 0, ActualWidth, ActualHeight), liveSplits);

        foreach (var orphan in _splitters.Keys.Where(split => !liveSplits.Contains(split)).ToList())
        {
            RemoveSplitter(orphan);
        }

        var visibleTabs = new HashSet<SessionTabViewModel>();
        foreach (var (leaf, bounds) in _leafBounds)
        {
            if (_paneHosts.TryGetValue(leaf, out var pane))
            {
                Canvas.SetLeft(pane, bounds.X);
                Canvas.SetTop(pane, bounds.Y);
                pane.Width = Math.Max(0, bounds.Width);
                pane.Height = Math.Max(0, bounds.Height);
                pane.RefreshFocusChrome(_controller.LeafCount);
            }

            if (_surfaces.TryGetValue(leaf.Tab, out var surface))
            {
                Canvas.SetLeft(surface, bounds.X);
                Canvas.SetTop(surface, bounds.Y);
                surface.Width = Math.Max(0, bounds.Width);
                surface.Height = Math.Max(0, bounds.Height);
                visibleTabs.Add(leaf.Tab);
            }
        }

        ApplySurfaceVisibility(visibleTabs);
    }

    private void ApplySurfaceVisibility(HashSet<SessionTabViewModel>? visibleTabs)
    {
        foreach (var (tab, surface) in _surfaces)
        {
            var isVisible = visibleTabs is not null && visibleTabs.Contains(tab);
            surface.Visibility = isVisible ? Visibility.Visible : Visibility.Collapsed;
            if (surface is ISessionSurfaceActivation activation)
            {
                activation.SetSessionSurfaceActive(isVisible);
            }
        }
    }

    private void LayoutNode(SessionLayoutNode node, Rect bounds, HashSet<SessionSplitNode> liveSplits)
    {
        if (node is SessionLeafNode leaf)
        {
            _leafBounds[leaf] = bounds;
            return;
        }

        if (node is not SessionSplitNode split) return;

        liveSplits.Add(split);
        var splitter = GetOrCreateSplitter(split);
        splitter.TrackBounds = bounds;

        if (split.Orientation == SessionSplitOrientation.Horizontal)
        {
            var grip = Math.Min(GripThickness, bounds.Width);
            var avail = Math.Max(0, bounds.Width - grip);
            var firstW = avail * split.Ratio;
            var secondW = avail - firstW;

            LayoutNode(split.First, new Rect(bounds.X, bounds.Y, firstW, bounds.Height), liveSplits);
            LayoutNode(split.Second, new Rect(bounds.X + firstW + grip, bounds.Y, secondW, bounds.Height), liveSplits);

            Canvas.SetLeft(splitter, bounds.X + firstW);
            Canvas.SetTop(splitter, bounds.Y);
            splitter.Width = grip;
            splitter.Height = bounds.Height;
        }
        else
        {
            var grip = Math.Min(GripThickness, bounds.Height);
            var avail = Math.Max(0, bounds.Height - grip);
            var firstH = avail * split.Ratio;
            var secondH = avail - firstH;

            LayoutNode(split.First, new Rect(bounds.X, bounds.Y, bounds.Width, firstH), liveSplits);
            LayoutNode(split.Second, new Rect(bounds.X, bounds.Y + firstH + grip, bounds.Width, secondH), liveSplits);

            Canvas.SetLeft(splitter, bounds.X);
            Canvas.SetTop(splitter, bounds.Y + firstH);
            splitter.Width = bounds.Width;
            splitter.Height = grip;
        }
    }

    private PaneSplitter GetOrCreateSplitter(SessionSplitNode split)
    {
        if (_splitters.TryGetValue(split, out var existing))
        {
            existing.Split = split;
            existing.Track = this;
            return existing;
        }

        var splitter = new PaneSplitter
        {
            Split = split,
            Track = this,
        };
        splitter.RatioChanged += OnSplitterRatioChanged;
        _splitters[split] = splitter;
        _canvas.Children.Add(splitter);
        return splitter;
    }

    private void OnSplitterRatioChanged(object? sender, EventArgs e) => Relayout();

    private void RemoveSplitter(SessionSplitNode split)
    {
        if (!_splitters.Remove(split, out var splitter)) return;
        splitter.RatioChanged -= OnSplitterRatioChanged;
        _canvas.Children.Remove(splitter);
    }

    private void ClearSplitters()
    {
        foreach (var split in _splitters.Keys.ToList())
        {
            RemoveSplitter(split);
        }
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (!TryResolveDropTarget(e, out _, out _, out var pane, out var edge))
        {
            e.AcceptedOperation = DataPackageOperation.None;
            ClearPreview();
            return;
        }

        e.AcceptedOperation = DataPackageOperation.Move;
        if (e.DragUIOverride is not null)
        {
            e.DragUIOverride.IsGlyphVisible = false;
            e.DragUIOverride.IsCaptionVisible = false;
        }

        ShowPreview(pane, edge);
    }

    private void OnDragLeave(object sender, DragEventArgs e) => ClearPreview();

    private void OnDrop(object sender, DragEventArgs e)
    {
        ClearPreview();
        if (!TryResolveDropTarget(e, out var tab, out var leaf, out _, out var edge))
        {
            return;
        }

        if (_controller!.DropOn(leaf, edge, tab))
        {
            e.AcceptedOperation = DataPackageOperation.Move;
        }
    }

    private bool TryResolveDropTarget(
        DragEventArgs e,
        out SessionTabViewModel tab,
        out SessionLeafNode leaf,
        out SessionPaneHost pane,
        out SessionLayoutEdge edge)
    {
        tab = null!;
        leaf = null!;
        pane = null!;
        edge = default;

        var dragged = ResolveDraggedTab(e);
        if (dragged is null || _controller is null)
        {
            // #region agent log
            AgentDebugLog("A", "SessionLayoutHost.TryResolveDropTarget", "no-dragged-or-controller", new { hasDragged = dragged is not null });
            // #endregion
            return false;
        }

        var point = e.GetPosition(_canvas);
        if (!TryHitTestLeaf(point, out var hitLeaf, out var local, out var bounds) || hitLeaf is null)
        {
            // #region agent log
            AgentDebugLog("F", "SessionLayoutHost.TryResolveDropTarget", "miss-leaf", new { point.X, point.Y, leafCount = _leafBounds.Count });
            // #endregion
            return false;
        }

        if (!_controller.CanDropOn(hitLeaf, dragged))
        {
            // #region agent log
            AgentDebugLog("E", "SessionLayoutHost.TryResolveDropTarget", "can-drop-false", new { });
            // #endregion
            return false;
        }

        if (!_paneHosts.TryGetValue(hitLeaf, out var hitPane))
        {
            return false;
        }

        var hitEdge = SessionLayoutController.HitTestEdge(local.X, local.Y, bounds.Width, bounds.Height);
        // #region agent log
        AgentDebugLog("E", "SessionLayoutHost.TryResolveDropTarget", "edge-hit", new
        {
            local.X,
            local.Y,
            bounds.Width,
            bounds.Height,
            edge = hitEdge?.ToString(),
            band = 0.25,
            paneW = hitPane.Width,
            paneH = hitPane.Height,
            actualW = hitPane.ActualWidth,
            actualH = hitPane.ActualHeight,
        });
        // #endregion
        if (hitEdge is null)
        {
            return false;
        }

        tab = dragged;
        leaf = hitLeaf;
        pane = hitPane;
        edge = hitEdge.Value;
        return true;
    }

    private SessionTabViewModel? ResolveDraggedTab(DragEventArgs e)
    {
        if (_draggedTab is not null)
        {
            return _draggedTab;
        }

        if (e.DataView.Properties.TryGetValue(DragTabFormat, out var boxed)
            && boxed is SessionTabViewModel tab)
        {
            return tab;
        }

        return null;
    }

    private bool TryHitTestLeaf(
        Point pointInCanvas,
        out SessionLeafNode? leaf,
        out Point localInPane,
        out Rect bounds)
    {
        leaf = null;
        localInPane = default;
        bounds = default;

        foreach (var (candidate, rect) in _leafBounds)
        {
            if (!rect.Contains(pointInCanvas))
            {
                continue;
            }

            leaf = candidate;
            localInPane = new Point(pointInCanvas.X - rect.X, pointInCanvas.Y - rect.Y);
            bounds = rect;
            return true;
        }

        return false;
    }

    private void ShowPreview(SessionPaneHost pane, SessionLayoutEdge edge)
    {
        if (!ReferenceEquals(_previewPane, pane) || _previewEdge != edge)
        {
            if (_previewPane is not null && !ReferenceEquals(_previewPane, pane))
            {
                _previewPane.Overlay.Clear();
            }

            _previewPane = pane;
            _previewEdge = edge;
            pane.Overlay.ShowEdge(edge);
        }
    }

    private void ClearPreview()
    {
        if (_previewPane is not null)
        {
            _previewPane.Overlay.Clear();
            _previewPane = null;
        }

        _previewEdge = null;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_controller is not null)
        {
            _controller.PropertyChanged -= OnControllerPropertyChanged;
        }

        ClearPreview();
        foreach (var leaf in _paneHosts.Keys.ToList())
        {
            RemovePaneHost(leaf);
        }

        ClearSplitters();
    }

    // #region agent log
    private static void AgentDebugLog(string hypothesisId, string location, string message, object data)
    {
        try
        {
            var payload = new Dictionary<string, object?>
            {
                ["sessionId"] = "e57f3c",
                ["hypothesisId"] = hypothesisId,
                ["location"] = location,
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };
            File.AppendAllText(
                @"C:\Users\dange\.cursor\worktrees\wormhole\qoqy\debug-e57f3c.log",
                JsonSerializer.Serialize(payload) + "\n");
        }
        catch
        {
            // ignore debug log failures
        }
    }
    // #endregion
}
