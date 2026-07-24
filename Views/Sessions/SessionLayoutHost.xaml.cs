using System.Collections.ObjectModel;
using System.ComponentModel;
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
    /// <summary>
    /// Reserved gap between pane surfaces. Must stay large enough that WebView2 HWNDs cannot
    /// swallow the grip (airspace); thinner values made the splitter unrecoverable after drag.
    /// </summary>
    private const double GripThickness = 12;

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
    private bool _dragDropHandled;
    private SessionPaneHost? _headerDropHighlightPane;
    private readonly Canvas _canvas = new();
    private bool _isSplitterDragging;
    private bool _relayoutQueued;

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
        // FocusedLeaf alone only toggles IsFocused on leaves (pane chrome); topology is unchanged.
        if (e.PropertyName is nameof(SessionLayoutController.StructureVersion)
            or nameof(SessionLayoutController.Root)
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
            else if (_paneHosts.TryGetValue(leaf, out var existing))
            {
                existing.Leaf = leaf;
            }
        }

        UpdatePaneHeaders();
        Relayout();
    }

    private void UpdatePaneHeaders()
    {
        var show = (_controller?.LeafCount ?? 0) > 1;
        foreach (var pane in _paneHosts.Values)
        {
            pane.ShowConnectionHeader = show;
        }
    }

    private void AddPaneHost(SessionLeafNode leaf)
    {
        var pane = new SessionPaneHost
        {
            Leaf = leaf,
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Top,
            IsHitTestVisible = true,
            ShowConnectionHeader = (_controller?.LeafCount ?? 0) > 1,
        };
        pane.ActivateRequested += OnPaneActivateRequested;
        pane.CloseRequested += OnPaneCloseRequested;
        pane.RestoreFullViewRequested += OnPaneRestoreFullViewRequested;
        pane.DuplicateRequested += OnPaneDuplicateRequested;
        pane.FileTransferRequested += OnPaneFileTransferRequested;
        pane.HeaderDragStarted += OnPaneHeaderDragStarted;
        pane.HeaderDragEnded += OnPaneHeaderDragEnded;
        pane.ConnectionHeaderDragOver += OnConnectionHeaderDragOver;
        pane.ConnectionHeaderDragLeave += OnConnectionHeaderDragLeave;
        pane.ConnectionHeaderDrop += OnConnectionHeaderDrop;
        pane.LayoutDragOver += OnDragOver;
        pane.LayoutDragLeave += OnDragLeave;
        pane.LayoutDrop += OnDrop;
        _paneHosts[leaf] = pane;
        _canvas.Children.Add(pane);
    }

    private void RemovePaneHost(SessionLeafNode leaf)
    {
        if (!_paneHosts.Remove(leaf, out var pane)) return;
        pane.ActivateRequested -= OnPaneActivateRequested;
        pane.CloseRequested -= OnPaneCloseRequested;
        pane.RestoreFullViewRequested -= OnPaneRestoreFullViewRequested;
        pane.DuplicateRequested -= OnPaneDuplicateRequested;
        pane.FileTransferRequested -= OnPaneFileTransferRequested;
        pane.HeaderDragStarted -= OnPaneHeaderDragStarted;
        pane.HeaderDragEnded -= OnPaneHeaderDragEnded;
        pane.ConnectionHeaderDragOver -= OnConnectionHeaderDragOver;
        pane.ConnectionHeaderDragLeave -= OnConnectionHeaderDragLeave;
        pane.ConnectionHeaderDrop -= OnConnectionHeaderDrop;
        pane.LayoutDragOver -= OnDragOver;
        pane.LayoutDragLeave -= OnDragLeave;
        pane.LayoutDrop -= OnDrop;
        _canvas.Children.Remove(pane);
    }

    private void OnPaneActivateRequested(object? sender, EventArgs e)
    {
        if (sender is not SessionPaneHost { Leaf: { } leaf }) return;
        _controller?.Focus(leaf);
    }

    private void OnPaneCloseRequested(object? sender, EventArgs e)
    {
        if (sender is not SessionPaneHost { Leaf.Tab: { } tab }) return;
        PaneCloseRequested?.Invoke(this, tab);
    }

    private void OnPaneRestoreFullViewRequested(object? sender, EventArgs e)
    {
        if (sender is not SessionPaneHost { Leaf.Tab: { } tab }) return;
        PaneRestoreFullViewRequested?.Invoke(this, tab);
    }

    private void OnPaneDuplicateRequested(object? sender, EventArgs e)
    {
        if (sender is not SessionPaneHost { Leaf.Tab: { } tab }) return;
        PaneDuplicateRequested?.Invoke(this, tab);
    }

    private void OnPaneFileTransferRequested(object? sender, EventArgs e)
    {
        if (sender is not SessionPaneHost { Leaf.Tab: { } tab }) return;
        PaneFileTransferRequested?.Invoke(this, tab);
    }

    private void OnPaneHeaderDragStarted(object? sender, SessionTabViewModel tab)
    {
        BeginTabDrag(tab);
    }

    private void OnPaneHeaderDragEnded(object? sender, EventArgs e) => NotifyDragSourceCompleted();

    /// <summary>
    /// Marks the in-flight dragged tab for layout drop targeting (global strip or pane chip).
    /// </summary>
    public void BeginTabDrag(SessionTabViewModel tab)
    {
        _dragDropHandled = false;
        DraggedTab = tab;
        // Do NOT disable surface hit-testing here. Pane hosts are transparent over content;
        // with surfaces IsHitTestVisible=false nothing under the pointer is hit-tested, so
        // SessionLayoutHost never receives DragOver/Drop (docking dies with DropResult=None).
    }

    public void EndTabDrag()
    {
        DraggedTab = null;
        ClearHeaderDropHighlight();
        ClearPreview();
    }

    /// <summary>
    /// Source drag finished. Defer clearing <see cref="DraggedTab"/> so Drop handlers that are
    /// dispatched after StartDragAsync/TabDragCompleted returns still resolve the tab.
    /// </summary>
    public void NotifyDragSourceCompleted()
    {
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
        {
            if (!_dragDropHandled)
            {
                EndTabDrag();
            }
        });
    }

    private void MarkDropHandledAndEnd()
    {
        _dragDropHandled = true;
        EndTabDrag();
    }

    private void OnConnectionHeaderDragOver(object sender, DragEventArgs e)
    {
        if (sender is not SessionPaneHost { Leaf: { } leaf } pane)
        {
            e.AcceptedOperation = DataPackageOperation.None;
            return;
        }

        var tab = ResolveDraggedTab(e);
        if (tab is null || ReferenceEquals(leaf.Tab, tab) || _controller is null)
        {
            e.AcceptedOperation = DataPackageOperation.None;
            ClearHeaderDropHighlight();
            return;
        }

        e.AcceptedOperation = DataPackageOperation.Move;
        if (e.DragUIOverride is not null)
        {
            e.DragUIOverride.IsGlyphVisible = false;
            e.DragUIOverride.IsCaptionVisible = true;
            e.DragUIOverride.Caption = "Move to this pane";
        }

        SetHeaderDropHighlight(pane);
        ClearPreview();
        e.Handled = true;
    }

    private void OnConnectionHeaderDragLeave(object sender, DragEventArgs e)
    {
        if (sender is SessionPaneHost pane)
        {
            pane.SetConnectionHeaderDropHighlight(false);
            if (ReferenceEquals(_headerDropHighlightPane, pane))
            {
                _headerDropHighlightPane = null;
            }
        }
    }

    private void OnConnectionHeaderDrop(object sender, DragEventArgs e)
    {
        ClearHeaderDropHighlight();
        ClearPreview();
        var tab = ResolveDraggedTab(e);
        if (sender is not SessionPaneHost { Leaf: { } leaf } || _controller is null)
        {
            MarkDropHandledAndEnd();
            return;
        }

        if (tab is null || ReferenceEquals(leaf.Tab, tab))
        {
            MarkDropHandledAndEnd();
            return;
        }

        if (_controller.MoveOntoLeaf(leaf, tab))
        {
            e.AcceptedOperation = DataPackageOperation.Move;
            e.Handled = true;
        }

        MarkDropHandledAndEnd();
    }

    private void SetHeaderDropHighlight(SessionPaneHost pane)
    {
        if (ReferenceEquals(_headerDropHighlightPane, pane)) return;
        ClearHeaderDropHighlight();
        _headerDropHighlightPane = pane;
        pane.SetConnectionHeaderDropHighlight(true);
    }

    private void ClearHeaderDropHighlight()
    {
        _headerDropHighlightPane?.SetConnectionHeaderDropHighlight(false);
        _headerDropHighlightPane = null;
    }

    /// <summary>Raised when the user closes a connection from a per-pane header.</summary>
    public event EventHandler<SessionTabViewModel>? PaneCloseRequested;

    /// <summary>Raised when the user restores a tiled pane to the single full view.</summary>
    public event EventHandler<SessionTabViewModel>? PaneRestoreFullViewRequested;

    /// <summary>Raised when the user duplicates a connection from a per-pane header.</summary>
    public event EventHandler<SessionTabViewModel>? PaneDuplicateRequested;

    /// <summary>Raised when the user opens SFTP from a per-pane header.</summary>
    public event EventHandler<SessionTabViewModel>? PaneFileTransferRequested;

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
            _paneHosts.TryGetValue(leaf, out var pane);
            if (pane is not null)
            {
                SetCanvasBounds(pane, bounds);
                Canvas.SetZIndex(pane, 10);
            }

            if (_surfaces.TryGetValue(leaf.Tab, out var surface))
            {
                // Clear MinHeight/MinWidth so session templates cannot overflow leaf bounds.
                if (surface.MinHeight > 0) surface.MinHeight = 0;
                if (surface.MinWidth > 0) surface.MinWidth = 0;

                // Protocol surface sits under the per-pane connection header (mRemoteNG-style).
                var headerH = pane?.ReservedHeaderHeight ?? 0;
                var content = new Rect(
                    bounds.X,
                    bounds.Y + headerH,
                    bounds.Width,
                    Math.Max(0, bounds.Height - headerH));
                SetCanvasBounds(surface, content);
                Canvas.SetZIndex(surface, 0);
                visibleTabs.Add(leaf.Tab);
            }
        }

        // Visibility does not change mid-sash-drag; skip the pass to keep the UI thread free.
        if (!_isSplitterDragging)
        {
            ApplySurfaceVisibility(visibleTabs);
        }
    }

    private static void SetCanvasBounds(FrameworkElement element, Rect bounds)
    {
        var width = Math.Max(0, bounds.Width);
        var height = Math.Max(0, bounds.Height);
        // Canvas children default Width/Height/offsets to NaN. NaN comparisons are never true,
        // so a naive "changed by 0.5?" check skipped the first assign and left the WebView2 at a
        // tiny content size (~80x60) — below xterm's usable minimum, so ready never arrived in time.
        var left = Canvas.GetLeft(element);
        var top = Canvas.GetTop(element);
        if (double.IsNaN(left) || Math.Abs(left - bounds.X) > 0.5)
            Canvas.SetLeft(element, bounds.X);
        if (double.IsNaN(top) || Math.Abs(top - bounds.Y) > 0.5)
            Canvas.SetTop(element, bounds.Y);
        if (double.IsNaN(element.Width) || Math.Abs(element.Width - width) > 0.5)
            element.Width = width;
        if (double.IsNaN(element.Height) || Math.Abs(element.Height - height) > 0.5)
            element.Height = height;
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
            Canvas.SetZIndex(splitter, 1000);
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
            Canvas.SetZIndex(splitter, 1000);
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
        splitter.DragStarted += OnSplitterDragStarted;
        splitter.DragEnded += OnSplitterDragEnded;
        Canvas.SetZIndex(splitter, 1000);
        _splitters[split] = splitter;
        _canvas.Children.Add(splitter);
        return splitter;
    }

    private void OnSplitterRatioChanged(object? sender, EventArgs e)
    {
        // Coalesce multiple PointerMoved updates into one layout pass per dispatcher tick.
        if (_relayoutQueued) return;
        _relayoutQueued = true;
        DispatcherQueue.TryEnqueue(() =>
        {
            _relayoutQueued = false;
            Relayout();
        });
    }

    private void OnSplitterDragStarted(object? sender, EventArgs e)
    {
        _isSplitterDragging = true;
        SetSurfacesHitTestVisible(false);
    }

    private void OnSplitterDragEnded(object? sender, EventArgs e)
    {
        _isSplitterDragging = false;
        SetSurfacesHitTestVisible(true);
        Relayout();
    }

    private void SetSurfacesHitTestVisible(bool visible)
    {
        foreach (var surface in _surfaces.Values)
        {
            surface.IsHitTestVisible = visible;
        }
    }

    private void RemoveSplitter(SessionSplitNode split)
    {
        if (!_splitters.Remove(split, out var splitter)) return;
        splitter.RatioChanged -= OnSplitterRatioChanged;
        splitter.DragStarted -= OnSplitterDragStarted;
        splitter.DragEnded -= OnSplitterDragEnded;
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
        if (!TryResolveDropTarget(e, out _, out _, out var pane, out var edge, out var onHeader))
        {
            e.AcceptedOperation = DataPackageOperation.None;
            ClearPreview();
            return;
        }

        e.AcceptedOperation = DataPackageOperation.Move;
        if (e.DragUIOverride is not null)
        {
            e.DragUIOverride.IsGlyphVisible = false;
            e.DragUIOverride.IsCaptionVisible = true;
            e.DragUIOverride.Caption = onHeader ? "Move to this pane" : "Dock here";
        }

        // Header drops move into that pane — no edge highlight needed.
        if (onHeader)
        {
            ClearPreview();
        }
        else
        {
            ShowPreview(pane, edge);
        }

        e.Handled = true;
    }

    private void OnDragLeave(object sender, DragEventArgs e) => ClearPreview();

    private void OnDrop(object sender, DragEventArgs e)
    {
        ClearPreview();
        if (!TryResolveDropTarget(e, out var tab, out var leaf, out _, out var edge, out var onHeader))
        {
            MarkDropHandledAndEnd();
            return;
        }

        var ok = onHeader
            ? _controller!.MoveOntoLeaf(leaf, tab)
            : _controller!.DropOn(leaf, edge, tab);
        if (ok)
        {
            e.AcceptedOperation = DataPackageOperation.Move;
            e.Handled = true;
        }

        MarkDropHandledAndEnd();
    }

    private bool TryResolveDropTarget(
        DragEventArgs e,
        out SessionTabViewModel tab,
        out SessionLeafNode leaf,
        out SessionPaneHost pane,
        out SessionLayoutEdge edge,
        out bool onConnectionHeader)
    {
        tab = null!;
        leaf = null!;
        pane = null!;
        edge = default;
        onConnectionHeader = false;

        var dragged = ResolveDraggedTab(e);
        if (dragged is null || _controller is null)
        {
            return false;
        }

        var point = e.GetPosition(_canvas);
        if (!TryHitTestLeaf(point, out var hitLeaf, out var local, out var bounds) || hitLeaf is null)
        {
            return false;
        }

        if (!_paneHosts.TryGetValue(hitLeaf, out var hitPane))
        {
            return false;
        }

        var headerH = hitPane.ReservedHeaderHeight;
        onConnectionHeader = headerH > 0 && local.Y < headerH;

        if (onConnectionHeader)
        {
            // Dropping on the connection row moves into that pane.
            if (ReferenceEquals(hitLeaf.Tab, dragged))
            {
                return false;
            }

            tab = dragged;
            leaf = hitLeaf;
            pane = hitPane;
            edge = SessionLayoutEdge.Left; // unused for header moves
            return true;
        }

        if (!_controller.CanDropOn(hitLeaf, dragged))
        {
            return false;
        }

        var hitEdge = SessionLayoutController.HitTestEdge(local.X, local.Y, bounds.Width, bounds.Height);
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
}
