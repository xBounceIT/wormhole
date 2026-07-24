using System.ComponentModel;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.UI;
using Wormhole.Helpers;
using Wormhole.ViewModels.Sessions;
using Wormhole.ViewModels.Sessions.Layout;

namespace Wormhole.Views.Sessions;

public sealed partial class SessionPaneHost : UserControl
{
    public const double ConnectionHeaderHeight = 34;
    private const double DragThresholdSquared = 36; // 6px

    public static readonly DependencyProperty LeafProperty =
        DependencyProperty.Register(
            nameof(Leaf),
            typeof(SessionLeafNode),
            typeof(SessionPaneHost),
            new PropertyMetadata(null, OnLeafChanged));

    public static readonly DependencyProperty ShowConnectionHeaderProperty =
        DependencyProperty.Register(
            nameof(ShowConnectionHeader),
            typeof(bool),
            typeof(SessionPaneHost),
            new PropertyMetadata(false, OnShowConnectionHeaderChanged));

    private SessionLeafNode? _subscribedLeaf;
    private SessionTabViewModel? _subscribedTab;
    private IDisposable? _flyoutOverlaySuppression;
    private bool _chipPressed;
    private PointerPoint? _chipPressPoint;
    private bool _dragStarted;
    private bool _headerDropHighlight;
    private static readonly SolidColorBrush HeaderDropHighlightBrush =
        new(Color.FromArgb(0x66, 0x00, 0x78, 0xD4));

    public SessionPaneHost()
    {
        InitializeComponent();
    }

    public SessionLeafNode? Leaf
    {
        get => (SessionLeafNode?)GetValue(LeafProperty);
        set => SetValue(LeafProperty, value);
    }

    public bool ShowConnectionHeader
    {
        get => (bool)GetValue(ShowConnectionHeaderProperty);
        set => SetValue(ShowConnectionHeaderProperty, value);
    }

    public SessionDropOverlay Overlay => DropOverlay;

    public double ReservedHeaderHeight => ShowConnectionHeader ? ConnectionHeaderHeight : 0;

    public event EventHandler? ActivateRequested;
    public event EventHandler? CloseRequested;
    public event EventHandler? RestoreFullViewRequested;
    public event EventHandler? DuplicateRequested;
    public event EventHandler? FileTransferRequested;
    public event EventHandler<SessionTabViewModel>? HeaderDragStarted;
    public event EventHandler? HeaderDragEnded;

    /// <summary>Drag-over on the connection row (tab strip), not the session content.</summary>
    public event DragEventHandler? ConnectionHeaderDragOver;
    public event DragEventHandler? ConnectionHeaderDragLeave;
    public event DragEventHandler? ConnectionHeaderDrop;

    public event DragEventHandler? LayoutDragOver;
    public event DragEventHandler? LayoutDragLeave;
    public event DragEventHandler? LayoutDrop;

    private static void OnLeafChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SessionPaneHost host)
        {
            host.AttachLeaf(e.NewValue as SessionLeafNode);
        }
    }

    private static void OnShowConnectionHeaderChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not SessionPaneHost host) return;
        var show = (bool)e.NewValue;
        host.HeaderRow.Height = show ? new GridLength(ConnectionHeaderHeight) : new GridLength(0);
        host.ConnectionHeader.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
    }

    private void AttachLeaf(SessionLeafNode? newLeaf)
    {
        if (_subscribedLeaf is not null)
        {
            _subscribedLeaf.PropertyChanged -= OnLeafPropertyChanged;
        }

        DetachTab();
        _subscribedLeaf = newLeaf;
        if (_subscribedLeaf is not null)
        {
            _subscribedLeaf.PropertyChanged += OnLeafPropertyChanged;
            AttachTab(_subscribedLeaf.Tab);
        }

        RefreshTitle();
        RefreshActionChrome();
    }

    private void OnLeafPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(SessionLeafNode.Tab))
        {
            AttachTab(Leaf?.Tab);
            RefreshTitle();
            RefreshActionChrome();
        }
    }

    private void AttachTab(SessionTabViewModel? tab)
    {
        DetachTab();
        _subscribedTab = tab;
        ConnectionHeader.DataContext = tab;
        TitleChip.DataContext = tab;
        if (_subscribedTab is not null)
        {
            _subscribedTab.PropertyChanged += OnTabPropertyChanged;
            DisconnectItem.Command = _subscribedTab.TabDisconnectCommand;
            ExternalClientItem.Command = _subscribedTab.TabUseExternalClientCommand;
            ReconnectItem.Command = _subscribedTab.ReconnectCommand;
        }
        else
        {
            DisconnectItem.ClearValue(MenuFlyoutItem.CommandProperty);
            ExternalClientItem.ClearValue(MenuFlyoutItem.CommandProperty);
            ReconnectItem.ClearValue(MenuFlyoutItem.CommandProperty);
        }

        RefreshActionChrome();
    }

    private void DetachTab()
    {
        if (_subscribedTab is null) return;
        _subscribedTab.PropertyChanged -= OnTabPropertyChanged;
        _subscribedTab = null;
    }

    private void OnTabPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(SessionTabViewModel.Title) or null or "")
        {
            RefreshTitle();
        }

        if (e.PropertyName is nameof(SessionTabViewModel.CanOpenFileTransfer)
            or nameof(SessionTabViewModel.CanReconnect)
            or nameof(SessionTabViewModel.CanTabDisconnect)
            or nameof(SessionTabViewModel.CanTabUseExternalClient)
            or nameof(SessionTabViewModel.Status)
            or null
            or "")
        {
            RefreshActionChrome();
        }
    }

    private void RefreshTitle() => TitleText.Text = Leaf?.Tab?.Title ?? string.Empty;

    private void RefreshActionChrome()
    {
        var tab = Leaf?.Tab;
        var showFileTransfer = tab?.CanOpenFileTransfer == true;
        FileTransferButton.Visibility = showFileTransfer ? Visibility.Visible : Visibility.Collapsed;
        FileTransferItem.Visibility = showFileTransfer ? Visibility.Visible : Visibility.Collapsed;
        ReconnectItem.Visibility = tab?.CanReconnect == true ? Visibility.Visible : Visibility.Collapsed;
        DisconnectItem.Visibility = tab?.CanTabDisconnect == true ? Visibility.Visible : Visibility.Collapsed;
        ExternalClientItem.Visibility = tab?.CanTabUseExternalClient == true ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnHeaderTapped(object sender, TappedRoutedEventArgs e)
    {
        if (_dragStarted) return;
        if (e.OriginalSource is DependencyObject source
            && (IsDescendantOf(source, CloseButton) || IsDescendantOf(source, FileTransferButton)))
        {
            return;
        }

        ActivateRequested?.Invoke(this, EventArgs.Empty);
    }

    private void OnHeaderDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        RestoreFullViewRequested?.Invoke(this, EventArgs.Empty);
        e.Handled = true;
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) =>
        CloseRequested?.Invoke(this, EventArgs.Empty);

    private void OnRestoreClick(object sender, RoutedEventArgs e) =>
        RestoreFullViewRequested?.Invoke(this, EventArgs.Empty);

    private void OnDuplicateClick(object sender, RoutedEventArgs e) =>
        DuplicateRequested?.Invoke(this, EventArgs.Empty);

    private void OnFileTransferClick(object sender, RoutedEventArgs e) =>
        FileTransferRequested?.Invoke(this, EventArgs.Empty);

    private void OnReconnectClick(object sender, RoutedEventArgs e) =>
        ActivateRequested?.Invoke(this, EventArgs.Empty);

    private void OnHeaderContextFlyoutOpened(object sender, object e)
    {
        _flyoutOverlaySuppression?.Dispose();
        _flyoutOverlaySuppression = RdpOverlayCoordinator.Suppress();
        ActivateRequested?.Invoke(this, EventArgs.Empty);
    }

    private void OnHeaderContextFlyoutClosed(object sender, object e)
    {
        _flyoutOverlaySuppression?.Dispose();
        _flyoutOverlaySuppression = null;
    }

    private void OnChipPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source
            && (IsDescendantOf(source, CloseButton) || IsDescendantOf(source, FileTransferButton)))
        {
            return;
        }

        if (!e.GetCurrentPoint(TitleChip).Properties.IsLeftButtonPressed) return;
        _chipPressed = true;
        _dragStarted = false;
        _chipPressPoint = e.GetCurrentPoint(TitleChip);
        TitleChip.CapturePointer(e.Pointer);
    }

    private async void OnChipPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_chipPressed || _chipPressPoint is null || Leaf?.Tab is null || _dragStarted)
        {
            return;
        }

        var current = e.GetCurrentPoint(TitleChip);
        var dx = current.Position.X - _chipPressPoint.Position.X;
        var dy = current.Position.Y - _chipPressPoint.Position.Y;
        if ((dx * dx) + (dy * dy) < DragThresholdSquared)
        {
            return;
        }

        var start = _chipPressPoint;
        _chipPressed = false;
        _chipPressPoint = null;
        _dragStarted = true;

        ActivateRequested?.Invoke(this, EventArgs.Empty);

        try
        {
            // Do not ReleasePointerCapture before StartDragAsync — that aborts the gesture
            // on WinUI and the drag never begins (drop onto another connection row then fails).
            // DragStarting sets the DataPackage and raises HeaderDragStarted → BeginTabDrag.
            await TitleChip.StartDragAsync(start);
        }
        finally
        {
            _dragStarted = false;
            HeaderDragEnded?.Invoke(this, EventArgs.Empty);
        }
    }

    private void OnChipPointerReleased(object sender, PointerRoutedEventArgs e)
    {
        _chipPressed = false;
        _chipPressPoint = null;
        try
        {
            TitleChip.ReleasePointerCapture(e.Pointer);
        }
        catch (UnauthorizedAccessException)
        {
            // Pointer was not captured by this element.
        }
    }

    private void OnChipPointerCaptureLost(object sender, PointerRoutedEventArgs e)
    {
        _chipPressed = false;
        _chipPressPoint = null;
    }

    private void OnHeaderDragStarting(UIElement sender, DragStartingEventArgs args)
    {
        if (Leaf?.Tab is not { } tab)
        {
            args.Cancel = true;
            return;
        }

        args.Data.Properties[SessionLayoutHost.DragTabFormat] = tab;
        args.Data.RequestedOperation = DataPackageOperation.Move;
        // Ensure the layout host knows even if PointerMoved path was skipped (keyboard, etc.).
        HeaderDragStarted?.Invoke(this, tab);
    }

    private void OnConnectionHeaderDragOver(object sender, DragEventArgs e) =>
        ConnectionHeaderDragOver?.Invoke(this, e);

    private void OnConnectionHeaderDragLeave(object sender, DragEventArgs e) =>
        ConnectionHeaderDragLeave?.Invoke(this, e);

    private void OnConnectionHeaderDrop(object sender, DragEventArgs e) =>
        ConnectionHeaderDrop?.Invoke(this, e);

    private void OnPaneDragOver(object sender, DragEventArgs e) =>
        LayoutDragOver?.Invoke(this, e);

    private void OnPaneDragLeave(object sender, DragEventArgs e) =>
        LayoutDragLeave?.Invoke(this, e);

    private void OnPaneDrop(object sender, DragEventArgs e) =>
        LayoutDrop?.Invoke(this, e);

    /// <summary>Highlight the connection row while it is a valid move-onto drop target.</summary>
    public void SetConnectionHeaderDropHighlight(bool active)
    {
        if (_headerDropHighlight == active) return;
        _headerDropHighlight = active;
        if (!ShowConnectionHeader) return;

        ConnectionHeader.Background = active
            ? HeaderDropHighlightBrush
            : (Brush)Application.Current.Resources["LayerFillColorDefaultBrush"];
    }

    private static bool IsDescendantOf(DependencyObject? node, DependencyObject ancestor)
    {
        while (node is not null)
        {
            if (ReferenceEquals(node, ancestor)) return true;
            node = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(node);
        }

        return false;
    }
}
