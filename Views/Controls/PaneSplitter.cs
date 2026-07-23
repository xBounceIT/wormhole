using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Wormhole.ViewModels.Sessions.Layout;

namespace Wormhole.Views.Controls;

/// <summary>
/// Thin grip between session panes. Drag updates <see cref="SessionSplitNode.Ratio"/>.
/// </summary>
public sealed class PaneSplitter : ContentControl
{
    public static readonly DependencyProperty SplitProperty =
        DependencyProperty.Register(
            nameof(Split),
            typeof(SessionSplitNode),
            typeof(PaneSplitter),
            new PropertyMetadata(null, OnSplitChanged));

    private bool _dragging;
    private Point _origin;
    private double _originRatio;
    private FrameworkElement? _track;
    private Rect _trackBounds;

    public PaneSplitter()
    {
        IsTabStop = false;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;
        Content = new Border
        {
            Background = new SolidColorBrush(Colors.Transparent),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch,
        };

        PointerPressed += OnPointerPressed;
        PointerMoved += OnPointerMoved;
        PointerReleased += OnPointerReleased;
        PointerCaptureLost += OnPointerCaptureLost;
    }

    public SessionSplitNode? Split
    {
        get => (SessionSplitNode?)GetValue(SplitProperty);
        set => SetValue(SplitProperty, value);
    }

    /// <summary>
    /// Element used for pointer coordinates (usually the layout host).
    /// </summary>
    public FrameworkElement? Track
    {
        get => _track;
        set => _track = value;
    }

    /// <summary>
    /// Bounds of this split within <see cref="Track"/> coordinates.
    /// </summary>
    public Rect TrackBounds
    {
        get => _trackBounds;
        set => _trackBounds = value;
    }

    public event EventHandler? RatioChanged;

    private static void OnSplitChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not PaneSplitter splitter) return;
        splitter.UpdateCursor();
    }

    private void UpdateCursor()
    {
        ProtectedCursor = Split?.Orientation == SessionSplitOrientation.Horizontal
            ? InputSystemCursor.Create(InputSystemCursorShape.SizeWestEast)
            : InputSystemCursor.Create(InputSystemCursorShape.SizeNorthSouth);
    }

    private void OnPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (Split is null || Track is null) return;
        _dragging = true;
        _origin = e.GetCurrentPoint(Track).Position;
        _originRatio = Split.Ratio;
        CapturePointer(e.Pointer);
        e.Handled = true;
    }

    private void OnPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_dragging || Split is null || Track is null) return;

        var pos = e.GetCurrentPoint(Track).Position;
        double span;
        double delta;
        if (Split.Orientation == SessionSplitOrientation.Horizontal)
        {
            span = Math.Max(1, _trackBounds.Width - ActualWidth);
            delta = pos.X - _origin.X;
        }
        else
        {
            span = Math.Max(1, _trackBounds.Height - ActualHeight);
            delta = pos.Y - _origin.Y;
        }

        SessionLayoutController.SetRatio(Split, _originRatio + (delta / span));
        RatioChanged?.Invoke(this, EventArgs.Empty);
        e.Handled = true;
    }

    private void OnPointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (!_dragging) return;
        _dragging = false;
        ReleasePointerCapture(e.Pointer);
        e.Handled = true;
    }

    private void OnPointerCaptureLost(object sender, PointerRoutedEventArgs e)
    {
        _dragging = false;
    }
}
