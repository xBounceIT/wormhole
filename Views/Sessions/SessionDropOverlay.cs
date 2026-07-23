using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.UI;
using Wormhole.ViewModels.Sessions.Layout;

namespace Wormhole.Views.Sessions;

/// <summary>
/// Semi-transparent highlight over a leaf pane showing the active docking edge.
/// </summary>
public sealed class SessionDropOverlay : Grid
{
    private readonly Border _highlight;
    private SessionLayoutEdge? _edge;

    public SessionDropOverlay()
    {
        IsHitTestVisible = false;
        Visibility = Visibility.Collapsed;
        Background = new SolidColorBrush(Color.FromArgb(0x00, 0, 0, 0));

        _highlight = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x66, 0x00, 0x78, 0xD4)),
            BorderBrush = new SolidColorBrush(Color.FromArgb(0xCC, 0x60, 0xCD, 0xFF)),
            BorderThickness = new Thickness(2),
            CornerRadius = new CornerRadius(4),
            Opacity = 0,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch,
        };
        Children.Add(_highlight);
        SizeChanged += OnSizeChanged;
    }

    public void Clear()
    {
        _edge = null;
        Visibility = Visibility.Collapsed;
        _highlight.Opacity = 0;
        _highlight.Margin = new Thickness(0);
        _highlight.ClearValue(WidthProperty);
        _highlight.ClearValue(HeightProperty);
        _highlight.HorizontalAlignment = HorizontalAlignment.Stretch;
        _highlight.VerticalAlignment = VerticalAlignment.Stretch;
    }

    public void ShowEdge(SessionLayoutEdge edge)
    {
        Visibility = Visibility.Visible;
        if (_edge == edge)
        {
            return;
        }

        _edge = edge;
        ApplyEdgeLayout(edge);
        AnimateIn();
    }

    private void ApplyEdgeLayout(SessionLayoutEdge edge)
    {
        _highlight.ClearValue(WidthProperty);
        _highlight.ClearValue(HeightProperty);
        const double inset = 4;

        switch (edge)
        {
            case SessionLayoutEdge.Left:
                _highlight.HorizontalAlignment = HorizontalAlignment.Left;
                _highlight.VerticalAlignment = VerticalAlignment.Stretch;
                _highlight.Width = Math.Max(24, ActualWidth * 0.5);
                _highlight.Margin = new Thickness(inset);
                break;
            case SessionLayoutEdge.Right:
                _highlight.HorizontalAlignment = HorizontalAlignment.Right;
                _highlight.VerticalAlignment = VerticalAlignment.Stretch;
                _highlight.Width = Math.Max(24, ActualWidth * 0.5);
                _highlight.Margin = new Thickness(inset);
                break;
            case SessionLayoutEdge.Top:
                _highlight.HorizontalAlignment = HorizontalAlignment.Stretch;
                _highlight.VerticalAlignment = VerticalAlignment.Top;
                _highlight.Height = Math.Max(24, ActualHeight * 0.5);
                _highlight.Margin = new Thickness(inset);
                break;
            case SessionLayoutEdge.Bottom:
                _highlight.HorizontalAlignment = HorizontalAlignment.Stretch;
                _highlight.VerticalAlignment = VerticalAlignment.Bottom;
                _highlight.Height = Math.Max(24, ActualHeight * 0.5);
                _highlight.Margin = new Thickness(inset);
                break;
        }
    }

    private void AnimateIn()
    {
        var anim = new DoubleAnimation
        {
            To = 1,
            Duration = new Duration(TimeSpan.FromMilliseconds(120)),
            EasingFunction = new CircleEase { EasingMode = EasingMode.EaseOut },
        };
        Storyboard.SetTarget(anim, _highlight);
        Storyboard.SetTargetProperty(anim, "Opacity");
        var sb = new Storyboard();
        sb.Children.Add(anim);
        sb.Begin();
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (_edge is { } edge && Visibility == Visibility.Visible)
        {
            ApplyEdgeLayout(edge);
        }
    }
}
