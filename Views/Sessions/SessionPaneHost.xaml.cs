using System.ComponentModel;
using System.Text.Json;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using Wormhole.ViewModels.Sessions.Layout;

namespace Wormhole.Views.Sessions;

public sealed partial class SessionPaneHost : UserControl
{
    public static readonly DependencyProperty LeafProperty =
        DependencyProperty.Register(
            nameof(Leaf),
            typeof(SessionLeafNode),
            typeof(SessionPaneHost),
            new PropertyMetadata(null, OnLeafChanged));

    private static readonly SolidColorBrush FocusBrush =
        new(Color.FromArgb(0xFF, 0x60, 0xCD, 0xFF));

    private static readonly SolidColorBrush TransparentBrush =
        new(Colors.Transparent);

    private SessionLeafNode? _subscribedLeaf;
    private int _leafCount = 1;

    public SessionPaneHost()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    public SessionLeafNode? Leaf
    {
        get => (SessionLeafNode?)GetValue(LeafProperty);
        set => SetValue(LeafProperty, value);
    }

    public SessionDropOverlay Overlay => DropOverlay;

    public event EventHandler<SessionLeafNode>? PaneActivateRequested;

    public void RefreshFocusChrome(int leafCount)
    {
        _leafCount = leafCount;
        UpdateFocusChrome(Leaf?.IsFocused == true);
    }

    private static void OnLeafChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SessionPaneHost host)
        {
            host.AttachLeaf(e.NewValue as SessionLeafNode);
        }
    }

    private void AttachLeaf(SessionLeafNode? newLeaf)
    {
        if (_subscribedLeaf is not null)
        {
            _subscribedLeaf.PropertyChanged -= OnLeafPropertyChanged;
            _subscribedLeaf = null;
        }

        if (newLeaf is null)
        {
            UpdateFocusChrome(false);
            return;
        }

        _subscribedLeaf = newLeaf;
        newLeaf.PropertyChanged += OnLeafPropertyChanged;
        UpdateFocusChrome(newLeaf.IsFocused);
    }

    private void OnLeafPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not SessionLeafNode leaf) return;

        if (e.PropertyName == nameof(SessionLeafNode.IsFocused))
        {
            UpdateFocusChrome(leaf.IsFocused);
        }
    }

    private void UpdateFocusChrome(bool focused)
    {
        // #region agent log
        AgentDebugLog("A", "SessionPaneHost.UpdateFocusChrome", "chrome", new
        {
            focused,
            leafCount = _leafCount,
            wouldShowIfMultiOnly = focused && _leafCount > 1,
            title = Leaf?.Tab?.Title,
        });
        // #endregion
        FocusChrome.BorderBrush = focused ? FocusBrush : TransparentBrush;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (Leaf is { } leaf && !ReferenceEquals(_subscribedLeaf, leaf))
        {
            AttachLeaf(leaf);
        }
        else
        {
            UpdateFocusChrome(Leaf?.IsFocused == true);
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_subscribedLeaf is not null)
        {
            _subscribedLeaf.PropertyChanged -= OnLeafPropertyChanged;
            _subscribedLeaf = null;
        }
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
