using System.Collections.ObjectModel;
using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.ViewModels;

public partial class ShellViewModel : ObservableObject
{
    private const double ResizerHitWidth = 8;
    private const double FallbackMinSidebarWidth = 120;
    private const double MaxSidebarWidth = 600;
    private const double TextFitPadding = 8;

    private readonly IAppSettingsService _settings;
    private readonly ILogger<ShellViewModel> _logger;

    [ObservableProperty]
    private SessionTabViewModel? selectedTab;

    [ObservableProperty]
    private double minSidebarWidth = FallbackMinSidebarWidth;

    private double sidebarWidth;
    public double SidebarWidth
    {
        get => sidebarWidth;
        set
        {
            var clamped = value;
            if (clamped < MinSidebarWidth) clamped = MinSidebarWidth;
            if (clamped > MaxSidebarWidth) clamped = MaxSidebarWidth;
            // Cap to the host's current width so the resizer (positioned at the
            // pane's right edge) stays inside the window after a shrink. The
            // NavigationView already renders min(OpenPaneLength, windowWidth),
            // but the overlay margin is computed from the raw value.
            if (clamped > maxAvailableWidth) clamped = maxAvailableWidth;
            if (SetProperty(ref sidebarWidth, clamped))
            {
                OnPropertyChanged(nameof(SidebarResizerMargin));
            }
        }
    }

    private double maxAvailableWidth = double.PositiveInfinity;
    public double MaxAvailableWidth
    {
        get => maxAvailableWidth;
        set
        {
            if (value <= 0) return;
            if (SetProperty(ref maxAvailableWidth, value))
            {
                // Re-apply the clamp so a window shrink pulls the sidebar back
                // to a width where the drag handle is reachable on-screen.
                SidebarWidth = sidebarWidth;
            }
        }
    }

#pragma warning disable CA1822 // kept instance — bound from XAML via {x:Bind ViewModel.SidebarResizerHitWidth}
    public double SidebarResizerHitWidth => ResizerHitWidth;
#pragma warning restore CA1822

    public Thickness SidebarResizerMargin =>
        new(sidebarWidth - (ResizerHitWidth / 2), 0, 0, 0);

    public ObservableCollection<SessionTabViewModel> Tabs { get; } = new();

    public bool HasTabs => Tabs.Count > 0;

    public bool IsEmpty => Tabs.Count == 0;

    /// <summary>
    /// Number of open tabs holding a live connection that closing the app would disconnect
    /// (see <see cref="SessionTabViewModel.WillDisconnectOnAppClose"/>). Computed on demand —
    /// read by the window-close path to decide whether to warn before disconnecting. Disconnected,
    /// failed, and handed-off external sessions are excluded: closing the app won't tear them down,
    /// so they don't warrant a confirmation prompt.
    /// </summary>
    public int ActiveSessionCount => Tabs.Count(static tab => tab.WillDisconnectOnAppClose);

    public ConnectionTreeViewModel Tree { get; }

    public UpdateViewModel Update { get; }

    public ShellViewModel(
        ConnectionTreeViewModel tree,
        UpdateViewModel update,
        IAppSettingsService settings,
        ILogger<ShellViewModel> logger)
    {
        Tree = tree;
        Update = update;
        _settings = settings;
        _logger = logger;

        SidebarWidth = settings.Current.SidebarWidth;

        bool wasEmpty = Tabs.Count == 0;
        Tabs.CollectionChanged += (_, _) =>
        {
            var isEmpty = Tabs.Count == 0;
            if (isEmpty == wasEmpty) return;
            wasEmpty = isEmpty;
            OnPropertyChanged(nameof(HasTabs));
            OnPropertyChanged(nameof(IsEmpty));
        };
    }

    public void ApplyMeasuredMinSidebarWidth(double measuredItemWidth)
    {
        if (measuredItemWidth <= 0) return;
        MinSidebarWidth = Math.Round(measuredItemWidth + TextFitPadding);
        if (SidebarWidth < MinSidebarWidth)
        {
            SidebarWidth = MinSidebarWidth;
        }
    }

    public void PersistSidebarWidth()
    {
        var rounded = (int)Math.Round(SidebarWidth);
        if (_settings.Current.SidebarWidth == rounded) return;
        _settings.Current.SidebarWidth = rounded;
        _settings.Save();
    }

    public async Task CloseAllSessionsAsync()
    {
        var tabs = Tabs.ToArray();
        foreach (var tab in tabs)
        {
            try
            {
                await tab.CloseAsync().ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Session tab '{Title}' failed to close during app shutdown.", tab.Title);
            }
        }

        SelectedTab = null;
        Tabs.Clear();
    }
}
