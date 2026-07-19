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
    private readonly ITransientSessionCredentialStore? _transientCredentials;

    [ObservableProperty]
    private SessionTabViewModel? selectedTab;

    private SessionTabViewModel? lastKnownSelectedTab;

    partial void OnSelectedTabChanged(SessionTabViewModel? value)
    {
        if (value is not null && Tabs.Contains(value))
        {
            lastKnownSelectedTab = value;
            return;
        }

        // TabView can briefly report null or an item that has just been removed while its
        // container is being recycled. Never let the app-level selected tab point at a
        // closed VM or at nothing while tabs remain; either state can re-realize a torn-down
        // surface or leave the session host blank.
        var fallback = lastKnownSelectedTab is { } lastSelected && Tabs.Contains(lastSelected)
            ? lastSelected
            : Tabs.Count == 0 ? null : Tabs[Tabs.Count - 1];
        lastKnownSelectedTab = fallback;
        SelectedTab = fallback;
    }

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
        ILogger<ShellViewModel> logger,
        ITransientSessionCredentialStore? transientCredentials = null)
    {
        Tree = tree;
        Update = update;
        _settings = settings;
        _logger = logger;
        _transientCredentials = transientCredentials;

        SidebarWidth = settings.Current.SidebarWidth;

        bool wasEmpty = Tabs.Count == 0;
        Tabs.CollectionChanged += (_, args) =>
        {
            ReleaseTransientCredentials(args);
            var isEmpty = Tabs.Count == 0;
            if (isEmpty != wasEmpty)
            {
                wasEmpty = isEmpty;
                OnPropertyChanged(nameof(HasTabs));
                OnPropertyChanged(nameof(IsEmpty));
            }

            CoerceSelectedTabAfterTabsChanged(args);
        };
    }

    private void ReleaseTransientCredentials(NotifyCollectionChangedEventArgs args)
    {
        if (_transientCredentials is null) return;
        if (args.Action == NotifyCollectionChangedAction.Reset)
        {
            _transientCredentials.Clear();
            return;
        }

        if (args.Action is not (NotifyCollectionChangedAction.Remove or NotifyCollectionChangedAction.Replace))
        {
            return;
        }

        if (args.OldItems is null) return;
        foreach (var item in args.OldItems)
        {
            if (item is SessionTabViewModel { Profile: { IsEphemeral: true } profile })
            {
                var hasOpenDuplicate = Tabs.Any(tab =>
                    tab.Profile is { IsEphemeral: true } remaining &&
                    remaining.NodeId == profile.NodeId);
                if (!hasOpenDuplicate)
                {
                    _transientCredentials.Remove(profile.NodeId);
                }
            }
        }
    }

    private void CoerceSelectedTabAfterTabsChanged(NotifyCollectionChangedEventArgs args)
    {
        var selected = SelectedTab;
        if (selected is null || Tabs.Contains(selected)) return;

        SelectedTab = FindSelectionFallbackAfterRemove(args);
    }

    private SessionTabViewModel? FindSelectionFallbackAfterRemove(NotifyCollectionChangedEventArgs args)
    {
        if (Tabs.Count == 0) return null;

        var fallbackIndex = args.Action is NotifyCollectionChangedAction.Remove or NotifyCollectionChangedAction.Replace
            ? args.OldStartingIndex
            : -1;
        if (fallbackIndex < 0 || fallbackIndex >= Tabs.Count)
        {
            fallbackIndex = Tabs.Count - 1;
        }

        return Tabs[fallbackIndex];
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

        Tabs.Clear();

        var closeTasks = tabs.Select(CloseTabForShutdownAsync).ToArray();
        await Task.WhenAll(closeTasks).ConfigureAwait(true);
    }

    private async Task CloseTabForShutdownAsync(SessionTabViewModel tab)
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
}
