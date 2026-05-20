using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Xaml;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.ViewModels;

public partial class ShellViewModel : ObservableObject
{
    private const double ResizerHitWidth = 24;
    private const double FallbackMinSidebarWidth = 120;
    private const double MaxSidebarWidth = 600;
    private const double TextFitPadding = 8;

    private readonly IAppSettingsService _settings;

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

    public double SidebarResizerHitWidth => ResizerHitWidth;

    public Thickness SidebarResizerMargin =>
        new(sidebarWidth - (ResizerHitWidth / 2), 0, 0, 0);

    public ObservableCollection<SessionTabViewModel> Tabs { get; } = new();

    public bool HasTabs => Tabs.Count > 0;

    public bool IsEmpty => Tabs.Count == 0;

    public ConnectionTreeViewModel Tree { get; }

    public UpdateViewModel Update { get; }

    public ShellViewModel(ConnectionTreeViewModel tree, UpdateViewModel update, IAppSettingsService settings)
    {
        Tree = tree;
        Update = update;
        _settings = settings;

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
}
