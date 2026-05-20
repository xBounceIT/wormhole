using System.Collections.ObjectModel;
using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.ViewModels;

public partial class ShellViewModel : ObservableObject
{
    [ObservableProperty]
    private SessionTabViewModel? selectedTab;

    public ObservableCollection<SessionTabViewModel> Tabs { get; } = new();

    public ConnectionTreeViewModel Tree { get; }

    public bool HasNoTabs => Tabs.Count == 0;

    public ShellViewModel(ConnectionTreeViewModel tree)
    {
        Tree = tree;
        Tabs.CollectionChanged += OnTabsChanged;
    }

    private void OnTabsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        OnPropertyChanged(nameof(HasNoTabs));
    }
}
