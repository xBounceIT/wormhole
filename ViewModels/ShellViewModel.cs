using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.ViewModels;

public partial class ShellViewModel : ObservableObject
{
    [ObservableProperty]
    private SessionTabViewModel? selectedTab;

    public ObservableCollection<SessionTabViewModel> Tabs { get; } = new();

    public ConnectionTreeViewModel Tree { get; }

    public ShellViewModel(ConnectionTreeViewModel tree)
    {
        Tree = tree;
    }
}
