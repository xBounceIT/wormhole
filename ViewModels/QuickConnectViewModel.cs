using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wormhole.Models;

namespace Wormhole.ViewModels;

public partial class QuickConnectViewModel : ObservableObject
{
    [ObservableProperty]
    private ProtocolType protocol = ProtocolType.Ssh;

    [ObservableProperty]
    private string host = string.Empty;

    [ObservableProperty]
    private int? port;

    [ObservableProperty]
    private string username = string.Empty;

    [RelayCommand]
    public void Connect()
    {
        // TODO: open a session tab using the selected protocol.
    }
}
