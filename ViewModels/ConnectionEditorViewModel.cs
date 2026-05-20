using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Models;

namespace Wormhole.ViewModels;

public partial class ConnectionEditorViewModel : ObservableObject
{
    [ObservableProperty]
    private string name = string.Empty;

    [ObservableProperty]
    private ProtocolType protocol = ProtocolType.Ssh;

    [ObservableProperty]
    private string host = string.Empty;

    [ObservableProperty]
    private int? port;

    [ObservableProperty]
    private string username = string.Empty;
}
