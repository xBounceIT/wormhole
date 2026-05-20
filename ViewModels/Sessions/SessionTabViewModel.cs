using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Models;

namespace Wormhole.ViewModels.Sessions;

public abstract partial class SessionTabViewModel : ObservableObject
{
    [ObservableProperty]
    private string title = string.Empty;

    [ObservableProperty]
    private SessionStatus status = SessionStatus.Disconnected;

    public ConnectionProfile? Profile { get; protected set; }

    public abstract ProtocolType Protocol { get; }
}

public enum SessionStatus
{
    Disconnected,
    Connecting,
    Connected,
    Failed,
}
