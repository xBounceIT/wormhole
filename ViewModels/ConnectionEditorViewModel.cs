using System;
using System.Collections.ObjectModel;
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

    // Tri-state: null = inherit from ancestor folder, false = explicitly off, true = explicitly on.
    // Matches the existing RdpFullScreen shape so the UI control can bind directly.
    [ObservableProperty]
    private bool? tunnelEnabled;

    [ObservableProperty]
    private Guid? selectedTunnelConfigId;

    public ObservableCollection<TunnelConfig> AvailableTunnelConfigs { get; } = new();
}
