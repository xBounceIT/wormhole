using System;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class QuickConnectViewModel : ObservableObject
{
    private readonly ISessionTabFactory _tabFactory;

    [ObservableProperty]
    private ProtocolType protocol = ProtocolType.Ssh;

    [ObservableProperty]
    private string host = string.Empty;

    [ObservableProperty]
    private int? port;

    [ObservableProperty]
    private string username = string.Empty;

    public QuickConnectViewModel(ISessionTabFactory tabFactory)
    {
        _tabFactory = tabFactory;
    }

    [RelayCommand]
    public void Connect()
    {
        if (string.IsNullOrWhiteSpace(Host)) return;

        var spec = HostSpecParser.Parse(Host);
        var profile = new ConnectionProfile
        {
            NodeId = Guid.NewGuid(),
            Name = Host.Trim(),
            Protocol = Protocol,
            Host = spec.Host,
            Port = spec.Port ?? Port ?? DefaultPort(Protocol),
            Username = !string.IsNullOrEmpty(spec.User) ? spec.User : (string.IsNullOrEmpty(Username) ? null : Username),
        };

        switch (Protocol)
        {
            case ProtocolType.Ssh:
                _tabFactory.OpenSsh(profile);
                break;
            default:
                // RDP/SFTP UI surfaces land in follow-up PRs.
                throw new NotSupportedException($"Quick-connect for {Protocol} is not implemented yet.");
        }
    }

    private static int DefaultPort(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Sftp => 22,
        ProtocolType.Rdp => 3389,
        _ => 22,
    };
}
