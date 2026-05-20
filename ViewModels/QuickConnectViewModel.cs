using System;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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

        var (user, hostName, parsedPort) = ParseTarget(Host.Trim());
        var profile = new ConnectionProfile
        {
            NodeId = Guid.NewGuid(),
            Name = Host.Trim(),
            Protocol = Protocol,
            Host = hostName,
            Port = parsedPort ?? Port ?? DefaultPort(Protocol),
            Username = !string.IsNullOrEmpty(user) ? user : (string.IsNullOrEmpty(Username) ? null : Username),
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

    private static (string? User, string Host, int? Port) ParseTarget(string input)
    {
        string? user = null;
        var s = input;

        var at = s.IndexOf('@');
        if (at > 0)
        {
            user = s.Substring(0, at);
            s = s.Substring(at + 1);
        }

        int? port = null;
        var colon = s.LastIndexOf(':');
        if (colon > 0 && int.TryParse(s.AsSpan(colon + 1), out var p))
        {
            port = p;
            s = s.Substring(0, colon);
        }

        return (user, s, port);
    }

    private static int DefaultPort(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Sftp => 22,
        ProtocolType.Rdp => 3389,
        _ => 22,
    };
}
