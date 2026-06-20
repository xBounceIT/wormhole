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

    public IReadOnlyList<QuickConnectProtocolChoice> ProtocolChoices { get; } = new[]
    {
        new QuickConnectProtocolChoice(ProtocolType.Ssh, "SSH"),
        new QuickConnectProtocolChoice(ProtocolType.Rdp, "RDP"),
        new QuickConnectProtocolChoice(ProtocolType.Vnc, "VNC"),
    };

    public QuickConnectProtocolChoice? SelectedProtocolChoice
    {
        get => ProtocolChoices.FirstOrDefault(c => c.Protocol == Protocol);
        set
        {
            if (value is null) return;
            Protocol = value.Protocol;
        }
    }

    partial void OnProtocolChanged(ProtocolType value) => OnPropertyChanged(nameof(SelectedProtocolChoice));

    [ObservableProperty]
    private string host = string.Empty;

    [ObservableProperty]
    private int? port;

    [ObservableProperty]
    private string username = string.Empty;

    [ObservableProperty]
    private string? errorMessage;

    public QuickConnectViewModel(ISessionTabFactory tabFactory)
    {
        _tabFactory = tabFactory;
    }

    [RelayCommand]
    public void Connect()
    {
        ErrorMessage = null;
        if (string.IsNullOrWhiteSpace(Host)) return;

        HostSpec spec;
        try
        {
            spec = HostSpecParser.Parse(Host);
        }
        catch (FormatException ex)
        {
            ErrorMessage = ex.Message;
            return;
        }

        var profile = new ConnectionProfile
        {
            NodeId = Guid.NewGuid(),
            Name = Host.Trim(),
            Protocol = Protocol,
            Host = spec.Host,
            Port = spec.Port ?? Port ?? DefaultPort(Protocol),
            Username = Protocol == ProtocolType.Vnc
                ? null
                : !string.IsNullOrEmpty(spec.User) ? spec.User : (string.IsNullOrEmpty(Username) ? null : Username),
        };

        _tabFactory.Open(profile);
    }

    private static int DefaultPort(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Rdp => 3389,
        ProtocolType.Vnc => 5900,
        _ => 22,
    };
}

public sealed record QuickConnectProtocolChoice(ProtocolType Protocol, string Label);
