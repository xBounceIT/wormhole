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

    // Bound to the ComboBox.SelectedIndex (which doesn't speak ProtocolType natively).
    // Enum members are ordered Ssh, Rdp, Sftp — same order as the ComboBoxItems.
    public int ProtocolIndex
    {
        get => (int)Protocol;
        set
        {
            if (value < 0) return;
            Protocol = (ProtocolType)value;
        }
    }

    partial void OnProtocolChanged(ProtocolType value) => OnPropertyChanged(nameof(ProtocolIndex));

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
            Username = !string.IsNullOrEmpty(spec.User) ? spec.User : (string.IsNullOrEmpty(Username) ? null : Username),
        };

        _tabFactory.Open(profile);
    }

    private static int DefaultPort(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Sftp => 22,
        ProtocolType.Rdp => 3389,
        _ => 22,
    };
}
