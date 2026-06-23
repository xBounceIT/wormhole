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
    [NotifyPropertyChangedFor(nameof(HostPlaceholder))]
    private ProtocolType protocol = ProtocolType.Ssh;

    public IReadOnlyList<QuickConnectProtocolChoice> ProtocolChoices { get; } = new[]
    {
        new QuickConnectProtocolChoice(ProtocolType.Ssh, "SSH"),
        new QuickConnectProtocolChoice(ProtocolType.Rdp, "RDP"),
        new QuickConnectProtocolChoice(ProtocolType.Vnc, "VNC"),
        new QuickConnectProtocolChoice(ProtocolType.Serial, "SERIAL"),
    };

    public QuickConnectProtocolChoice? SelectedProtocolChoice
    {
        get => ProtocolChoices.FirstOrDefault(c => c.Protocol == Protocol);
        set
        {
            if (value is null || value.Protocol == Protocol) return;
            Protocol = value.Protocol;
        }
    }

    public string HostPlaceholder => Protocol == ProtocolType.Serial ? "COM1 or COM1:115200" : "user@host";

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

    partial void OnProtocolChanged(ProtocolType value) => OnPropertyChanged(nameof(SelectedProtocolChoice));

    [RelayCommand]
    public void Connect()
    {
        ErrorMessage = null;
        if (string.IsNullOrWhiteSpace(Host)) return;

        if (Protocol == ProtocolType.Serial)
        {
            if (!TryParseSerialTarget(Host, out var portName, out var baudRate, out var error))
            {
                ErrorMessage = error;
                return;
            }

            _tabFactory.Open(new ConnectionProfile
            {
                NodeId = Guid.NewGuid(),
                Name = portName,
                Protocol = ProtocolType.Serial,
                Host = portName,
                Port = 0,
                SerialBaudRate = baudRate ?? SerialDefaults.BaudRate,
                SerialDataBits = SerialDefaults.DataBits,
                SerialStopBits = SerialDefaults.StopBits,
                SerialParity = SerialDefaults.Parity,
                SerialFlowControl = SerialDefaults.FlowControl,
            });
            return;
        }

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

    private static bool TryParseSerialTarget(string input, out string portName, out int? baudRate, out string? error)
    {
        var trimmed = input.Trim();
        portName = trimmed;
        baudRate = null;
        error = null;
        if (string.IsNullOrWhiteSpace(trimmed)) return false;

        var separator = trimmed.LastIndexOf(':');
        if (separator < 0) return true;

        if (separator == 0 || separator == trimmed.Length - 1 ||
            !int.TryParse(trimmed[(separator + 1)..], out var parsedBaudRate) ||
            parsedBaudRate <= 0)
        {
            error = "Serial quick connect must use COM1 or COM1:115200.";
            return false;
        }

        portName = trimmed[..separator].Trim();
        baudRate = parsedBaudRate;
        if (!string.IsNullOrWhiteSpace(portName)) return true;

        error = "Serial quick connect must use COM1 or COM1:115200.";
        return false;
    }

    private static int DefaultPort(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Rdp => 3389,
        ProtocolType.Vnc => 5900,
        ProtocolType.Serial => 0,
        _ => 22,
    };
}

public sealed record QuickConnectProtocolChoice(ProtocolType Protocol, string Label);