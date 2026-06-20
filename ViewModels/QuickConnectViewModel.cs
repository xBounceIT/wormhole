using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class QuickConnectViewModel : ObservableObject
{
    private static readonly ProtocolType[] QuickConnectProtocols =
    {
        ProtocolType.Ssh,
        ProtocolType.Rdp,
        ProtocolType.Serial,
    };

    private readonly ISessionTabFactory _tabFactory;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProtocolIndex), nameof(HostPlaceholder))]
    private ProtocolType protocol = ProtocolType.Ssh;

    // Bound to the ComboBox.SelectedIndex (which doesn't speak ProtocolType natively).
    public int ProtocolIndex
    {
        get => Array.IndexOf(QuickConnectProtocols, Protocol);
        set
        {
            if (value < 0 || value >= QuickConnectProtocols.Length) return;
            Protocol = QuickConnectProtocols[value];
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
            Username = !string.IsNullOrEmpty(spec.User) ? spec.User : (string.IsNullOrEmpty(Username) ? null : Username),
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
        _ => 22,
    };
}
