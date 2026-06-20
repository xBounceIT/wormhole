using System.IO.Ports;
using Microsoft.Extensions.Logging;
using Wormhole.Models;
using Wormhole.Services.Serial;
using PortsParity = System.IO.Ports.Parity;
using PortsStopBits = System.IO.Ports.StopBits;

namespace Wormhole.Services;

public sealed class SerialSessionService : ISerialSessionService
{
    private readonly ILogger<SerialSessionService> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public SerialSessionService(ILogger<SerialSessionService> logger, ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    public async Task<ITerminalSession> ConnectAsync(
        ConnectionProfile profile,
        TerminalSize initialSize,
        CancellationToken cancellationToken = default)
    {
        if (profile.Protocol != ProtocolType.Serial)
            throw new ArgumentException("Connection profile must use the serial protocol.", nameof(profile));
        if (string.IsNullOrWhiteSpace(profile.Host))
            throw new ArgumentException("Connection profile must have a serial line name.", nameof(profile));

        var portName = profile.Host.Trim();
        var baudRate = SerialDefaults.NormalizeBaudRate(profile.SerialBaudRate);
        var dataBits = SerialDefaults.NormalizeDataBits(profile.SerialDataBits);
        var stopBits = SerialDefaults.NormalizeStopBits(profile.SerialStopBits);
        var parity = SerialDefaults.NormalizeParity(profile.SerialParity);
        var flowControl = SerialDefaults.NormalizeFlowControl(profile.SerialFlowControl);
        var port = new SerialPort(
            portName,
            baudRate,
            ToPortsParity(parity),
            dataBits,
            ToPortsStopBits(stopBits))
        {
            Handshake = ToHandshake(flowControl),
            ReadTimeout = SerialPort.InfiniteTimeout,
            WriteTimeout = SerialPort.InfiniteTimeout,
            ReadBufferSize = 64 * 1024,
            WriteBufferSize = 64 * 1024,
            DtrEnable = true,
        };

        if (flowControl != SerialFlowControlMode.RtsCts)
        {
            port.RtsEnable = true;
        }

        try
        {
            await Task.Run(port.Open, CancellationToken.None).WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            SafeDispose(port);
            throw;
        }

        _logger.LogInformation(
            "Serial port {PortName} opened at {BaudRate} baud, {DataBits}{Parity}{StopBits}, flow {FlowControl}.",
            port.PortName,
            baudRate,
            dataBits,
            ParityDisplay(parity),
            StopBitsDisplay(stopBits),
            flowControl);

        return new SerialSession(
            port,
            flowControl,
            _loggerFactory.CreateLogger<SerialSession>());
    }

    private static Handshake ToHandshake(SerialFlowControlMode flowControl) => flowControl switch
    {
        SerialFlowControlMode.XonXoff => Handshake.XOnXOff,
        SerialFlowControlMode.RtsCts => Handshake.RequestToSend,
        _ => Handshake.None,
    };

    private static PortsParity ToPortsParity(SerialParityMode parity) => parity switch
    {
        SerialParityMode.Odd => PortsParity.Odd,
        SerialParityMode.Even => PortsParity.Even,
        SerialParityMode.Mark => PortsParity.Mark,
        SerialParityMode.Space => PortsParity.Space,
        _ => PortsParity.None,
    };

    private static PortsStopBits ToPortsStopBits(SerialStopBitsMode stopBits) => stopBits switch
    {
        SerialStopBitsMode.Two => PortsStopBits.Two,
        SerialStopBitsMode.OnePointFive => PortsStopBits.OnePointFive,
        _ => PortsStopBits.One,
    };

    private static string StopBitsDisplay(SerialStopBitsMode stopBits) => stopBits switch
    {
        SerialStopBitsMode.Two => "2",
        SerialStopBitsMode.OnePointFive => "1.5",
        _ => "1",
    };

    private static string ParityDisplay(SerialParityMode parity) => parity switch
    {
        SerialParityMode.Odd => "O",
        SerialParityMode.Even => "E",
        SerialParityMode.Mark => "M",
        SerialParityMode.Space => "S",
        _ => "N",
    };

    private static void SafeDispose(SerialPort port)
    {
        try { port.Dispose(); } catch { /* best effort */ }
    }
}
