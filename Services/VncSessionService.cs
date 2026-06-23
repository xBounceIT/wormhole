using System.Net;
using MarcusW.VncClient;
using MarcusW.VncClient.Output;
using MarcusW.VncClient.Protocol.Implementation.EncodingTypes.Pseudo;
using MarcusW.VncClient.Protocol.Implementation.MessageTypes.Outgoing;
using MarcusW.VncClient.Protocol.Implementation.Services.Transports;
using MarcusW.VncClient.Protocol.SecurityTypes;
using MarcusW.VncClient.Rendering;
using MarcusW.VncClient.Security;
using Microsoft.Extensions.Logging;
using Wormhole.Models;
using Wormhole.Services.Tunneling;

namespace Wormhole.Services;

public sealed class VncSessionService : IVncSessionService
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);

    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<VncSessionService> _logger;

    public VncSessionService(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<VncSessionService>();
    }

    public async Task<IVncSession> ConnectAsync(
        ConnectionProfile profile,
        IVncPasswordProvider passwordProvider,
        IVncRenderTarget renderTarget,
        ITunnelInstance? tunnel = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(passwordProvider);
        ArgumentNullException.ThrowIfNull(renderTarget);
        if (string.IsNullOrWhiteSpace(profile.Host))
            throw new ArgumentException("Connection profile must have a host.", nameof(profile));

        var connectHost = profile.Host;
        var connectPort = profile.Port;
        if (tunnel is not null)
        {
            connectPort = await tunnel.BindLocalForwarderAsync(profile.Host, profile.Port, cancellationToken)
                .ConfigureAwait(false);
            connectHost = IPAddress.Loopback.ToString();
            _logger.LogDebug(
                "Routing VNC connect for {Host}:{Port} through loopback forwarder {LocalHost}:{LocalPort}.",
                profile.Host,
                profile.Port,
                connectHost,
                connectPort);
        }

        var client = new VncClient(_loggerFactory);
        var parameters = new ConnectParameters
        {
            TransportParameters = new TcpTransportParameters
            {
                Host = connectHost,
                Port = connectPort,
            },
            ConnectTimeout = ConnectTimeout,
            MaxReconnectAttempts = 0,
            AllowSharedConnection = true,
            AuthenticationHandler = new PasswordProviderAuthenticationHandler(passwordProvider, cancellationToken),
            InitialRenderTarget = renderTarget,
            InitialOutputHandler = NoopOutputHandler.Instance,
            RenderFlags = RenderFlags.Default,
        };

        var connection = await client.ConnectAsync(parameters, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("VNC connected to {Host}:{Port}.", profile.Host, profile.Port);
        return new VncSessionAdapter(connection, _loggerFactory.CreateLogger<VncSessionAdapter>());
    }

    private sealed class PasswordProviderAuthenticationHandler : IAuthenticationHandler
    {
        private readonly IVncPasswordProvider _passwordProvider;
        private readonly CancellationToken _cancellationToken;

        public PasswordProviderAuthenticationHandler(
            IVncPasswordProvider passwordProvider,
            CancellationToken cancellationToken)
        {
            _passwordProvider = passwordProvider;
            _cancellationToken = cancellationToken;
        }

        public async Task<TInput> ProvideAuthenticationInputAsync<TInput>(
            RfbConnection connection,
            ISecurityType securityType,
            IAuthenticationInputRequest<TInput> request)
            where TInput : class, IAuthenticationInput
        {
            if (typeof(TInput) == typeof(PasswordAuthenticationInput))
            {
                var password = await _passwordProvider.GetPasswordAsync(_cancellationToken).ConfigureAwait(false);
                if (password is null)
                {
                    throw new VncAuthenticationCancelledException();
                }

                return (TInput)(object)new PasswordAuthenticationInput(password);
            }

            if (typeof(TInput) == typeof(CredentialsAuthenticationInput))
            {
                throw new NotSupportedException(
                    $"The VNC server requested username/password authentication ({securityType.Name}), which Wormhole's VNC v1 support does not handle.");
            }

            throw new NotSupportedException(
                $"The VNC server requested unsupported authentication input {typeof(TInput).Name} for {securityType.Name}.");
        }
    }

    private sealed class VncSessionAdapter : IVncSession
    {
        private readonly RfbConnection _connection;
        private readonly ILogger _logger;
        private readonly VncSessionClosedEventReplay _closedEvents;
        private bool _disposed;

        public VncSessionAdapter(RfbConnection connection, ILogger logger)
        {
            _connection = connection;
            _logger = logger;
            _closedEvents = new(this);
            _connection.ConnectionStateChanged += OnConnectionStateChanged;
        }

        public event EventHandler<VncSessionClosedEventArgs>? Closed
        {
            add => _closedEvents.Closed += value;
            remove => _closedEvents.Closed -= value;
        }

        public void SetRenderTarget(IVncRenderTarget renderTarget)
        {
            ArgumentNullException.ThrowIfNull(renderTarget);
            _connection.RenderTarget = renderTarget;
        }

        public Task SendPointerAsync(
            int x,
            int y,
            VncPointerButtons buttons,
            CancellationToken cancellationToken = default)
        {
            var message = new PointerEventMessage(new Position(x, y), ToMouseButtons(buttons));
            return _connection.SendMessageAsync(message, cancellationToken);
        }

        public Task SendKeyAsync(bool isDown, int keySymbol, CancellationToken cancellationToken = default)
        {
            var message = new KeyEventMessage(isDown, (KeySymbol)keySymbol);
            return _connection.SendMessageAsync(message, cancellationToken);
        }

        public async ValueTask DisposeAsync()
        {
            _disposed = true;
            _closedEvents.Dispose();
            _connection.ConnectionStateChanged -= OnConnectionStateChanged;
            try
            {
                await _connection.CloseAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "VNC close threw during teardown.");
            }
            finally
            {
                _connection.Dispose();
            }
        }

        private void OnConnectionStateChanged(object? sender, ConnectionStateChangedEventArgs e)
        {
            if (_disposed) return;

            if (e.CurrentState == ConnectionState.Closed)
            {
                RaiseTerminalClosed(isClean: true, e.Reason, e.Exception);
            }
            else if (e.CurrentState is ConnectionState.Interrupted or ConnectionState.ReconnectFailed)
            {
                RaiseTerminalClosed(isClean: false, e.Reason, e.Exception);
            }
        }

        private void RaiseTerminalClosed(bool isClean, string? reason, Exception? exception)
        {
            var message = !string.IsNullOrWhiteSpace(reason)
                ? reason!
                : exception?.Message ?? (isClean ? "VNC connection closed." : "VNC connection was interrupted.");
            var args = new VncSessionClosedEventArgs(isClean, message, exception);
            _closedEvents.TryRaise(args);
        }

        private static MouseButtons ToMouseButtons(VncPointerButtons buttons)
        {
            var result = MouseButtons.None;
            if (buttons.HasFlag(VncPointerButtons.Left)) result |= MouseButtons.Left;
            if (buttons.HasFlag(VncPointerButtons.Middle)) result |= MouseButtons.Middle;
            if (buttons.HasFlag(VncPointerButtons.Right)) result |= MouseButtons.Right;
            if (buttons.HasFlag(VncPointerButtons.WheelUp)) result |= MouseButtons.WheelUp;
            if (buttons.HasFlag(VncPointerButtons.WheelDown)) result |= MouseButtons.WheelDown;
            if (buttons.HasFlag(VncPointerButtons.WheelLeft)) result |= MouseButtons.WheelLeft;
            if (buttons.HasFlag(VncPointerButtons.WheelRight)) result |= MouseButtons.WheelRight;
            return result;
        }
    }

    private sealed class NoopOutputHandler : IOutputHandler
    {
        public static NoopOutputHandler Instance { get; } = new();

        public void RingBell() { }
        public void HandleServerClipboardUpdate(string text) { }
        public void HandleDesktopNameChange(string name) { }
        public void HandleXvpOperationFailed() { }
        public void HandlePointerModeChange(bool isRelativePointer) { }
        public void HandleLedStateChange(LedState state) { }
        public void HandleExtendedClipboardNotify(MarcusW.VncClient.Protocol.Implementation.ExtendedClipboardFormat formats) { }
        public void HandleExtendedClipboardData(MarcusW.VncClient.Protocol.Implementation.ExtendedClipboardData data) { }
        public void HandleExtendedClipboardRequest(MarcusW.VncClient.Protocol.Implementation.ExtendedClipboardFormat formats) { }
    }
}
