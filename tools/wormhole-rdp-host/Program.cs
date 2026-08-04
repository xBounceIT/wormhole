using System.Text.Json;
using System.Text.Json.Serialization;
using Wormhole.Helpers;
using Wormhole.Interop.Rdp;
using Wormhole.Models;

namespace Wormhole.RdpHost;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new RdpHostApplicationContext());
        return 0;
    }
}

internal sealed class RdpHostApplicationContext : ApplicationContext
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly object _outputLock = new();
    private readonly Control _dispatcher;
    private RdpHostForm? _form;
    private bool _closing;

    public RdpHostApplicationContext()
    {
        // A hidden control gives the reader thread a stable STA dispatch target. The ActiveX
        // form is created, configured, and disposed only from this UI thread.
        _dispatcher = new Control();
        _dispatcher.CreateControl();
        _ = Task.Run(ReadCommandsAsync);
    }

    private async Task ReadCommandsAsync()
    {
        try
        {
            while (await Console.In.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                RdpHostCommand? command;
                try
                {
                    command = JsonSerializer.Deserialize<RdpHostCommand>(line, JsonOptions);
                }
                catch (JsonException)
                {
                    Write(new RdpHostEvent("error", Message: "invalid native RDP command"));
                    continue;
                }
                if (command is null) continue;

                try
                {
                    _dispatcher.BeginInvoke((Action)(() => HandleCommand(command)));
                }
                catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
                {
                    return;
                }
            }
        }
        catch (IOException)
        {
            // The Go supervisor can close stdin while tearing down the process. That is a normal
            // shutdown path, not a user-visible RDP error.
        }
        finally
        {
            TryBeginInvoke(CloseHost);
        }
    }

    private void HandleCommand(RdpHostCommand command)
    {
        if (_closing) return;

        try
        {
            switch (command.Op)
            {
                case "start":
                    Start(command);
                    break;
                case "resize":
                    if (_form is not null && command.Bounds.IsUsable)
                    {
                        if (!_form.SetHostBounds(
                                command.Bounds.X,
                                command.Bounds.Y,
                                command.Bounds.Width,
                                command.Bounds.Height))
                        {
                            throw new InvalidOperationException("native RDP surface resize failed");
                        }
                    }
                    Write(new RdpHostEvent("ack", command.RequestId));
                    break;
                case "show":
                    if (_form is not null)
                    {
                        if (command.Bounds.IsUsable)
                        {
                            if (!_form.SetHostBounds(
                                    command.Bounds.X,
                                    command.Bounds.Y,
                                    command.Bounds.Width,
                                    command.Bounds.Height,
                                    reveal: true))
                            {
                                throw new InvalidOperationException("native RDP surface reveal failed");
                            }
                        }
                        else
                        {
                            _ = Win32Interop.ShowWindow(_form.Hwnd, Win32Interop.SW_SHOWNA);
                        }
                    }
                    Write(new RdpHostEvent("ack", command.RequestId));
                    break;
                case "hide":
                    if (_form is not null) _ = Win32Interop.ShowWindow(_form.Hwnd, Win32Interop.SW_HIDE);
                    Write(new RdpHostEvent("ack", command.RequestId));
                    break;
                case "focus":
                    _form?.RequestFocus();
                    Write(new RdpHostEvent("ack", command.RequestId));
                    break;
                case "disconnect":
                case "shutdown":
                    Write(new RdpHostEvent("ack", command.RequestId));
                    CloseHost();
                    break;
                default:
                    Write(new RdpHostEvent("error", command.RequestId, "unsupported native RDP command"));
                    break;
            }
        }
        catch (Exception)
        {
            // Never serialize exception text from the ActiveX stack: some COM providers include
            // server/user data in their messages. The UI only needs a stable, secret-free error.
            Write(new RdpHostEvent("error", command.RequestId, "native Windows RDP host operation failed"));
            if (command.Op == "start") CloseHost();
        }
    }

    private void Start(RdpHostCommand command)
    {
        if (_form is not null)
        {
            Write(new RdpHostEvent("error", command.RequestId, "native RDP host is already initialized"));
            return;
        }
        if (!command.Bounds.IsUsable)
        {
            throw new InvalidOperationException("native RDP surface bounds are invalid");
        }

        var owner = ParseWindowHandle(command.OwnerWindow);
        if (owner == IntPtr.Zero)
        {
            throw new InvalidOperationException("Electron owner window handle is missing");
        }

        var form = CreateRealizedHostForm();
        _form = form;
        var connectionVisible = false;
        void Reveal(string context, bool focus = false)
        {
            connectionVisible = true;
            try
            {
                _ = Win32Interop.ShowWindow(form.Hwnd, Win32Interop.SW_SHOWNA);
                _ = form.EnsureVisibleAndRedraw(context);
                if (focus) form.RequestFocus();
            }
            catch
            {
                // The OCX can be tearing down concurrently with a terminal event. The Go
                // process boundary still contains the failure and the next retry creates a new
                // helper/form.
            }
        }

        void Conceal()
        {
            connectionVisible = false;
            try { _ = Win32Interop.ShowWindow(form.Hwnd, Win32Interop.SW_HIDE); }
            catch { /* best-effort during teardown */ }
        }

        form.Connected += () =>
        {
            Reveal("connected", focus: true);
            Write(new RdpHostEvent("connected"));
        };
        form.LoginComplete += () =>
        {
            Reveal("login-complete", focus: true);
            Write(new RdpHostEvent("loginComplete"));
        };
        form.Disconnected += code =>
        {
            Conceal();
            var info = form.GetDisconnectInfo(code);
            Write(new RdpHostEvent("disconnected", Code: code, Message: info.Description));
            // The WinUI service disposes the ActiveX host after a terminal disconnect. Do the
            // same here so a later Retry can create a fresh OCX instead of hitting Start()'s
            // one-shot guard on a dead control. Auto-reconnect events arrive before this terminal
            // notification and keep the form alive while the OCX is recovering.
            CloseHost();
        };
        form.FatalError += code =>
        {
            Conceal();
            Write(new RdpHostEvent("fatalError", Code: code));
            CloseHost();
        };
        form.LogonError += code => Write(new RdpHostEvent("logonError", Code: code));
        form.AutoReconnecting2 += (_, _, attempt, max) =>
        {
            Conceal();
            Write(new RdpHostEvent("autoReconnecting", Attempt: attempt, Max: max));
        };
        form.AutoReconnected += () =>
        {
            Reveal("auto-reconnected");
            Write(new RdpHostEvent("autoReconnected"));
        };

        var hwnd = form.Hwnd;
        ConfigureAsOwnedOverlay(hwnd, owner);
        var profile = command.Profile.ToConnectionProfile();
        form.Configure(
            profile,
            command.Profile.Password,
            command.Profile.GatewayUsername,
            command.Profile.GatewayPassword,
            owner,
            command.Bounds.Width,
            command.Bounds.Height);
        if (!form.SetHostBounds(
                command.Bounds.X,
                command.Bounds.Y,
                command.Bounds.Width,
                command.Bounds.Height,
                reveal: true))
        {
            throw new InvalidOperationException("native RDP surface activation failed");
        }

        // Start only after every event subscription and the owned overlay relationship are in
        // place. This mirrors RdpSessionService's early-event race fix in the WinUI client.
        form.Start();
        if (!_closing && !connectionVisible) Conceal();
        if (!_closing) Write(new RdpHostEvent("ready"));
    }

    private static RdpHostForm CreateRealizedHostForm()
    {
        // Match the WinUI service's activation policy: try the newest registered mstscax class,
        // fall back through older registrations, and force both HWNDs before Configure. Some
        // machines register the CLSID but fail during AxHost in-place activation, so probing only
        // the registry is not enough.
        var candidates = AxMsRdpClient9NotSafeForScripting.GetRegisteredClasses();
        for (var index = 0; index < candidates.Count - 1; index++)
        {
            RdpHostForm? candidate = null;
            try
            {
                candidate = new RdpHostForm(candidates[index]);
                _ = candidate.Hwnd;
                return candidate;
            }
            catch (Exception)
            {
                try { candidate?.Dispose(); }
                catch { /* try the next registered ActiveX class */ }
            }
        }

        var fallback = new RdpHostForm(candidates[^1]);
        _ = fallback.Hwnd;
        return fallback;
    }

    private void CloseHost()
    {
        if (_closing) return;
        _closing = true;
        try
        {
            _form?.Disconnect();
            _form?.Dispose();
        }
        catch
        {
            // Best-effort teardown; the process boundary is the final containment layer.
        }
        finally
        {
            _form = null;
            _dispatcher.Dispose();
            ExitThread();
        }
    }

    private void TryBeginInvoke(Action action)
    {
        try
        {
            if (!_dispatcher.IsDisposed) _dispatcher.BeginInvoke(action);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            // The message loop is already down.
        }
    }

    private void Write(RdpHostEvent response)
    {
        lock (_outputLock)
        {
            try
            {
                Console.Out.WriteLine(JsonSerializer.Serialize(response, JsonOptions));
                Console.Out.Flush();
            }
            catch (IOException)
            {
                TryBeginInvoke(CloseHost);
            }
        }
    }

    private static IntPtr ParseWindowHandle(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return IntPtr.Zero;
        var text = raw.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        if (!ulong.TryParse(
                text,
                text.Any(char.IsLetter) ? System.Globalization.NumberStyles.HexNumber : System.Globalization.NumberStyles.Integer,
                provider: null,
                out var value))
        {
            return IntPtr.Zero;
        }
        return new IntPtr(unchecked((long)value));
    }

    private static void ConfigureAsOwnedOverlay(IntPtr hwnd, IntPtr owner)
    {
        Win32Interop.SetWindowLongPtr(hwnd, Win32Interop.GWLP_HWNDPARENT, owner);
        var style = Win32Interop.GetWindowLongPtr(hwnd, Win32Interop.GWL_EXSTYLE).ToInt64();
        var toolWindowStyle = style | Win32Interop.WS_EX_TOOLWINDOW;
        if (toolWindowStyle != style)
        {
            Win32Interop.SetWindowLongPtr(hwnd, Win32Interop.GWL_EXSTYLE, new IntPtr(toolWindowStyle));
        }
        _ = Win32Interop.SetWindowPos(
            hwnd,
            IntPtr.Zero,
            0,
            0,
            0,
            0,
            Win32Interop.SWP_NOMOVE |
            Win32Interop.SWP_NOSIZE |
            Win32Interop.SWP_NOZORDER |
            Win32Interop.SWP_NOACTIVATE |
            Win32Interop.SWP_FRAMECHANGED);
    }
}

internal sealed class RdpHostCommand
{
    public string Op { get; set; } = string.Empty;
    public string RequestId { get; set; } = string.Empty;
    public string OwnerWindow { get; set; } = string.Empty;
    public RdpHostBounds Bounds { get; set; }
    public RdpHostProfile Profile { get; set; } = new();
}

internal readonly record struct RdpHostBounds(
    int X,
    int Y,
    int Width,
    int Height)
{
    public bool IsUsable => Width >= 1 && Height >= 1;
}

internal sealed class RdpHostProfile
{
    public string? NodeId { get; set; }
    public string Name { get; set; } = "RDP session";
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 3389;
    public string? Username { get; set; }
    public string? Domain { get; set; }
    public string? Password { get; set; }
    public string? GatewayHostname { get; set; }
    public string? GatewayUsername { get; set; }
    public string? GatewayPassword { get; set; }
    public string? ScreenSize { get; set; }
    public bool FullScreen { get; set; }
    public int ColorDepth { get; set; } = 32;
    public bool UseAllMonitors { get; set; }
    public int AudioMode { get; set; }
    public int AudioCaptureMode { get; set; }
    public int KeyboardHookMode { get; set; } = 2;
    public bool RedirectClipboard { get; set; } = true;
    public bool RedirectPrinters { get; set; }
    public bool RedirectSmartCards { get; set; }
    public bool RedirectPorts { get; set; }
    public bool RedirectDevices { get; set; }
    public string RedirectDrives { get; set; } = string.Empty;
    public int ConnectionSpeed { get; set; } = 7;
    public bool DesktopBackground { get; set; } = true;
    public bool FontSmoothing { get; set; } = true;
    public bool DesktopComposition { get; set; } = true;
    public bool WindowDrag { get; set; } = true;
    public bool MenuAnimation { get; set; } = true;
    public bool VisualStyles { get; set; } = true;
    public bool BitmapCaching { get; set; } = true;
    public bool AutoReconnect { get; set; } = true;
    public int ServerAuthentication { get; set; } = 2;
    public int GatewayUsageMethod { get; set; }
    public bool GatewayBypassLocal { get; set; } = true;
    public bool GatewayUseSameCreds { get; set; }
    public bool UseExternalClient { get; set; }

    public ConnectionProfile ToConnectionProfile()
    {
        var nodeId = Guid.TryParse(NodeId, out var parsedNodeId) ? parsedNodeId : Guid.NewGuid();
        return new ConnectionProfile
        {
            NodeId = nodeId,
            Name = string.IsNullOrWhiteSpace(Name) ? Host : Name,
            Protocol = ProtocolType.Rdp,
            Host = Host,
            Port = Port is >= 1 and <= 65535 ? Port : 3389,
            Username = string.IsNullOrWhiteSpace(Username) ? null : Username,
            RdpDomain = string.IsNullOrWhiteSpace(Domain) ? null : Domain,
            RdpScreenSize = ScreenSize,
            RdpFullScreen = FullScreen,
            RdpColorDepth = ColorDepth,
            RdpUseAllMonitors = UseAllMonitors,
            RdpAudioMode = AudioMode,
            RdpAudioCaptureMode = AudioCaptureMode,
            RdpKeyboardHookMode = KeyboardHookMode,
            RdpRedirectClipboard = RedirectClipboard,
            RdpRedirectPrinters = RedirectPrinters,
            RdpRedirectSmartCards = RedirectSmartCards,
            RdpRedirectPorts = RedirectPorts,
            RdpRedirectDevices = RedirectDevices,
            RdpRedirectDrives = RedirectDrives,
            RdpConnectionSpeed = ConnectionSpeed,
            RdpDesktopBackground = DesktopBackground,
            RdpFontSmoothing = FontSmoothing,
            RdpDesktopComposition = DesktopComposition,
            RdpWindowDrag = WindowDrag,
            RdpMenuAnimation = MenuAnimation,
            RdpVisualStyles = VisualStyles,
            RdpBitmapCaching = BitmapCaching,
            RdpAutoReconnect = AutoReconnect,
            RdpServerAuthentication = ServerAuthentication,
            RdpGatewayUsageMethod = GatewayUsageMethod,
            RdpGatewayHostname = GatewayHostname,
            RdpGatewayBypassLocal = GatewayBypassLocal,
            RdpGatewayUseSameCreds = GatewayUseSameCreds,
            RdpUseExternalClient = UseExternalClient,
        };
    }
}

internal sealed record RdpHostEvent(
    string Type,
    string RequestId = "",
    string? Message = null,
    int Code = 0,
    int Attempt = 0,
    int Max = 0);
