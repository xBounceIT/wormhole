using System.Text.Json;
using System.Text.Json.Serialization;
using Wormhole.Helpers;
using Wormhole.Interop.Rdp;
using Wormhole.Models;
using FormsTimer = System.Windows.Forms.Timer;

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
    private const int ResolutionDebounceMs = 100;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly object _outputLock = new();
    private readonly object _resizeLock = new();
    private readonly Control _dispatcher;
    private readonly List<string> _pendingResizeRequestIds = [];
    private RdpHostForm? _form;
    private RdpHostCommand? _pendingResize;
    private bool _resizeDispatchScheduled;
    private FormsTimer? _resolutionTimer;
    private bool _dynamicResolution;
    private int _pendingResolutionWidth;
    private int _pendingResolutionHeight;
    private int _lastResolutionWidth;
    private int _lastResolutionHeight;
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

                if (command.Op == "resize")
                {
                    QueueResize(command);
                    continue;
                }

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
                    ApplyResize(command);
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
                    CloseHost();
                    // The Go supervisor treats this acknowledgement as the deterministic cleanup
                    // boundary. Publish it only after the ActiveX control and HWND are disposed.
                    Write(new RdpHostEvent("ack", command.RequestId));
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

    private void QueueResize(RdpHostCommand command)
    {
        var schedule = false;
        lock (_resizeLock)
        {
            _pendingResize = command;
            _pendingResizeRequestIds.Add(command.RequestId);
            if (!_resizeDispatchScheduled)
            {
                _resizeDispatchScheduled = true;
                schedule = true;
            }
        }
        if (schedule) TryBeginInvoke(FlushPendingResize);
    }

    private void FlushPendingResize()
    {
        RdpHostCommand? command;
        string[] requestIds;
        lock (_resizeLock)
        {
            command = _pendingResize;
            requestIds = [.. _pendingResizeRequestIds];
            _pendingResize = null;
            _pendingResizeRequestIds.Clear();
            _resizeDispatchScheduled = false;
        }
        if (command is null) return;

        try
        {
            ApplyResize(command);
            WriteBatch(requestIds.Select(requestId => new RdpHostEvent("ack", requestId)));
        }
        catch (Exception)
        {
            WriteBatch(requestIds.Select(requestId =>
                new RdpHostEvent("error", requestId, "native Windows RDP host operation failed")));
        }
    }

    private void ApplyResize(RdpHostCommand command)
    {
        if (_form is null || !command.Bounds.IsUsable) return;
        if (!_form.SetHostBounds(
                command.Bounds.X,
                command.Bounds.Y,
                command.Bounds.Width,
                command.Bounds.Height))
        {
            throw new InvalidOperationException("native RDP surface resize failed");
        }
        ScheduleRemoteResolution(command.Bounds.Width, command.Bounds.Height);
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
        void Reveal(bool focus = false)
        {
            connectionVisible = true;
            try
            {
                _ = Win32Interop.ShowWindow(form.Hwnd, Win32Interop.SW_SHOWNA);
                _ = form.EnsureVisibleAndRedraw();
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
            Reveal(focus: true);
            ScheduleRemoteResolution(_pendingResolutionWidth, _pendingResolutionHeight);
            Write(new RdpHostEvent("connected"));
        };
        form.LoginComplete += () =>
        {
            Reveal(focus: true);
            ScheduleRemoteResolution(_pendingResolutionWidth, _pendingResolutionHeight);
            Write(new RdpHostEvent("loginComplete"));
        };
        form.Disconnected += code =>
        {
            Conceal();
            var info = form.GetDisconnectInfo(code);
            Write(new RdpHostEvent("disconnected", Code: code, Message: info.Description));
            // Dispose the ActiveX host after a terminal disconnect so a later retry can create a
            // fresh OCX instead of hitting Start()'s one-shot guard on a dead control. Auto-reconnect
            // events arrive before this terminal notification and keep the form alive while the OCX
            // is recovering.
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
            Reveal();
            Write(new RdpHostEvent("autoReconnected"));
        };

        var hwnd = form.Hwnd;
        ConfigureAsOwnedOverlay(hwnd, owner);
        var profile = command.Profile.ToRdpConnectionProfile();
        _dynamicResolution =
            !profile.RdpFullScreen && RdpScreenSizes.IsFullConnectionContent(profile.RdpScreenSize);
        // Establish the real connection rectangle while the host is still hidden. Native ActiveX
        // dialogs use this HWND as their UI parent, so the certificate prompt centers over the
        // connection surface instead of the whole Electron window or the 1x1 startup seed.
        if (!form.SetHostBounds(
                command.Bounds.X,
                command.Bounds.Y,
                command.Bounds.Width,
                command.Bounds.Height))
        {
            throw new InvalidOperationException("native RDP surface positioning failed");
        }
        form.Configure(
            profile,
            command.Profile.Password,
            command.Profile.GatewayUsername,
            command.Profile.GatewayPassword,
            hwnd,
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

        // Start only after every event subscription and the owned Electron overlay relationship
        // are in place, otherwise an early native event can be lost.
        ScheduleRemoteResolution(command.Bounds.Width, command.Bounds.Height);
        form.Start();
        if (!_closing && !connectionVisible) Conceal();
        if (!_closing) Write(new RdpHostEvent("ready", command.RequestId));
    }

    private void ScheduleRemoteResolution(int width, int height)
    {
        if (!_dynamicResolution || _form is null || width < 1 || height < 1) return;
        if (width == _lastResolutionWidth && height == _lastResolutionHeight) return;
        if (_resolutionTimer is { Enabled: true } &&
            width == _pendingResolutionWidth &&
            height == _pendingResolutionHeight)
        {
            return;
        }
        _pendingResolutionWidth = width;
        _pendingResolutionHeight = height;
        if (_resolutionTimer is null)
        {
            _resolutionTimer = new FormsTimer { Interval = ResolutionDebounceMs };
            _resolutionTimer.Tick += (_, _) => ApplyRemoteResolution();
        }
        _resolutionTimer.Stop();
        _resolutionTimer.Start();
    }

    private void ApplyRemoteResolution()
    {
        _resolutionTimer?.Stop();
        var form = _form;
        if (form is null) return;
        if (_pendingResolutionWidth == _lastResolutionWidth &&
            _pendingResolutionHeight == _lastResolutionHeight)
        {
            return;
        }
        if (!form.TryUpdateRemoteResolution(_pendingResolutionWidth, _pendingResolutionHeight)) return;
        _lastResolutionWidth = _pendingResolutionWidth;
        _lastResolutionHeight = _pendingResolutionHeight;
    }

    private static RdpHostForm CreateRealizedHostForm()
    {
        // Try the newest registered mstscax class, fall back through older registrations, and
        // force both HWNDs before Configure. Some
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
            _resolutionTimer?.Stop();
            _resolutionTimer?.Dispose();
            _resolutionTimer = null;
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
        WriteBatch([response]);
    }

    private void WriteBatch(IEnumerable<RdpHostEvent> responses)
    {
        lock (_outputLock)
        {
            try
            {
                foreach (var response in responses)
                {
                    Console.Out.WriteLine(JsonSerializer.Serialize(response, JsonOptions));
                }
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
    public bool GatewayUseSameCreds { get; set; }

    public RdpConnectionProfile ToRdpConnectionProfile()
    {
        return new RdpConnectionProfile
        {
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
            RdpGatewayUseSameCreds = GatewayUseSameCreds,
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
