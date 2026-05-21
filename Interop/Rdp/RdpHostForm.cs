using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Threading;
using System.Windows.Forms;
using Microsoft.CSharp.RuntimeBinder;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;
using FormsForm = System.Windows.Forms.Form;

namespace Wormhole.Interop.Rdp;

/// <summary>
/// WinForms <see cref="FormsForm"/> hosting the <see cref="AxMsRdpClient9NotSafeForScripting"/>
/// ActiveX control. The form HWND is reparented onto the WinUI main window by
/// <c>RdpSessionService</c>; the ActiveX paints into it. The form must be created and
/// driven from the STA UI thread — see <see cref="EnsureStaThread"/>.
/// </summary>
internal sealed class RdpHostForm : FormsForm
{
    private static readonly Guid IMsTscAxEventsIid = new("336D5562-EFA8-482E-8CB3-C5C0FC7A7DB6");

    private readonly AxMsRdpClient9NotSafeForScripting _ax;
    private readonly MsTscAxEventsSink _sink;
    private readonly ILogger? _logger;
    private IConnectionPoint? _connectionPoint;
    private int _adviseCookie;
    private bool _connectStarted;

    public event Action? Connected;
    public event Action<int>? Disconnected;
    public event Action<int>? FatalError;
    public event Action<int>? LogonError;
    public event Action<int, int>? AutoReconnecting;
    public event Action<int, bool, int, int>? AutoReconnecting2;
    public event Action? AutoReconnected;

    public RdpHostForm(ILogger<RdpHostForm>? logger = null)
    {
        EnsureStaThread();

        _logger = logger;
        _sink = new MsTscAxEventsSink((handler, ex) =>
            _logger?.LogDebug(ex, "RDP event sink handler {Handler} threw.", handler));

        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        ShowInTaskbar = false;
        ControlBox = false;
        MinimizeBox = false;
        MaximizeBox = false;
        Text = "Wormhole RDP host";

        _ax = new AxMsRdpClient9NotSafeForScripting
        {
            Dock = DockStyle.Fill,
        };
        Controls.Add(_ax);
    }

    /// <summary>HWND of this form. Reading forces handle creation, which is what we want
    /// before SetParent — the ActiveX host needs a real Win32 window to paint into.</summary>
    public IntPtr Hwnd
    {
        get
        {
            if (!IsHandleCreated)
            {
                CreateControl();          // realises the AxHost child
                _ = Handle;               // forces this form's HWND
            }
            return Handle;
        }
    }

    /// <summary>
    /// Apply every setting from <paramref name="profile"/> to the ActiveX. Must be called
    /// after the OCX is materialised (<see cref="Hwnd"/> accessed) and before <see cref="Start"/>.
    /// All access is via <c>dynamic</c> against the OCX's IDispatch — we don't ship typed
    /// COM wrappers, but the property names and types match the published MsRdpClient API.
    /// </summary>
    public void Configure(
        ConnectionProfile profile,
        string? password,
        string? gatewayUsername = null,
        string? gatewayPassword = null)
    {
        EnsureStaThread();
        dynamic ocx = RequireOcx();

        // --- Core connection target ---
        ocx.Server = profile.Host;
        if (!string.IsNullOrEmpty(profile.Username)) ocx.UserName = profile.Username;
        if (!string.IsNullOrEmpty(profile.RdpDomain)) ocx.Domain = profile.RdpDomain;

        // --- Display ---
        var (dw, dh) = ResolveDesktopSize(profile.RdpScreenSize);
        ocx.DesktopWidth = dw;
        ocx.DesktopHeight = dh;
        ocx.ColorDepth = NormaliseColorDepth(profile.RdpColorDepth);
        // UseMultimon is exposed via IMsRdpClientNonScriptable5 — IDispatch lookup against
        // the OCX finds it directly. Older builds without the interface return E_NOTFOUND
        // which TrySetOptional swallows. Pair with mstsc-style "Use all my monitors" UX.
        TrySetOptional(() => ocx.UseMultimon = profile.RdpUseAllMonitors);

        // --- Advanced settings (port, audio, redirection, gateway, experience, auth) ---
        dynamic adv = ocx.AdvancedSettings9;
        adv.RDPPort = profile.Port;

        // mstsc-style: pass password through ClearTextPassword. The OCX consumes it during
        // Connect() and then we proactively clear it in Start() so the plaintext doesn't
        // linger in OCX-owned memory longer than necessary.
        if (!string.IsNullOrEmpty(password)) adv.ClearTextPassword = password;

        adv.RedirectClipboard = profile.RdpRedirectClipboard;
        adv.RedirectPrinters = profile.RdpRedirectPrinters;
        adv.RedirectSmartCards = profile.RdpRedirectSmartCards;
        adv.RedirectPorts = profile.RdpRedirectPorts;
        // RedirectDevices is the AdvSettings8 PnP toggle; older OCX builds may not expose it.
        TrySetOptional(() => adv.RedirectDevices = profile.RdpRedirectDevices);

        ApplyDriveRedirection(adv, profile.RdpRedirectDrives);

        adv.AudioRedirectionMode = profile.RdpAudioMode;
        // AudioCaptureRedirectionMode requires AdvSettings7+.
        TrySetOptional(() => adv.AudioCaptureRedirectionMode = profile.RdpAudioCaptureMode);
        adv.KeyboardHookMode = profile.RdpKeyboardHookMode;

        adv.PerformanceFlags = BuildPerformanceFlags(profile);
        // NetworkConnectionType requires AdvSettings6+.
        TrySetOptional(() => adv.NetworkConnectionType = (uint)profile.RdpConnectionSpeed);
        adv.EnableAutoReconnect = profile.RdpAutoReconnect;
        adv.AuthenticationLevel = (uint)profile.RdpServerAuthentication;

        // --- Gateway ---
        if (profile.RdpGatewayUsageMethod != 0)
        {
            try
            {
                dynamic transport = ocx.TransportSettings2;
                // "Bypass RD Gateway server for local addresses" maps mstsc's mode 3
                // (TSC_PROXY_MODE_DEFAULT — use default profile) → 4 (TSC_PROXY_MODE_NONE_DETECT
                // — use default profile but detect direct connection first). The other modes
                // encode bypass intrinsically: 0 = no gateway (irrelevant), 1 = always use (no
                // bypass), 2 = detect (already bypasses for direct-reachable). So we only
                // promote when the user chose "Use default" *and* checked bypass.
                var usageMethod = (uint)profile.RdpGatewayUsageMethod;
                if (profile.RdpGatewayUsageMethod == 3 && profile.RdpGatewayBypassLocal)
                {
                    usageMethod = 4;
                }
                transport.GatewayUsageMethod = usageMethod;
                if (!string.IsNullOrEmpty(profile.RdpGatewayHostname))
                    transport.GatewayHostname = profile.RdpGatewayHostname;
                // GatewayCredSharing: when set, the OCX reuses the main connection
                // credentials for the gateway instead of presenting a separate prompt — this
                // is the "Use my RD Gateway credentials for the remote computer" toggle in
                // the editor.
                TrySetOptional(() => transport.GatewayCredSharing = profile.RdpGatewayUseSameCreds ? 1u : 0u);
                // Apply the resolved gateway credentials when the user supplied them.
                if (!string.IsNullOrEmpty(gatewayUsername))
                {
                    var capturedUser = gatewayUsername;
                    TrySetOptional(() => transport.GatewayUsername = capturedUser);
                }
                if (!string.IsNullOrEmpty(gatewayPassword))
                {
                    var capturedPwd = gatewayPassword;
                    TrySetOptional(() => transport.GatewayPassword = capturedPwd);
                }
                // GatewayCredsSource intentionally left at its OCX default — the property
                // chooses between NTLM/SmartCard/Cookie auth, and forcing NTLM (=0) breaks
                // smart-card scenarios. Users who need explicit control can set
                // GatewayUsageMethod=3 (default RDG) and configure the gateway via mstsc.
            }
            catch (Exception ex) when (ex is COMException or RuntimeBinderException)
            {
                throw new InvalidOperationException(
                    "Could not apply RD Gateway settings (local mstscax build doesn't expose ITransportSettings2 — install a current Remote Desktop client).", ex);
            }
        }

        // Wire the events sink now so we don't miss an OnConnected that fires immediately
        // after Connect() returns.
        AttachEventsSink();
    }

    /// <summary>Initiate the RDP handshake. Configure must have been called first.</summary>
    public void Start()
    {
        EnsureStaThread();
        if (_connectStarted) return;
        _connectStarted = true;
        dynamic ocx = RequireOcx();
        ocx.Connect();
        // Clear the plaintext password from the OCX's settings now that Connect() has
        // consumed it for the authentication handshake. The OCX retains the value for
        // auto-reconnect, so this is a trade-off: we accept that auto-reconnect of a
        // dropped session can't replay the password (the user gets the failure overlay
        // and Retry button instead), in exchange for not leaving the plaintext sitting
        // in COM-owned memory across the connection's lifetime.
        try { ocx.AdvancedSettings9.ClearTextPassword = string.Empty; }
        catch (Exception ex) { _logger?.LogDebug(ex, "Post-Connect ClearTextPassword scrub failed (suppressed)."); }
    }

    /// <summary>Idempotent disconnect. Tolerates the OCX already being in a disconnected state.
    /// All-exception catch is intentional: teardown must not throw — a server-side termination
    /// can surface as a COMException (RPC), the OCX may not expose <c>Disconnect</c> on an older
    /// build (RuntimeBinderException), and racing with the OCX's own teardown can produce
    /// InvalidOperationException. None of those should propagate to the caller.</summary>
    public void Disconnect()
    {
        if (TryGetOcx() is not { } ocxObj) return;
        try
        {
            dynamic ocx = ocxObj;
            // Connected: 0 = disconnected, 1 = connected, 2 = connecting.
            int state = 0;
            try { state = (int)ocx.Connected; } catch (RuntimeBinderException) { } catch (COMException) { }
            if (state != 0) ocx.Disconnect();
        }
        catch (Exception ex)
        {
            // Best-effort teardown — log so a swallowed RPC/COM error doesn't vanish entirely.
            _logger?.LogDebug(ex, "RDP Disconnect threw during teardown (suppressed).");
        }
    }

    /// <summary>Translate the OCX's disconnect code into a human-readable string by
    /// asking the OCX itself (it ships with a description table).</summary>
    public string GetDisconnectDescription(int code, int extendedCode)
    {
        if (TryGetOcx() is not { } ocxObj)
            return $"Disconnect reason {code} (extended {extendedCode}).";
        try
        {
            dynamic ocx = ocxObj;
            return (string)ocx.GetErrorDescription((uint)code, (uint)extendedCode);
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException)
        {
            return $"Disconnect reason {code} (extended {extendedCode}).";
        }
    }

    private void AttachEventsSink()
    {
        if (_connectionPoint is not null) return;

        // IConnectionPointContainer is the dual interface every connectable ActiveX exposes.
        var cpc = (IConnectionPointContainer)RequireOcx();
        var iid = IMsTscAxEventsIid;
        cpc.FindConnectionPoint(ref iid, out _connectionPoint);
        if (_connectionPoint is null) return;

        // Hook each sink event before Advise so initial messages aren't lost. Only
        // OnLoginComplete (post-auth, shell up) maps to our Connected event — OnConnected
        // fires after the TLS handshake but before NLA/credential validation, so emitting
        // it would briefly flip the VM to Connected even when a logon error follows.
        _sink.LoginComplete += () => Connected?.Invoke();
        _sink.Disconnected += code => Disconnected?.Invoke(code);
        _sink.FatalError += code => FatalError?.Invoke(code);
        _sink.LogonError += code => LogonError?.Invoke(code);
        _sink.AutoReconnecting += (reason, attempt) => AutoReconnecting?.Invoke(reason, attempt);
        _sink.AutoReconnecting2 += (reason, available, attempt, max) =>
            AutoReconnecting2?.Invoke(reason, available, attempt, max);
        _sink.AutoReconnected += () => AutoReconnected?.Invoke();

        _connectionPoint.Advise(_sink, out _adviseCookie);
    }

    private void DetachEventsSink()
    {
        var cp = _connectionPoint;
        _connectionPoint = null;
        // Break the C# event chain on the sink first — the inline lambdas captured in
        // AttachEventsSink reference this form, so leaving them attached would root the form
        // (and the AxHost + OCX behind it) across teardown.
        _sink.ClearHandlers();
        if (cp is null) return;
        try
        {
            if (_adviseCookie != 0) cp.Unadvise(_adviseCookie);
        }
        catch (Exception ex)
        {
            // COM may have already torn down — log so a real leak isn't silent.
            _logger?.LogDebug(ex, "Unadvise failed during DetachEventsSink (suppressed).");
        }
        finally
        {
            _adviseCookie = 0;
            try { Marshal.ReleaseComObject(cp); }
            catch (Exception ex) { _logger?.LogDebug(ex, "ReleaseComObject on connection point threw (suppressed)."); }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { Disconnect(); }
            catch (Exception ex) { _logger?.LogDebug(ex, "Disconnect during Dispose threw (suppressed)."); }
            DetachEventsSink();
            try { _ax?.Dispose(); }
            catch (Exception ex) { _logger?.LogDebug(ex, "AxHost Dispose threw (suppressed)."); }
        }
        base.Dispose(disposing);
    }

    private static void EnsureStaThread()
    {
        if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
        {
            throw new InvalidOperationException(
                "RdpHostForm must be created and operated on an STA thread (the WinUI UI thread).");
        }
    }

    /// <summary>Strongly-typed accessor that throws when the OCX isn't realised yet
    /// (caller forgot to touch <see cref="Hwnd"/>). Centralises the null check that would
    /// otherwise repeat at every call site.</summary>
    private object RequireOcx() =>
        _ax.Ocx ?? throw new InvalidOperationException("RDP ActiveX not yet realised; access Hwnd first.");

    private object? TryGetOcx() => _ax.Ocx;

    /// <summary>
    /// Apply a setter that may not exist on an older OCX build. We catch only the two
    /// "property doesn't exist" exceptions (<see cref="RuntimeBinderException"/> from the
    /// dynamic binder, <see cref="COMException"/> with DISP_E_UNKNOWNNAME from IDispatch).
    /// Other exceptions — RPC failures, type mismatches — propagate so they aren't masked.
    /// </summary>
    private static void TrySetOptional(Action set)
    {
        const int DISP_E_UNKNOWNNAME = unchecked((int)0x80020006);
        const int DISP_E_MEMBERNOTFOUND = unchecked((int)0x80020003);
        try { set(); }
        catch (RuntimeBinderException) { }
        catch (COMException ex) when (ex.HResult == DISP_E_UNKNOWNNAME || ex.HResult == DISP_E_MEMBERNOTFOUND) { }
    }

    private static int NormaliseColorDepth(int requested) =>
        requested switch
        {
            15 => 16, // The OCX rounds 15 up to 16 internally; do it explicitly.
            16 => 16,
            24 => 24,
            32 => 32,
            _ => 32,
        };

    private static (int Width, int Height) ResolveDesktopSize(string? screenSize)
    {
        // Null / empty / "Full screen" → use the primary monitor work area (best mstsc-like default).
        if (string.IsNullOrWhiteSpace(screenSize) ||
            string.Equals(screenSize, RdpScreenSizes.FullScreenSentinel, StringComparison.OrdinalIgnoreCase))
        {
            var sb = Screen.PrimaryScreen?.WorkingArea ?? new System.Drawing.Rectangle(0, 0, 1920, 1080);
            return (Math.Max(640, sb.Width), Math.Max(480, sb.Height));
        }
        var parts = screenSize.Split('x', 'X');
        if (parts.Length == 2 &&
            int.TryParse(parts[0].Trim(), out var w) &&
            int.TryParse(parts[1].Trim(), out var h) &&
            w >= 640 && h >= 480)
        {
            return (w, h);
        }
        return (1280, 800);
    }

    /// <summary>
    /// PerformanceFlags is a bitmask of disable-this-feature bits. mstsc-style: setting a
    /// bit DISABLES the feature on the wire. The bit values are documented as TS_PERF_*
    /// constants on IMsRdpClientAdvancedSettings.
    /// </summary>
    private static uint BuildPerformanceFlags(ConnectionProfile p)
    {
        const uint TS_PERF_DISABLE_WALLPAPER = 0x01;
        const uint TS_PERF_DISABLE_FULLWINDOWDRAG = 0x02;
        const uint TS_PERF_DISABLE_MENUANIMATIONS = 0x04;
        const uint TS_PERF_DISABLE_THEMING = 0x08;
        const uint TS_PERF_DISABLE_CURSOR_SHADOW = 0x20;
        const uint TS_PERF_DISABLE_CURSORSETTINGS = 0x40;
        const uint TS_PERF_ENABLE_FONT_SMOOTHING = 0x80;
        const uint TS_PERF_ENABLE_DESKTOP_COMPOSITION = 0x100;

        uint flags = 0;
        if (!p.RdpDesktopBackground) flags |= TS_PERF_DISABLE_WALLPAPER;
        if (!p.RdpWindowDrag) flags |= TS_PERF_DISABLE_FULLWINDOWDRAG;
        if (!p.RdpMenuAnimation) flags |= TS_PERF_DISABLE_MENUANIMATIONS;
        if (!p.RdpVisualStyles) flags |= (TS_PERF_DISABLE_THEMING | TS_PERF_DISABLE_CURSOR_SHADOW | TS_PERF_DISABLE_CURSORSETTINGS);
        if (p.RdpFontSmoothing) flags |= TS_PERF_ENABLE_FONT_SMOOTHING;
        if (p.RdpDesktopComposition) flags |= TS_PERF_ENABLE_DESKTOP_COMPOSITION;
        return flags;
    }

    private static void ApplyDriveRedirection(dynamic adv, string raw)
    {
        // mstsc has two ways: "redirect all fixed drives" (bool) or per-letter via the
        // DriveCollection. RdpDriveList.ParseLetters returns null for the "all" sentinel,
        // empty set for "", or a populated set for an explicit letter list.
        var letters = RdpDriveList.ParseLetters(raw);
        if (letters is null) { adv.RedirectDrives = true; return; }
        if (letters.Count == 0) { adv.RedirectDrives = false; return; }

        try
        {
            dynamic drives = adv.DriveCollection;
            uint count = (uint)drives.DriveCount;
            for (uint i = 0; i < count; i++)
            {
                dynamic drive = drives.DriveByIndex[i];
                string name = (string)drive.DriveName; // e.g. "C:\\"
                var firstChar = !string.IsNullOrEmpty(name) ? char.ToUpperInvariant(name[0]) : '\0';
                drive.RedirectionState = letters.Contains(firstChar);
            }
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException)
        {
            // Older OCX exposes only the bool. Degrade to "no drives" rather than "all" —
            // the user opted into a specific letter list, so silently expanding to every
            // drive (including network/USB/removable) would be a least-privilege violation.
            adv.RedirectDrives = false;
        }
    }
}
