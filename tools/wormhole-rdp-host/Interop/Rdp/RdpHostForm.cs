using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Windows.Forms;
using Microsoft.CSharp.RuntimeBinder;
using Wormhole.Helpers;
using Wormhole.Models;
using FormsForm = System.Windows.Forms.Form;

namespace Wormhole.Interop.Rdp;

/// <summary>
/// WinForms <see cref="FormsForm"/> hosting the <see cref="AxMsRdpClient9NotSafeForScripting"/>
/// ActiveX control. The form is a top-level window owned by the Electron main window rather than
/// reparented into Chromium, which would composite the OCX behind the renderer surface. Electron
/// positions it in screen coordinates over the active tab. The form must be created and driven
/// from the STA UI thread — see <see cref="EnsureStaThread"/>.
/// </summary>
internal sealed class RdpHostForm : FormsForm
{
    private static readonly Guid IMsTscAxEventsIid = new("336D5562-EFA8-482E-8CB3-C5C0FC7A7DB6");

    private readonly AxMsRdpClient9NotSafeForScripting _ax;
    private readonly MsTscAxEventsSink _sink;
    private IConnectionPoint? _connectionPoint;
    private int _adviseCookie;
    private bool _connectStarted;
    private bool _hasAppliedHostBounds;
    private int _lastHostX;
    private int _lastHostY;
    private int _lastHostWidth;
    private int _lastHostHeight;

    public event Action? Connected;
    public event Action? LoginComplete;
    public event Action<int>? Disconnected;
    public event Action<int>? FatalError;
    public event Action<int>? LogonError;
    public event Action<int, bool, int, int>? AutoReconnecting2;
    public event Action? AutoReconnected;

    internal RdpHostForm(AxMsRdpClient9NotSafeForScripting.RdpActiveXClass activeXClass)
    {
        EnsureStaThread();

        _sink = new MsTscAxEventsSink();

        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        ShowInTaskbar = false;
        ControlBox = false;
        MinimizeBox = false;
        MaximizeBox = false;
        Text = "Wormhole RDP host";

        _ax = new AxMsRdpClient9NotSafeForScripting(activeXClass)
        {
            Dock = DockStyle.Fill,
        };
        Controls.Add(_ax);
    }

    /// <summary>HWND of this form. Reading forces handle creation, which is what we want
    /// before configuring/showing the overlay — the ActiveX host needs a real Win32 window to paint into.
    /// We also force the AxHost child's HWND explicitly: <see cref="Control.CreateControl()"/>
    /// short-circuits before creating any child handles when the parent Form is invisible
    /// (we never call <c>Show()</c> on this form), so without the explicit
    /// <c>_ = _ax.Handle</c> the AxHost's <c>OnHandleCreated</c> never runs, the OCX is
    /// never InPlaceActivate'd, and <see cref="RequireOcx"/> throws "not yet realised".</summary>
    internal IntPtr Hwnd
    {
        get
        {
            if (!IsHandleCreated)
            {
                _ = Handle;               // forces this form's HWND
            }
            if (!_ax.IsHandleCreated)
            {
                _ = _ax.Handle;           // forces AxHost child HWND → OnHandleCreated → OCX instantiated
            }
            return Handle;
        }
    }

    /// <summary>
    /// Position the owned top-level overlay (in screen coordinates). Size changes also force
    /// the AxHost child to fill the new client area; position-only moves avoid child layout
    /// and forced redraw so the overlay can track owner-window drags without repaint churn.
    /// Bounds updates preserve the current visibility unless <paramref name="reveal"/> is set.
    /// </summary>
    internal bool SetHostBounds(int x, int y, int width, int height, bool reveal = false)
    {
        EnsureStaThread();
        if (width < 1 || height < 1) return false;

        var hostHwnd = Hwnd;
        var sizeChanged = !_hasAppliedHostBounds ||
                          width != _lastHostWidth ||
                          height != _lastHostHeight;
        var positionChanged = !_hasAppliedHostBounds ||
                              x != _lastHostX ||
                              y != _lastHostY;
        if (!sizeChanged && !positionChanged)
        {
            return !reveal || EnsureVisibleAndRedraw();
        }

        var flags = RdpHostBoundsWindowPos.BuildFlags(sizeChanged, reveal);

        if (!Win32Interop.SetWindowPos(
                hostHwnd,
                sizeChanged ? Win32Interop.HWND_TOP : IntPtr.Zero,
                x,
                y,
                width,
                height,
                flags))
        {
            return false;
        }

        if (!sizeChanged)
        {
            RecordAppliedHostBounds(x, y, width, height);
            return true;
        }

        if (!_ax.IsHandleCreated) return false;
        var axHwnd = _ax.Handle;
        if (axHwnd == IntPtr.Zero) return false;

        try
        {
            _ax.SetBounds(0, 0, width, height);
        }
        catch
        {
            // Native MoveWindow below remains the authoritative sizing operation.
        }

        var childMoved = Win32Interop.MoveWindow(axHwnd, 0, 0, width, height, bRepaint: false);

        if (reveal)
        {
            if (!EnsureVisibleAndRedraw()) return false;
        }
        else
        {
            // Queue paint work instead of forcing RDW_UPDATENOW on every drag frame. Windows can
            // then collapse superseded invalidations while geometry remains current.
            RequestHostTreeRedraw(hostHwnd, immediate: false);
        }

        if (childMoved)
        {
            RecordAppliedHostBounds(x, y, width, height);
            return true;
        }

        return false;
    }

    private void RecordAppliedHostBounds(int x, int y, int width, int height)
    {
        _hasAppliedHostBounds = true;
        _lastHostX = x;
        _lastHostY = y;
        _lastHostWidth = width;
        _lastHostHeight = height;
    }

    /// <summary>
    /// Renegotiate the REMOTE desktop resolution to the given client pixel size via
    /// <c>IMsRdpClient9::UpdateSessionDisplaySettings</c> — the RDP Display Control channel
    /// (MS-RDPEDISP) that mstsc.exe uses for "dynamic resolution". This makes the remote OS
    /// actually re-lay-out at the new size (crisp, fills the tab) instead of relying on the
    /// client-side <c>SmartSizing</c> rescale of a fixed-resolution canvas.
    /// <para>
    /// Best-effort and never throws into the caller: returns <c>false</c> (changing nothing) when
    /// the OCX isn't realised yet, the session isn't established (the call is only valid once
    /// <c>Connected==1</c>), the mstscax build predates <c>IMsRdpClient9</c>, or the server/secure
    /// desktop doesn't support the Display Control channel (RDP &lt; 8.1). In every such case the
    /// existing SmartSizing scaling remains the active fill behaviour — a resize must not be able
    /// to fail the session. Callers MUST debounce this to the end of a resize gesture; it triggers
    /// a server-side display-mode change and is not meant to fire per layout tick.
    /// </para>
    /// </summary>
    internal bool TryUpdateRemoteResolution(int widthPx, int heightPx)
    {
        EnsureStaThread();
        if (widthPx < 1 || heightPx < 1) return false;
        if (TryGetOcx() is not { } ocxObj) return false;

        var (w, h) = RdpDesktopSizeResolver.ClampDynamicResolution(widthPx, heightPx);
        try
        {
            dynamic ocx = ocxObj;

            // Only valid on an established session; during the handshake the call throws or is
            // ignored. Connected: 0 = disconnected, 1 = connected, 2 = connecting.
            int state = 0;
            try { state = (int)ocx.Connected; }
            catch (RuntimeBinderException) { }
            catch (COMException) { }
            if (state != 1) return false;

            // Physical size omitted (0 ⇒ ignored per spec, so the server doesn't infer a DPI from
            // millimetres); no rotation; 100/100 scale factors — a guaranteed-valid pair we use to
            // request full resolution at no remote DPI scaling. Per MS-RDPEDISP DesktopScaleFactor
            // accepts 100..500 and DeviceScaleFactor {100,140,180}; a mismatched pair is silently
            // dropped by the server, so 100/100 is the safe choice. Width/height are already clamped
            // to 200..8192 with an even width by ClampDynamicResolution.
            ocx.UpdateSessionDisplaySettings((uint)w, (uint)h, 0u, 0u, 0u, 100u, 100u);
            return true;
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException or InvalidOperationException)
        {
            // Older mstscax without IMsRdpClient9 (RuntimeBinderException / DISP_E_*), a parameter
            // mismatch on a divergent build (DISP_E_BADPARAMCOUNT), or a server/secure-desktop that
            // doesn't support the Display Control VC (failure HRESULT). Keep SmartSizing scaling.
            return false;
        }
    }

    /// <summary>
    /// Apply every setting from <paramref name="profile"/> to the ActiveX. Must be called
    /// after the OCX is materialised (<see cref="Hwnd"/> accessed) and before <see cref="Start"/>.
    /// All access is via <c>dynamic</c> against the OCX's IDispatch — we don't ship typed
    /// COM wrappers, but the property names and types match the published MsRdpClient API.
    /// </summary>
    internal void Configure(
        RdpConnectionProfile profile,
        string? password,
        string? gatewayUsername = null,
        string? gatewayPassword = null,
        IntPtr ownerHwnd = default,
        int initialSurfaceWidth = 0,
        int initialSurfaceHeight = 0)
    {
        EnsureStaThread();
        dynamic ocx = RequireOcx();

        // --- Core connection target ---
        ocx.Server = profile.Host;
        if (!string.IsNullOrEmpty(profile.Username)) ocx.UserName = profile.Username;
        if (!string.IsNullOrEmpty(profile.RdpDomain)) ocx.Domain = profile.RdpDomain;

        // --- Display ---
        var (dw, dh) = ResolveDesktopSize(
            profile.RdpScreenSize,
            ownerHwnd,
            initialSurfaceWidth,
            initialSurfaceHeight);
        ocx.DesktopWidth = dw;
        ocx.DesktopHeight = dh;
        ocx.ColorDepth = NormaliseColorDepth(profile.RdpColorDepth);
        // Keep the whole remote logon surface visible inside the tab. Without this, a
        // monitor-sized/default desktop hosted in a smaller tab can show only the empty top-left
        // corner and look like a blank RDP canvas.
        TrySetOptional(() => ocx.AdvancedSettings9.SmartSizing = true);
        // UseMultimon is exposed via IMsRdpClientNonScriptable5 — IDispatch lookup against
        // the OCX finds it directly. Older builds without the interface return E_NOTFOUND
        // which TrySetOptional swallows. Pair with mstsc-style "Use all my monitors" UX.
        TrySetOptional(() => ocx.UseMultimon = profile.RdpUseAllMonitors);

        // --- Advanced settings (port, audio, redirection, gateway, experience, auth) ---
        // The properties below are documented on IMsRdpClientAdvancedSettings (the base) or its
        // numbered successors, but real mstscax IDispatch implementations don't all surface every
        // documented name — e.g. KeyboardHookMode disappeared on at least one current build and
        // the dynamic dispatcher throws RuntimeBinderException trying to set it. Anything that
        // isn't strictly required to make a connection happen (i.e. anything where falling back
        // to the OCX default is acceptable) is wrapped in TrySetOptional so a missing property
        // degrades gracefully instead of aborting Configure. Connection-critical setters
        // (RDPPort, ClearTextPassword) stay loud — if those fail something is very wrong and we
        // want the exception to surface.
        dynamic adv = ocx.AdvancedSettings9;
        adv.RDPPort = profile.Port;

        // NLA / CredSSP: mstsc.exe enables CredSSP by default; the embedded OCX
        // defaults it to VARIANT_FALSE, which makes any server configured for
        // "require NLA" (the default on modern Windows) terminate the session
        // with exDiscReasonNlaRequired (2825) — surfaced as the "Network Level
        // Authentication is not supported" overlay. Enabling it here restores
        // parity with mstsc. Kept loud (not TrySetOptional) for the same reason
        // as AuthenticationLevel below: the OCX default is the broken value, so
        // silently swallowing a missing-property error would just resurrect the
        // exact bug this line fixes with no diagnostic for the user. The
        // property lives on IMsRdpClientAdvancedSettings5 (RDP 5.1+) and is
        // effectively universal on any supported Windows mstscax build.
        adv.EnableCredSspSupport = true;

        // mstsc-style: pass password through ClearTextPassword. Connect() is asynchronous
        // and the OCX may still need the value after Start() returns, including for its own
        // reconnect flow, so do not mutate it after the handshake starts.
        if (!string.IsNullOrEmpty(password)) adv.ClearTextPassword = password;
        ApplyPromptSuppression(
            ocx,
            adv,
            hasPassword: !string.IsNullOrEmpty(password),
            ownerHwnd: ownerHwnd);

        TrySetOptional(() => adv.RedirectClipboard = profile.RdpRedirectClipboard);
        TrySetOptional(() => adv.RedirectPrinters = profile.RdpRedirectPrinters);
        TrySetOptional(() => adv.RedirectSmartCards = profile.RdpRedirectSmartCards);
        TrySetOptional(() => adv.RedirectPorts = profile.RdpRedirectPorts);
        // RedirectDevices is the AdvSettings8 PnP toggle; older OCX builds may not expose it.
        TrySetOptional(() => adv.RedirectDevices = profile.RdpRedirectDevices);

        ApplyDriveRedirection(ocx, profile.RdpRedirectDrives);

        TrySetOptional(() => adv.AudioRedirectionMode = profile.RdpAudioMode);
        // AudioCaptureRedirectionMode requires AdvSettings7+.
        TrySetOptional(() => adv.AudioCaptureRedirectionMode = profile.RdpAudioCaptureMode);
        // KeyboardHookMode is documented on IMsRdpClientAdvancedSettings (the base) but the
        // mstscax shipping in this environment doesn't surface it via IDispatch — fall back to
        // the OCX default (2 = FullScreenOnly) when the binder can't resolve the name.
        TrySetOptional(() => adv.KeyboardHookMode = profile.RdpKeyboardHookMode);

        TrySetOptional(() => adv.PerformanceFlags = BuildPerformanceFlags(profile));
        // Persistent bitmap cache. The property name landed on IMsRdpClientAdvancedSettings5
        // as BitmapCachePersistEnable; older OCX builds expose a typo-laden BitmapPeristence
        // (with a single 'r') as a fallback. Try the modern name first, then the legacy.
        TrySetOptional(() => adv.BitmapCachePersistEnable = profile.RdpBitmapCaching);
        TrySetOptional(() => adv.BitmapPeristence = profile.RdpBitmapCaching ? 1 : 0);
        // NetworkConnectionType requires AdvSettings6+.
        TrySetOptional(() => adv.NetworkConnectionType = (uint)profile.RdpConnectionSpeed);
        TrySetOptional(() => adv.EnableAutoReconnect = profile.RdpAutoReconnect);
        // AuthenticationLevel stays loud (not TrySetOptional) — it controls server-cert
        // validation enforcement (0=No server authentication, 1=Require, 2=Warn/prompt).
        // The OCX default is the weakest value (0), so swallowing a setter failure would
        // silently downgrade users who chose Require or Warn. The property is on
        // IMsRdpClientAdvancedSettings4+ and is effectively universal; if it ever does fail,
        // the user should see the error and update their Remote Desktop client.
        adv.AuthenticationLevel = (uint)profile.RdpServerAuthentication;

        // --- Gateway ---
        if (profile.RdpGatewayUsageMethod != 0)
        {
            try
            {
                dynamic transport = ocx.TransportSettings2;
                // Pass the user-picked GatewayUsageMethod through verbatim. An earlier
                // revision promoted (mode 3 + bypass-local) to mode 4, but per the OCX docs
                // for IMsRdpClientTransportSettings::GatewayUsageMethod, value 4
                // (TSC_PROXY_MODE_NONE_DETECT) actually means "Do not use an RD Gateway
                // server, but detect server settings" — i.e. it disables the gateway
                // entirely. That mapping silently lost gateway routing for users who picked
                // "Use default" with bypass-local. The "Bypass RD Gateway for local
                // addresses" toggle has no direct OCX equivalent (it's a .rdp file format
                // hint that mstsc interprets via mode selection at write time); we persist
                // the field for round-trip with future .rdp import/export but it does not
                // affect the COM-surface connection today.
                transport.GatewayUsageMethod = (uint)profile.RdpGatewayUsageMethod;
                if (!string.IsNullOrEmpty(profile.RdpGatewayHostname))
                    transport.GatewayHostname = profile.RdpGatewayHostname;
                // GatewayCredSharing: when set, the OCX reuses the main connection
                // credentials for the gateway instead of presenting a separate prompt — this
                // is the "Use my RD Gateway credentials for the remote computer" toggle in
                // the editor.
                //
                // Per the IMsRdpClientTransportSettings2 docs, credential sharing and the
                // explicit GatewayUsername/GatewayPassword properties are MUTUALLY EXCLUSIVE:
                // the docs explicitly state that sharing does not support password sharing
                // via GatewayPassword/ClearTextPassword. Setting both can fall back to
                // prompts or fail authentication unexpectedly, so we apply explicit gateway
                // credentials only when sharing is off.
                TrySetOptional(() => transport.GatewayCredSharing = profile.RdpGatewayUseSameCreds ? 1u : 0u);
                if (!profile.RdpGatewayUseSameCreds)
                {
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

    internal bool EnsureVisibleAndRedraw()
    {
        EnsureStaThread();
        var hostHwnd = Hwnd;
        var hostVisible = ForceVisibleTop(hostHwnd);
        var axVisible = true;
        if (_ax.IsHandleCreated)
        {
            axVisible = ForceVisibleTop(_ax.Handle);
        }

        RequestHostTreeRedraw(hostHwnd);

        return hostVisible && axVisible;
    }

    private static void RequestHostTreeRedraw(IntPtr hostHwnd, bool immediate = true)
    {
        // RDW_ALLCHILDREN recursively includes the AxHost HWND. One host-tree invalidation avoids
        // scheduling the same ActiveX repaint a second time through an explicit child call.
        RequestRedraw(hostHwnd, immediate);
    }

    /// <summary>Initiate the RDP handshake. Configure must have been called first.</summary>
    internal void Start()
    {
        EnsureStaThread();
        if (_connectStarted) return;
        _connectStarted = true;
        dynamic ocx = RequireOcx();
        ocx.Connect();
    }

    /// <summary>
    /// Push Win32 keyboard focus into the embedded ActiveX child HWND so the first
    /// keystroke after a fresh connect lands on the remote logon screen instead of
    /// the Electron renderer. Idempotent. Must run on the STA UI thread (same as
    /// every other API on this form). No-ops when the form or the AxHost child
    /// hasn't been realised yet — that path is reachable during a teardown race
    /// between the OCX firing OnLoginComplete and the controller closing the session.
    /// SetFocus targets <c>_ax.Handle</c> rather than the form's HWND because the
    /// OCX paints into the AxHost child and Win32 focus is HWND-specific (Z-order
    /// alone doesn't redirect keyboard input).
    /// </summary>
    internal void RequestFocus()
    {
        // EnsureStaThread is intentionally OUTSIDE the try below. STA violations are
        // programming errors that should surface loudly via the InvalidOperationException
        // throw, not be silently swallowed.
        EnsureStaThread();
        if (!IsHandleCreated || !_ax.IsHandleCreated) return;
        try
        {
            // Capture the handle FIRST so a teardown race between IsHandleCreated and
            // SetFocus can't slip SetFocus(NULL) through — SetFocus(NULL) is a valid
            // Win32 call that DETACHES keyboard focus from the calling thread, breaking
            // input until something else takes focus.
            var hwnd = _ax.Handle;
            if (hwnd == IntPtr.Zero) return;

            _ = Win32Interop.SetFocus(hwnd);
        }
        catch
        {
            // The native SetFocus call itself doesn't throw. The managed wrappers around
            // _ax.Handle (ObjectDisposedException, COMException from teardown) can —
            // swallow so a teardown race doesn't poison the OCX event handler whose
            // continuation requested focus. NOTE: this catch does NOT cover the
            // EnsureStaThread() at the top of the method — that's intentionally loud.
        }
    }

    /// <summary>Idempotent disconnect. Tolerates the OCX already being in a disconnected state.
    /// All-exception catch is intentional: teardown must not throw — a server-side termination
    /// can surface as a COMException (RPC), the OCX may not expose <c>Disconnect</c> on an older
    /// build (RuntimeBinderException), and racing with the OCX's own teardown can produce
    /// InvalidOperationException. None of those should propagate to the caller.</summary>
    internal void Disconnect()
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
        catch
        {
            // Best-effort teardown; the helper process is the final containment boundary.
        }
    }
    /// <summary>Read the OCX's <c>ExtendedDisconnectReason</c> and translate the pair into
    /// a human-readable string in one pass. Per the IMsTscAxEvents::OnDisconnected guidance
    /// the extended reason is what gives the catch-all <c>disconnectReasonNoInfo</c> bucket
    /// any actionable server-side context. Returns <c>(0, fallback)</c> if the OCX is gone
    /// or doesn't expose the properties.</summary>
    internal (int Extended, string Description) GetDisconnectInfo(int code)
    {
        var fallback = $"Disconnect reason {code}.";
        if (TryGetOcx() is not { } ocxObj) return (0, fallback);
        try
        {
            dynamic ocx = ocxObj;
            int extended = (int)ocx.ExtendedDisconnectReason;
            string desc = (string)ocx.GetErrorDescription((uint)code, (uint)extended);
            return (extended, desc);
        }
        catch (Exception ex) when (
            ex is COMException or RuntimeBinderException or InvalidCastException or InvalidOperationException or ObjectDisposedException)
        {
            return (0, fallback);
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

        // Hook each sink event before Advise so initial messages aren't lost. OnConnected
        // means the native control has established server transport and can own the canvas;
        // OnLoginComplete is a distinct post-authentication milestone.
        _sink.Connected += () => Connected?.Invoke();
        _sink.LoginComplete += () => LoginComplete?.Invoke();
        _sink.Disconnected += code => Disconnected?.Invoke(code);
        _sink.FatalError += code => FatalError?.Invoke(code);
        _sink.LogonError += code => LogonError?.Invoke(code);
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
        catch
        {
            // COM may already have torn down the connection point.
        }
        finally
        {
            _adviseCookie = 0;
            try { Marshal.ReleaseComObject(cp); }
            catch { /* Best-effort COM teardown. */ }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Deliberately do NOT call Disconnect() here — the OCX's polite MCS
            // termination blocks the UI/STA thread on a server ack, and disposal
            // is on the user-facing reconnect / tab-close path. AxHost.Dispose
            // tears down the OCX via COM teardown; the server detects the drop
            // via the resulting socket close. Callers that genuinely need an
            // orderly protocol shutdown can still call Disconnect() explicitly
            // before Dispose.
            DetachEventsSink();
            try { _ax?.Dispose(); }
            catch { /* Best-effort ActiveX teardown. */ }
        }
        base.Dispose(disposing);
    }

    private static void EnsureStaThread()
    {
        if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
        {
            throw new InvalidOperationException(
                "RdpHostForm must be created and operated on its STA UI thread.");
        }
    }

    /// <summary>Strongly-typed accessor that throws when the OCX isn't realised yet
    /// (caller forgot to touch <see cref="Hwnd"/>). Centralises the null check that would
    /// otherwise repeat at every call site.</summary>
    private object RequireOcx() =>
        _ax.Ocx ?? throw new InvalidOperationException("RDP ActiveX not yet realised; access Hwnd first.");

    private object? TryGetOcx() => _ax.Ocx;

    private static void RequestRedraw(IntPtr hwnd, bool immediate)
    {
        var flags = Win32Interop.RDW_INVALIDATE | Win32Interop.RDW_ALLCHILDREN;
        if (immediate) flags |= Win32Interop.RDW_UPDATENOW;
        _ = Win32Interop.RedrawWindow(hwnd, IntPtr.Zero, IntPtr.Zero, flags);
    }

    private static bool ForceVisibleTop(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return false;
        return Win32Interop.SetWindowPos(
            hwnd,
            Win32Interop.HWND_TOP,
            0,
            0,
            0,
            0,
            Win32Interop.SWP_NOMOVE |
            Win32Interop.SWP_NOSIZE |
            Win32Interop.SWP_NOACTIVATE |
            Win32Interop.SWP_SHOWWINDOW);
    }

    private static void ApplyPromptSuppression(dynamic ocx, dynamic adv, bool hasPassword, IntPtr ownerHwnd)
    {
        if (ownerHwnd != IntPtr.Zero)
        {
            // UIParentWindowHandle belongs to IMsRdpClientNonScriptable2, surfaced by the OCX
            // itself rather than AdvancedSettings. Setting it on adv is silently unsupported on
            // current mstscax builds and leaves certificate/authentication dialogs unparented.
            TrySetOptionalCredential(() => ocx.UIParentWindowHandle = ownerHwnd.ToInt64());
        }

        if (!hasPassword) return;

        TrySetOptionalCredential(() => ocx.PromptForCredsOnClient = false);
        TrySetOptionalCredential(() => ocx.AllowPromptingForCredentials = false);
        TrySetOptionalCredential(() => adv.PromptForCredentials = false);
    }

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

    private static void TrySetOptionalCredential(Action set)
    {
        const int DISP_E_UNKNOWNNAME = unchecked((int)0x80020006);
        const int DISP_E_MEMBERNOTFOUND = unchecked((int)0x80020003);
        const int DISP_E_TYPEMISMATCH = unchecked((int)0x80020005);
        try
        {
            set();
        }
        catch (RuntimeBinderException) { }
        catch (COMException ex) when (
            ex.HResult == DISP_E_UNKNOWNNAME ||
            ex.HResult == DISP_E_MEMBERNOTFOUND ||
            ex.HResult == DISP_E_TYPEMISMATCH)
        { }
        catch (ArgumentException) { }
        catch { /* Credential prompt suppression is best-effort across OCX versions. */ }
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

    private static (int Width, int Height) ResolveDesktopSize(
        string? screenSize,
        IntPtr ownerHwnd,
        int initialSurfaceWidth,
        int initialSurfaceHeight)
    {
        // Null / empty / "Full connection content" means "fill the embedded tab" in Wormhole.
        // Older saved "Full screen" rows and mRemoteNG "FitToWindow" imports are aliases for the
        // same dynamic mode. Using the whole owner monitor here makes the remote Windows logon UI
        // center itself outside the visible tab surface, which reads as a blank canvas even though
        // the RDP transport has connected. Fall back to the owner monitor only during very early
        // layout races where the surface has not measured at all. If the surface is only the 1x1
        // seed used during retry/initial load, clamp to the RDP minimum rather than falling back
        // to a full monitor-sized desktop.
        if (RdpScreenSizes.IsFullConnectionContent(screenSize))
        {
            Screen? screen = null;
            if (ownerHwnd != IntPtr.Zero)
            {
                // Screen.FromHandle wraps MonitorFromWindow; on an invalid HWND it returns
                // PrimaryScreen rather than throwing, but a concurrent display reconfig has
                // been observed to raise Win32Exception. Narrow the catch accordingly.
                try { screen = Screen.FromHandle(ownerHwnd); }
                catch (System.ComponentModel.Win32Exception) { }
                catch (ArgumentException) { }
            }
            var sb = (screen ?? Screen.PrimaryScreen)?.WorkingArea
                  ?? new System.Drawing.Rectangle(0, 0, 1920, 1080);
            return RdpDesktopSizeResolver.Resolve(
                screenSize,
                initialSurfaceWidth,
                initialSurfaceHeight,
                sb.Width,
                sb.Height);
        }

        return RdpDesktopSizeResolver.Resolve(
            screenSize,
            initialSurfaceWidth,
            initialSurfaceHeight,
            fallbackWidth: 1920,
            fallbackHeight: 1080);
    }

    /// <summary>
    /// PerformanceFlags is a bitmask of disable-this-feature bits. mstsc-style: setting a
    /// bit DISABLES the feature on the wire. The bit values are documented as TS_PERF_*
    /// constants on IMsRdpClientAdvancedSettings.
    /// </summary>
    private static uint BuildPerformanceFlags(RdpConnectionProfile p)
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

    private static void ApplyDriveRedirection(dynamic ocx, string raw)
    {
        // AdvancedSettings.RedirectDrives is the master enable; DriveCollection (off the
        // OCX root, via IMsRdpClientNonScriptable3) provides the per-drive RedirectionState
        // filter that only takes effect when the master is true. ParseLetters returns null
        // for "all", empty set for "none", or a populated set for an explicit letter list.
        dynamic adv = ocx.AdvancedSettings9;
        var letters = RdpDriveList.ParseLetters(raw);
        if (letters is null) { adv.RedirectDrives = true; return; }
        if (letters.Count == 0) { adv.RedirectDrives = false; return; }

        // Custom letters: the master must be true for the per-drive filter to take effect
        // at all. Set it before walking the collection so a mid-iteration COM failure still
        // leaves the user with redirection on for whatever the OCX already accepted.
        adv.RedirectDrives = true;
        try
        {
            dynamic drives = ocx.DriveCollection;
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
