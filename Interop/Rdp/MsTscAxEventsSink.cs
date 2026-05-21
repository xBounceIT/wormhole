using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace Wormhole.Interop.Rdp;

/// <summary>
/// COM dispinterface used as the event sink for <c>IMsTscAxEvents</c> on the
/// MsRdpClient9NotSafeForScripting control. IID matches the dispinterface published by
/// mstscax.dll. Method order and DISPIDs follow the public MSDN reference.
/// </summary>
[ComVisible(true)]
[Guid("336D5562-EFA8-482E-8CB3-C5C0FC7A7DB6")]
[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
public interface IMsTscAxEvents
{
    [DispId(1)] void OnConnecting();
    [DispId(2)] void OnConnected();
    [DispId(3)] void OnLoginComplete();
    [DispId(4)] void OnDisconnected(int discReason);
    [DispId(5)] void OnEnterFullScreenMode();
    [DispId(6)] void OnLeaveFullScreenMode();
    [DispId(7)] void OnChannelReceivedData(string chanName, string data);
    [DispId(8)] void OnRequestGoFullScreen();
    [DispId(9)] void OnRequestLeaveFullScreen();
    [DispId(10)] void OnFatalError(int errorCode);
    [DispId(11)] void OnWarning(int warningCode);
    [DispId(12)] void OnRemoteDesktopSizeChange(int width, int height);
    [DispId(13)] void OnIdleTimeoutNotification();
    [DispId(14)] void OnRequestContainerMinimize();
    [DispId(15)] void OnConfirmClose(out bool fAllowClose);
    [DispId(16)] void OnReceivedTSPublicKey(string publicKey, out bool fContinueLogon);
    [DispId(17)] void OnAutoReconnecting(int disconnectReason, int attemptCount, out int arcContinueStatus);
    [DispId(18)] void OnAuthenticationWarningDisplayed();
    [DispId(19)] void OnAuthenticationWarningDismissed();
    [DispId(20)] void OnRemoteProgramResult(string remoteProgramName, int execResult, int rawResult);
    [DispId(21)] void OnRemoteProgramDisplayed(bool displayed, uint exStyle);
    [DispId(22)] void OnRemoteWindowDisplayed(bool displayed, IntPtr hwnd, int remoteWindowDisplayedAttribute);
    [DispId(23)] void OnLogonError(int lError);
    [DispId(24)] void OnFocusReleased(int iDirection);
    [DispId(25)] void OnUserNameAcquired(string newUserName);
    [DispId(26)] void OnMouseInputModeChanged(bool fMouseModeRelative);
    [DispId(27)] void OnServiceMessageReceived(string serviceMessage);
    [DispId(28)] void OnConnectionBarPullDown();
    [DispId(29)] void OnNetworkStatusChanged(uint qualityFlags, int bandwidth, int rtt);
    [DispId(30)] void OnDevicesButtonPressed();
    [DispId(31)] void OnAutoReconnected();
    [DispId(32)] void OnAutoReconnecting2(int disconnectReason, bool networkAvailable, int attemptCount, int maxAttemptCount);
}

/// <summary>
/// Concrete managed sink. We pass an instance of this into IConnectionPoint.Advise; the OCX
/// then dispatches event methods to it. Each method forwards to a corresponding C# event
/// that <see cref="RdpHostForm"/> subscribes to. Errors swallowed (logged at host level) so a
/// buggy callback doesn't break the OCX's event pump.
/// </summary>
[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
[Guid("4A77F7F2-AD7C-4B30-BD53-9C9C00B61F86")]
public sealed class MsTscAxEventsSink : IMsTscAxEvents
{
    public event Action? Connecting;
    public event Action? Connected;
    public event Action? LoginComplete;
    public event Action<int>? Disconnected;
    public event Action<int>? FatalError;
    public event Action<int>? LogonError;
    public event Action<int, bool, int, int>? AutoReconnecting2;
    public event Action<int, int>? AutoReconnecting;
    public event Action? AutoReconnected;

    public void OnConnecting() { try { Connecting?.Invoke(); } catch { } }
    public void OnConnected() { try { Connected?.Invoke(); } catch { } }
    public void OnLoginComplete() { try { LoginComplete?.Invoke(); } catch { } }
    public void OnDisconnected(int discReason) { try { Disconnected?.Invoke(discReason); } catch { } }
    public void OnEnterFullScreenMode() { }
    public void OnLeaveFullScreenMode() { }
    public void OnChannelReceivedData(string chanName, string data) { }
    public void OnRequestGoFullScreen() { }
    public void OnRequestLeaveFullScreen() { }
    public void OnFatalError(int errorCode) { try { FatalError?.Invoke(errorCode); } catch { } }
    public void OnWarning(int warningCode) { }
    public void OnRemoteDesktopSizeChange(int width, int height) { }
    public void OnIdleTimeoutNotification() { }
    public void OnRequestContainerMinimize() { }
    public void OnConfirmClose(out bool fAllowClose) { fAllowClose = true; }
    public void OnReceivedTSPublicKey(string publicKey, out bool fContinueLogon) { fContinueLogon = true; }
    public void OnAutoReconnecting(int disconnectReason, int attemptCount, out int arcContinueStatus)
    {
        arcContinueStatus = 0; // 0 = continueReconnecting per IMsRdpClientAdvancedSettings.EnableAutoReconnect docs
        try { AutoReconnecting?.Invoke(disconnectReason, attemptCount); } catch { }
    }
    public void OnAuthenticationWarningDisplayed() { }
    public void OnAuthenticationWarningDismissed() { }
    public void OnRemoteProgramResult(string remoteProgramName, int execResult, int rawResult) { }
    public void OnRemoteProgramDisplayed(bool displayed, uint exStyle) { }
    public void OnRemoteWindowDisplayed(bool displayed, IntPtr hwnd, int remoteWindowDisplayedAttribute) { }
    public void OnLogonError(int lError) { try { LogonError?.Invoke(lError); } catch { } }
    public void OnFocusReleased(int iDirection) { }
    public void OnUserNameAcquired(string newUserName) { }
    public void OnMouseInputModeChanged(bool fMouseModeRelative) { }
    public void OnServiceMessageReceived(string serviceMessage) { }
    public void OnConnectionBarPullDown() { }
    public void OnNetworkStatusChanged(uint qualityFlags, int bandwidth, int rtt) { }
    public void OnDevicesButtonPressed() { }
    public void OnAutoReconnected() { try { AutoReconnected?.Invoke(); } catch { } }
    public void OnAutoReconnecting2(int disconnectReason, bool networkAvailable, int attemptCount, int maxAttemptCount)
    {
        try { AutoReconnecting2?.Invoke(disconnectReason, networkAvailable, attemptCount, maxAttemptCount); } catch { }
    }

    /// <summary>
    /// Release all managed event subscribers. Called by <see cref="RdpHostForm.DetachEventsSink"/>
    /// before <see cref="System.Runtime.InteropServices.Marshal.ReleaseComObject"/> on the
    /// connection point — without it, the inline lambdas that <c>AttachEventsSink</c> hooked
    /// keep the sink (and through it, the host form) rooted across connect cycles, leaking
    /// the form on every Retry / tab close-then-reopen.
    /// </summary>
    [ComVisible(false)]
    internal void ClearHandlers()
    {
        Connecting = null;
        Connected = null;
        LoginComplete = null;
        Disconnected = null;
        FatalError = null;
        LogonError = null;
        AutoReconnecting2 = null;
        AutoReconnecting = null;
        AutoReconnected = null;
    }
}
