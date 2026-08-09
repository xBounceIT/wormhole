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
    [DispId(21)] void OnRemoteWindowDisplayed(bool displayed, IntPtr hwnd, int remoteWindowDisplayedAttribute);
    [DispId(22)] void OnLogonError(int lError);
    [DispId(23)] void OnFocusReleased(int iDirection);
    [DispId(24)] void OnUserNameAcquired(string newUserName);
    [DispId(25)] void OnMouseInputModeChanged(bool fMouseModeRelative);
    [DispId(26)] void OnServiceMessageReceived(string serviceMessage);
    [DispId(27)] void OnConnectionBarPullDown();
    [DispId(28)] void OnNetworkStatusChanged(uint qualityFlags, int bandwidth, int rtt);
    [DispId(29)] void OnDevicesButtonPressed();
    // OnRemoteProgramDisplayed was added later in the dispinterface (v8+) with id 30; it slots
    // after OnDevicesButtonPressed, not next to OnRemoteProgramResult.
    [DispId(30)] void OnRemoteProgramDisplayed(bool displayed, uint exStyle);
    [DispId(31)] void OnAutoReconnected();
    [DispId(32)] void OnAutoReconnecting2(int disconnectReason, bool networkAvailable, int attemptCount, int maxAttemptCount);
}

/// <summary>
/// Concrete managed sink. We pass an instance of this into IConnectionPoint.Advise; the OCX
/// then dispatches event methods to it. Events used by the Electron host are forwarded to
/// managed subscribers. Exceptions never cross the COM dispatch boundary.
/// </summary>
[ComVisible(true)]
[ClassInterface(ClassInterfaceType.None)]
[Guid("4A77F7F2-AD7C-4B30-BD53-9C9C00B61F86")]
public sealed class MsTscAxEventsSink : IMsTscAxEvents
{
    public event Action? Connected;
    public event Action? LoginComplete;
    public event Action<int>? Disconnected;
    public event Action<int>? FatalError;
    public event Action<int>? LogonError;
    public event Action<int, bool, int, int>? AutoReconnecting2;
    public event Action? AutoReconnected;

    private static void Safe(Action invoke)
    {
        try { invoke(); }
        catch { /* Never let subscriber failures escape into COM event dispatch. */ }
    }

    public void OnConnecting() { }
    public void OnConnected() => Safe(() => Connected?.Invoke());
    public void OnLoginComplete() => Safe(() => LoginComplete?.Invoke());
    public void OnDisconnected(int discReason) => Safe(() => Disconnected?.Invoke(discReason));
    public void OnEnterFullScreenMode() { }
    public void OnLeaveFullScreenMode() { }
    public void OnChannelReceivedData(string chanName, string data) { }
    public void OnRequestGoFullScreen() { }
    public void OnRequestLeaveFullScreen() { }
    public void OnFatalError(int errorCode) => Safe(() => FatalError?.Invoke(errorCode));
    public void OnWarning(int warningCode) { }
    public void OnRemoteDesktopSizeChange(int width, int height) { }
    public void OnIdleTimeoutNotification() { }
    public void OnRequestContainerMinimize() { }
    public void OnConfirmClose(out bool fAllowClose) { fAllowClose = true; }
    public void OnReceivedTSPublicKey(string publicKey, out bool fContinueLogon) { fContinueLogon = true; }
    public void OnAutoReconnecting(int disconnectReason, int attemptCount, out int arcContinueStatus)
    {
        arcContinueStatus = 0; // 0 = continueReconnecting per IMsRdpClientAdvancedSettings.EnableAutoReconnect docs
    }
    public void OnAuthenticationWarningDisplayed() { }
    public void OnAuthenticationWarningDismissed() { }
    public void OnRemoteProgramResult(string remoteProgramName, int execResult, int rawResult) { }
    public void OnRemoteProgramDisplayed(bool displayed, uint exStyle) { }
    public void OnRemoteWindowDisplayed(bool displayed, IntPtr hwnd, int remoteWindowDisplayedAttribute) { }
    public void OnLogonError(int lError) => Safe(() => LogonError?.Invoke(lError));
    public void OnFocusReleased(int iDirection) { }
    public void OnUserNameAcquired(string newUserName) { }
    public void OnMouseInputModeChanged(bool fMouseModeRelative) { }
    public void OnServiceMessageReceived(string serviceMessage) { }
    public void OnConnectionBarPullDown() { }
    public void OnNetworkStatusChanged(uint qualityFlags, int bandwidth, int rtt) { }
    public void OnDevicesButtonPressed() { }
    public void OnAutoReconnected() => Safe(() => AutoReconnected?.Invoke());
    public void OnAutoReconnecting2(int disconnectReason, bool networkAvailable, int attemptCount, int maxAttemptCount)
        => Safe(
            () => AutoReconnecting2?.Invoke(disconnectReason, networkAvailable, attemptCount, maxAttemptCount));

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
        Connected = null;
        LoginComplete = null;
        Disconnected = null;
        FatalError = null;
        LogonError = null;
        AutoReconnecting2 = null;
        AutoReconnected = null;
    }
}
