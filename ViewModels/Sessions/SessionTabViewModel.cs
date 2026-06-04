using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Dispatching;
using Wormhole.Models;

namespace Wormhole.ViewModels.Sessions;

public abstract partial class SessionTabViewModel : ObservableObject
{
    [ObservableProperty]
    private string title = string.Empty;

    [ObservableProperty]
    private SessionStatus status = SessionStatus.Disconnected;

    public ConnectionProfile? Profile { get; protected set; }

    /// <summary>
    /// Numbered, phased progress shown in the connecting overlay. Populated with steps by the
    /// derived VM's connect path for tunneled connections (left empty for direct connections, which
    /// fall back to a plain spinner). Stable instance — bindings subscribe to it for the tab's life.
    /// </summary>
    public ConnectionProgress Progress { get; } = new();

    public abstract ProtocolType Protocol { get; }

    /// <summary>
    /// Captured at first <see cref="EnsureDispatcher"/> call. Null on threads without a
    /// WinUI dispatcher (e.g. unit tests) — <see cref="MarshalToUi(Action)"/> falls through
    /// to synchronous execution in that case.
    /// </summary>
    protected DispatcherQueue? UiDispatcher { get; private set; }

    public virtual ICommand? ReconnectCommand => null;

    public bool CanReconnect => ReconnectCommand is not null;

    /// <summary>
    /// Whether the "File transfer" entry in this tab's context menu should be visible.
    /// Default: false. SSH overrides this to <c>Status == Connected</c> so the entry
    /// only shows once we have a live SSH connection to ride alongside for the SFTP
    /// channel. Subclasses that override must raise <see cref="ObservableObject.PropertyChanged"/>
    /// for this property whenever its underlying state changes.
    /// </summary>
    public virtual bool CanOpenFileTransfer => false;

    /// <summary>
    /// Disconnect / "Open in System Remote Desktop" actions surfaced on the TAB context menu so
    /// they stay reachable for RDP. A connected RDP session is a top-level overlay that intercepts
    /// pointer events (right-click correctly goes to the remote desktop), so the surface's own
    /// ContextFlyout can't open over a live session. Default off; RDP overrides these and raises
    /// PropertyChanged for the Can* flags whenever its state changes.
    /// </summary>
    public virtual ICommand? TabDisconnectCommand => null;
    public virtual bool CanTabDisconnect => false;
    public virtual ICommand? TabUseExternalClientCommand => null;
    public virtual bool CanTabUseExternalClient => false;

    public virtual void Initialize(ConnectionProfile profile)
    {
        Profile = profile;
        Title = string.IsNullOrEmpty(profile.Name) ? profile.Host : profile.Name;
        Status = SessionStatus.Disconnected;
    }

    /// <summary>
    /// Replace the in-memory <see cref="Profile"/> snapshot (used after side-channel
    /// updates such as TOFU host-key pinning from the File Transfer dialog so the
    /// next consumer of <c>Profile</c> on this tab sees the pinned fingerprint
    /// instead of re-running TOFU). Does NOT persist — the caller is responsible
    /// for writing to the repository.
    /// <para>
    /// MUST be called on the UI thread: Profile has a protected setter and any future
    /// XAML binding to it would receive PropertyChanged on the calling thread. The
    /// only current call sites (SshSessionViewModel.ConnectAsync and
    /// FileTransferDialogService.ShowAsync) both run on the UI thread.
    /// </para>
    /// </summary>
    public void UpdateProfile(ConnectionProfile profile)
    {
        Profile = profile;
        // Notify so any future reactive consumer of Profile (none today, but the
        // surface is now public) sees the new value. ObservableObject.OnPropertyChanged
        // is the standard accessor.
        OnPropertyChanged(nameof(Profile));
    }

    /// <summary>
    /// Tear down all session-owned resources (sockets, ActiveX HWNDs, background pumps).
    /// Called from <c>SessionsPage.SessionTabs_TabCloseRequested</c> when the user closes the
    /// tab. Default implementation is a no-op so trivial sessions don't have to override.
    /// </summary>
    public virtual ValueTask CloseAsync() => ValueTask.CompletedTask;

    /// <summary>
    /// Lazily capture the dispatcher for the calling thread. Subclasses should call this
    /// once from their attach path (UI-thread entry point) so subsequent background-thread
    /// event handlers can marshal back via <see cref="MarshalToUi(Action)"/>.
    /// </summary>
    protected void EnsureDispatcher()
    {
        UiDispatcher ??= TryGetDispatcher();
    }

    /// <summary>
    /// Marshal an action to the captured UI dispatcher. Falls through to synchronous
    /// execution when no dispatcher was captured (unit tests, etc.). Logs to
    /// <see cref="OnDispatchEnqueueFailed"/> if <see cref="DispatcherQueue.TryEnqueue(DispatcherQueueHandler)"/>
    /// rejects the work — a dropped status notification can otherwise strand the VM in
    /// <see cref="SessionStatus.Connecting"/> with no recovery path.
    /// </summary>
    protected void MarshalToUi(Action action)
    {
        var dispatcher = UiDispatcher;
        if (dispatcher is null)
        {
            action();
            return;
        }
        if (!dispatcher.TryEnqueue(() => action()))
        {
            OnDispatchEnqueueFailed();
        }
    }

    /// <summary>
    /// Marshal an async action to the captured UI dispatcher. Exceptions inside the
    /// continuation are routed to <see cref="OnDispatchedException"/> so subclasses can put
    /// the VM in a terminal state instead of leaving it stuck on <see cref="SessionStatus.Connecting"/>.
    /// </summary>
    protected void MarshalToUi(Func<Task> action)
    {
        var dispatcher = UiDispatcher;
        if (dispatcher is null)
        {
            _ = RunSafe(action);
            return;
        }
        if (!dispatcher.TryEnqueue(async () => await RunSafe(action).ConfigureAwait(true)))
        {
            OnDispatchEnqueueFailed();
        }
    }

    /// <summary>
    /// Build an <see cref="IProgress{T}"/> whose <c>Report</c> marshals <paramref name="onUi"/> onto
    /// the captured UI dispatcher. Tunnel providers report from background threads (they await with
    /// <c>ConfigureAwait(false)</c>), so the handler — which touches observable state on
    /// <see cref="Progress"/> — must be hopped to the UI thread. Falls through to synchronous
    /// execution when no dispatcher was captured (unit tests), same as <see cref="MarshalToUi(Action)"/>.
    /// </summary>
    protected IProgress<T> CreateUiProgress<T>(Action<T> onUi) => new DispatchedProgress<T>(this, onUi);

    private sealed class DispatchedProgress<T> : IProgress<T>
    {
        private readonly SessionTabViewModel _owner;
        private readonly Action<T> _onUi;

        public DispatchedProgress(SessionTabViewModel owner, Action<T> onUi)
        {
            _owner = owner;
            _onUi = onUi;
        }

        public void Report(T value) => _owner.MarshalToUi(() => _onUi(value));
    }

    private async Task RunSafe(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            OnDispatchedException(ex);
        }
    }

    /// <summary>
    /// Invoked when <see cref="MarshalToUi(Func{Task})"/> catches an exception escaping the
    /// dispatched continuation. Default: nothing — subclasses override to surface failure UI.
    /// </summary>
    protected virtual void OnDispatchedException(Exception ex) { }

    /// <summary>
    /// Invoked when <see cref="DispatcherQueue.TryEnqueue(DispatcherQueueHandler)"/> rejects
    /// the work item (queue shutting down, etc.). Default: nothing — subclasses override to
    /// log the dropped notification.
    /// </summary>
    protected virtual void OnDispatchEnqueueFailed() { }

    private static DispatcherQueue? TryGetDispatcher()
    {
        try { return DispatcherQueue.GetForCurrentThread(); }
        catch (COMException) { return null; }
        catch (TypeInitializationException) { return null; }
    }
}

public enum SessionStatus
{
    Disconnected,
    Connecting,
    Connected,
    Failed,
}
