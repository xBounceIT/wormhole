using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
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

    public abstract ProtocolType Protocol { get; }

    /// <summary>
    /// Captured at first <see cref="EnsureDispatcher"/> call. Null on threads without a
    /// WinUI dispatcher (e.g. unit tests) — <see cref="MarshalToUi(Action)"/> falls through
    /// to synchronous execution in that case.
    /// </summary>
    protected DispatcherQueue? UiDispatcher { get; private set; }

    public virtual void Initialize(ConnectionProfile profile)
    {
        Profile = profile;
        Title = string.IsNullOrEmpty(profile.Name) ? profile.Host : profile.Name;
        Status = SessionStatus.Disconnected;
    }

    /// <summary>
    /// Tear down all session-owned resources (sockets, ActiveX HWNDs, background pumps).
    /// Called from <c>SessionsPage.SessionTabs_TabCloseRequested</c> when the user closes the
    /// tab. Default implementation is a no-op so trivial sessions (SFTP placeholder) don't
    /// have to override.
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
