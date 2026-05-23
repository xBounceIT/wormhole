using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
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
}

public enum SessionStatus
{
    Disconnected,
    Connecting,
    Connected,
    Failed,
}
