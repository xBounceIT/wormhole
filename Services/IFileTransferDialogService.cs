using Wormhole.ViewModels.Sessions;

namespace Wormhole.Services;

public interface IFileTransferDialogService
{
    /// <summary>Opens the modal File Transfer dialog for the given SSH session tab.
    /// Returns when the dialog is dismissed. Caller is responsible for ensuring the
    /// tab is in the Connected state — the menu item visibility already gates on this.</summary>
    Task ShowAsync(SessionTabViewModel sourceTab);
}
