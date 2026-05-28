using Wormhole.Models;
using Wormhole.Models.Backup;

namespace Wormhole.Services;

public interface IDialogService
{
    Task ShowMessageAsync(string title, string message);
    Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No");
    Task<string?> PromptForTextAsync(string title, string label, string defaultValue = "");

    /// <summary>
    /// Opens the multi-tab connection editor pre-filled from <paramref name="initial"/>. Returns
    /// a new <see cref="ConnectionNode"/> with the edited values on Save (caller writes it back to
    /// storage). Returns null if the user cancels. The input <paramref name="initial"/> is not
    /// mutated.
    /// </summary>
    /// <param name="initial">Node to seed the editor from. Pass a fresh stub for new connections.</param>
    /// <param name="isNew">Controls dialog title and button copy.</param>
    Task<ConnectionNode?> EditConnectionAsync(ConnectionNode initial, bool isNew);

    /// <summary>
    /// Opens the folder editor pre-filled from <paramref name="initial"/> (Name + VPN tunnel —
    /// the only fields a folder holds that descendants inherit via
    /// <see cref="Data.InheritanceResolver"/>). Returns a new <see cref="ConnectionNode"/> on
    /// Save; null on cancel. The input is not mutated.
    /// </summary>
    Task<ConnectionNode?> EditFolderAsync(ConnectionNode initial, bool isNew);

    Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null);
    Task<TunnelDraft?> PromptForTunnelAsync(TunnelDraft? initial = null);
    Task<string?> PromptPasswordAsync(string title, string message);

    /// <summary>
    /// Reveal a stored password read-only. Shows the (optional) username and the password as
    /// selectable plaintext plus a button to copy it to the clipboard. Display-only — there is
    /// no result to collect.
    /// </summary>
    Task ShowPasswordAsync(string title, string username, string password);

    /// <summary>
    /// Prompt for username + password together. Used when the connection profile has no
    /// stored username (a plain password prompt would leave the user no way to type one),
    /// or when the caller specifically wants the user to confirm both fields. Returns null
    /// on cancel; otherwise a non-empty tuple — both fields are required to enable the
    /// Connect button.
    /// </summary>
    Task<(string Username, string Password)?> PromptCredentialsAsync(string title, string message, string? initialUsername = null);
    Task<MRemoteNgImportResult?> PromptForMRemoteNgImportAsync();

    /// <summary>Show the export-backup dialog. Returns the result on success, null if the
    /// user closed the dialog without exporting.</summary>
    Task<BackupExportResult?> PromptForBackupExportAsync();

    /// <summary>Show the import-backup dialog. Returns the result on success, null if the
    /// user closed the dialog without importing anything.</summary>
    Task<BackupImportResult?> PromptForBackupImportAsync();
}
