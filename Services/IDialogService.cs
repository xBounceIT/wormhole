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

    /// <summary>
    /// Show the tunnel-test dialog for <paramref name="config"/>: establishes the saved tunnel once
    /// as a diagnostic, streaming live progress + a timestamped log, then closes it. Display-only —
    /// there is no result to collect; the dialog surfaces success/failure itself.
    /// </summary>
    Task ShowTunnelTestAsync(TunnelConfig config);

    Task<string?> PromptPasswordAsync(string title, string message);

    /// <summary>
    /// Ask whether to route a tunnel-configured connection through its VPN tunnel or connect
    /// directly. Shown only when the user has enabled
    /// <see cref="Models.AppSettings.PromptBeforeTunnelConnect"/> and the profile is configured
    /// for a tunnel. <paramref name="connectionName"/> and <paramref name="tunnelName"/> are
    /// display-only. Returns <see cref="Models.TunnelRouteChoice.Cancel"/> if the user dismisses
    /// the dialog.
    /// </summary>
    Task<TunnelRouteChoice> PromptTunnelRouteAsync(string connectionName, string tunnelName);

    /// <summary>
    /// Reveal stored credentials read-only. Shows the (optional) username and the secret
    /// (<paramref name="secretLabel"/> is the field caption — e.g. "Password" or "Key
    /// passphrase") as selectable plaintext plus a button to copy the secret to the clipboard.
    /// Display-only — there is no result to collect.
    /// </summary>
    Task ShowCredentialsAsync(string title, string username, string secretLabel, string secret);

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
