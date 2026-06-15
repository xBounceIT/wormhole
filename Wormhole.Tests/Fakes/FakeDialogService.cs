using System.Threading.Tasks;
using Wormhole.Models;
using Wormhole.Models.Backup;
using Wormhole.Services;

namespace Wormhole.Tests.Fakes;

/// <summary>
/// Test double for <see cref="IDialogService"/>. Each prompt method either returns the
/// configured result, or null/default if not configured. Tests drive specific scenarios via
/// the public setters. All methods are virtual so test-specific subclasses can override the
/// ones they care about.
/// </summary>
public class FakeDialogService : IDialogService
{
    public string? TextPromptResult { get; set; }
    public string? PasswordPromptResult { get; set; }
    public string? SecretPromptResult { get; set; }
    public (string Secret, string Confirmation)? NewSecretPromptResult { get; set; }
    public (string Username, string Password)? CredentialsPromptResult { get; set; }
    public bool ConfirmResult { get; set; } = true;
    public int ConfirmCount { get; private set; }

    /// <summary>
    /// When non-null, drives <see cref="EditConnectionAsync"/>. The fake mirrors the real
    /// dialog: identity (Id, ParentId, SortOrder, timestamps, Ssh* fields) is preserved from
    /// <c>initial</c>; editable fields are copied from this seed.
    /// </summary>
    public ConnectionNode? EditConnectionResult { get; set; }

    /// <summary>
    /// When non-null, drives <see cref="EditFolderAsync"/>. The fake mirrors the real dialog:
    /// identity is preserved from <c>initial</c>; Name and the two tunnel fields are copied
    /// from this seed (folders don't carry any other editable state today).
    /// </summary>
    public ConnectionNode? EditFolderResult { get; set; }

    /// <summary>Drives <see cref="PromptForMRemoteNgImportAsync"/>; null = user closed
    /// the dialog without committing.</summary>
    public MRemoteNgImportResult? MRemoteNgImportResult { get; set; }

    public int PasswordPromptCount { get; private set; }
    public int SecretPromptCount { get; private set; }
    public int NewSecretPromptCount { get; private set; }
    public int CredentialsPromptCount { get; private set; }
    public int TextPromptCount { get; private set; }
    public int MRemoteNgImportPromptCount { get; private set; }

    /// <summary>Records of the read-only credential-reveal dialog (<see cref="ShowCredentialsAsync"/>).</summary>
    public int ShowCredentialsCount { get; private set; }
    public string? LastShownSecret { get; private set; }
    public string? LastShownSecretLabel { get; private set; }
    public string? LastShownUsername { get; private set; }

    public virtual Task ShowMessageAsync(string title, string message) => Task.CompletedTask;

    public virtual Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No")
    {
        ConfirmCount++;
        return Task.FromResult(ConfirmResult);
    }

    public virtual Task<string?> PromptForTextAsync(string title, string label, string defaultValue = "")
    {
        TextPromptCount++;
        return Task.FromResult(TextPromptResult);
    }

    public virtual Task<ConnectionNode?> EditConnectionAsync(ConnectionNode initial, bool isNew)
    {
        if (EditConnectionResult is null) return Task.FromResult<ConnectionNode?>(null);
        var output = ConnectionNode.CloneIdentityFrom(initial);
        // The ConnectionEditorViewModel.WriteTo path covers every editable field for the real
        // dialog. The test fake doesn't have that VM, so copy the editable fields from the
        // configured seed directly.
        var src = EditConnectionResult;
        output.Name = src.Name;
        output.Protocol = src.Protocol;
        output.Host = src.Host;
        output.Port = src.Port;
        output.Username = src.Username;
        output.CredentialId = src.CredentialId;
        output.UseInlinePassword = src.UseInlinePassword;
        // Transient plaintext the tree VM stores in Credential Manager after the row commits —
        // mirror it so inline-password tree tests can seed a password through the fake editor.
        output.PendingInlinePassword = src.PendingInlinePassword;
        output.RdpDomain = src.RdpDomain;
        output.RdpScreenSize = src.RdpScreenSize;
        output.RdpFullScreen = src.RdpFullScreen;
        output.RdpColorDepth = src.RdpColorDepth;
        output.RdpUseAllMonitors = src.RdpUseAllMonitors;
        output.RdpAudioMode = src.RdpAudioMode;
        output.RdpAudioCaptureMode = src.RdpAudioCaptureMode;
        output.RdpKeyboardHookMode = src.RdpKeyboardHookMode;
        output.RdpRedirectClipboard = src.RdpRedirectClipboard;
        output.RdpRedirectPrinters = src.RdpRedirectPrinters;
        output.RdpRedirectSmartCards = src.RdpRedirectSmartCards;
        output.RdpRedirectPorts = src.RdpRedirectPorts;
        output.RdpRedirectDevices = src.RdpRedirectDevices;
        output.RdpRedirectDrives = src.RdpRedirectDrives;
        output.RdpConnectionSpeed = src.RdpConnectionSpeed;
        output.RdpDesktopBackground = src.RdpDesktopBackground;
        output.RdpFontSmoothing = src.RdpFontSmoothing;
        output.RdpDesktopComposition = src.RdpDesktopComposition;
        output.RdpWindowDrag = src.RdpWindowDrag;
        output.RdpMenuAnimation = src.RdpMenuAnimation;
        output.RdpVisualStyles = src.RdpVisualStyles;
        output.RdpBitmapCaching = src.RdpBitmapCaching;
        output.RdpAutoReconnect = src.RdpAutoReconnect;
        output.RdpServerAuthentication = src.RdpServerAuthentication;
        output.RdpGatewayUsageMethod = src.RdpGatewayUsageMethod;
        output.RdpGatewayHostname = src.RdpGatewayHostname;
        output.RdpGatewayCredentialId = src.RdpGatewayCredentialId;
        output.RdpGatewayBypassLocal = src.RdpGatewayBypassLocal;
        output.RdpGatewayUseSameCreds = src.RdpGatewayUseSameCreds;
        output.RdpUseExternalClient = src.RdpUseExternalClient;
        output.TunnelEnabled = src.TunnelEnabled;
        output.TunnelConfigId = src.TunnelConfigId;
        return Task.FromResult<ConnectionNode?>(output);
    }

    public virtual Task<ConnectionNode?> EditFolderAsync(ConnectionNode initial, bool isNew)
    {
        // Two ways tests can drive this:
        //  - EditFolderResult: precise control over Name and tunnel fields.
        //  - TextPromptResult: name-only fallback. Mirrors the original PromptForTextAsync
        //    contract the folder Add/Edit flow used before EditFolderAsync existed, so the
        //    pile of "make a folder called X" tests keeps working without enumeration.
        // Both branches start from initial.Clone() (not CloneIdentityFrom) — folders can
        // hold inheritance defaults (Protocol / Host / CredentialId / etc.) for their
        // descendants, and the editor must round-trip them untouched.
        if (EditFolderResult is not null)
        {
            var output = initial.Clone();
            var src = EditFolderResult;
            output.Name = src.Name;
            output.TunnelEnabled = src.TunnelEnabled;
            output.TunnelConfigId = src.TunnelConfigId;
            return Task.FromResult<ConnectionNode?>(output);
        }
        if (TextPromptResult is not null)
        {
            // Mirror PromptForTextAsync's invocation tracking so tests using TextPromptCount
            // to verify call-path coverage see the fallback as an actual text-prompt
            // consumption — otherwise a regression that routes back through the legacy
            // PromptForTextAsync flow could silently pass.
            TextPromptCount++;
            var output = initial.Clone();
            output.Name = TextPromptResult;
            return Task.FromResult<ConnectionNode?>(output);
        }
        return Task.FromResult<ConnectionNode?>(null);
    }

    public virtual Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null)
        => Task.FromResult<CredentialDraft?>(null);

    // Tunnel-create dialog plumbing — main added this to IDialogService when the SSH
    // tunneling feature landed. Default null mirrors the password / text prompt fakes;
    // tests that exercise tunnel creation override the method directly.
    public virtual Task<TunnelDraft?> PromptForTunnelAsync(TunnelDraft? initial = null)
        => Task.FromResult<TunnelDraft?>(null);

    /// <summary>Records calls to <see cref="ShowTunnelTestAsync"/> — the diagnostic dialog is
    /// display-only, so tests only assert it was opened for the right config.</summary>
    public int TunnelTestPromptCount { get; private set; }
    public TunnelConfig? LastTunnelTestConfig { get; private set; }

    public virtual Task ShowTunnelTestAsync(TunnelConfig config)
    {
        TunnelTestPromptCount++;
        LastTunnelTestConfig = config;
        return Task.CompletedTask;
    }

    public virtual Task<string?> PromptPasswordAsync(string title, string message)
    {
        PasswordPromptCount++;
        return Task.FromResult(PasswordPromptResult);
    }

    public virtual Task<string?> PromptSecretAsync(string title, string message, string label, string primaryText = "OK")
    {
        SecretPromptCount++;
        return Task.FromResult(SecretPromptResult);
    }

    public virtual Task<(string Secret, string Confirmation)?> PromptNewSecretAsync(
        string title,
        string message,
        string label,
        string primaryText = "Save")
    {
        NewSecretPromptCount++;
        return Task.FromResult(NewSecretPromptResult);
    }

    /// <summary>Drives <see cref="PromptTunnelRouteAsync"/>. Defaults to
    /// <see cref="TunnelRouteChoice.UseTunnel"/> so a test that enables the prompt without
    /// configuring an answer keeps the pre-feature behavior (use the tunnel).</summary>
    public TunnelRouteChoice TunnelRouteResult { get; set; } = TunnelRouteChoice.UseTunnel;
    public int TunnelRoutePromptCount { get; private set; }
    public string? LastTunnelRouteName { get; private set; }
    public string? LastTunnelRouteConnectionName { get; private set; }

    public virtual Task<TunnelRouteChoice> PromptTunnelRouteAsync(string connectionName, string tunnelName)
    {
        TunnelRoutePromptCount++;
        LastTunnelRouteConnectionName = connectionName;
        LastTunnelRouteName = tunnelName;
        return Task.FromResult(TunnelRouteResult);
    }

    public virtual Task ShowCredentialsAsync(string title, string username, string secretLabel, string secret)
    {
        ShowCredentialsCount++;
        LastShownUsername = username;
        LastShownSecretLabel = secretLabel;
        LastShownSecret = secret;
        return Task.CompletedTask;
    }

    public virtual Task<(string Username, string Password)?> PromptCredentialsAsync(string title, string message, string? initialUsername = null)
    {
        CredentialsPromptCount++;
        return Task.FromResult(CredentialsPromptResult);
    }

    public virtual Task<MRemoteNgImportResult?> PromptForMRemoteNgImportAsync()
    {
        MRemoteNgImportPromptCount++;
        return Task.FromResult(MRemoteNgImportResult);
    }

    /// <summary>Drives <see cref="PromptForBackupExportAsync"/>; null = user closed the
    /// dialog without exporting.</summary>
    public BackupExportResult? BackupExportResult { get; set; }
    /// <summary>Drives <see cref="PromptForBackupImportAsync"/>; null = user closed the
    /// dialog without importing.</summary>
    public BackupImportResult? BackupImportResult { get; set; }

    public int BackupExportPromptCount { get; private set; }
    public int BackupImportPromptCount { get; private set; }

    public virtual Task<BackupExportResult?> PromptForBackupExportAsync()
    {
        BackupExportPromptCount++;
        return Task.FromResult(BackupExportResult);
    }

    public virtual Task<BackupImportResult?> PromptForBackupImportAsync()
    {
        BackupImportPromptCount++;
        return Task.FromResult(BackupImportResult);
    }
}
