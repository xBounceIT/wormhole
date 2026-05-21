using System.Threading.Tasks;
using Wormhole.Models;
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
    public bool ConfirmResult { get; set; } = true;

    /// <summary>
    /// When non-null, drives <see cref="EditConnectionAsync"/>. The fake mirrors the real
    /// dialog: identity (Id, ParentId, SortOrder, timestamps, Ssh* fields) is preserved from
    /// <c>initial</c>; editable fields are copied from this seed.
    /// </summary>
    public ConnectionNode? EditConnectionResult { get; set; }

    public int PasswordPromptCount { get; private set; }
    public int TextPromptCount { get; private set; }

    public virtual Task ShowMessageAsync(string title, string message) => Task.CompletedTask;

    public virtual Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No")
        => Task.FromResult(ConfirmResult);

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
        return Task.FromResult<ConnectionNode?>(output);
    }

    public virtual Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null)
        => Task.FromResult<CredentialDraft?>(null);

    public virtual Task<string?> PromptPasswordAsync(string title, string message)
    {
        PasswordPromptCount++;
        return Task.FromResult(PasswordPromptResult);
    }
}
