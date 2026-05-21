using Wormhole.Models;

namespace Wormhole.Services;

public interface IDialogService
{
    Task ShowMessageAsync(string title, string message);
    Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No");
    Task<string?> PromptForTextAsync(string title, string label, string defaultValue = "");
    Task<NewConnectionDraft?> PromptForConnectionAsync(NewConnectionDraft? initial = null);
    Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null);
    Task<string?> PromptPasswordAsync(string title, string message);
}
