using System.Threading.Tasks;
using Wormhole.Models;

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

    Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null);

    Task<string?> PromptPasswordAsync(string title, string message);
}
