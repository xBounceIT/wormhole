namespace Wormhole.Services.Bitwarden;

public interface IBitwardenVaultClient
{
    Task<BitwardenStatus> GetStatusAsync(CancellationToken cancellationToken = default);
    Task<string> LoginAsync(string email, string masterPassword, string? authenticatorCode = null, CancellationToken cancellationToken = default);
    Task<string> UnlockAsync(string masterPassword, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<BitwardenLoginItem>> ListLoginItemsAsync(string? sessionKey, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<BitwardenLoginItem>> SearchLoginItemsAsync(string query, string? sessionKey, CancellationToken cancellationToken = default);
    Task<BitwardenLoginItem?> GetLoginItemAsync(string itemId, string? sessionKey, CancellationToken cancellationToken = default);
    Task SyncAsync(string? sessionKey, CancellationToken cancellationToken = default);
}
