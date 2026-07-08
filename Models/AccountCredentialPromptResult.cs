namespace Wormhole.Models;

public sealed record AccountCredentialPromptResult(
    string? Username,
    string Password,
    CredentialProfile? SelectedCredential,
    bool SaveCredentialToConnection);

public sealed record BitwardenLoginPromptResult(
    string Email,
    string MasterPassword,
    string? AuthenticatorCode,
    BitwardenCliServerRegion ServerRegion);
