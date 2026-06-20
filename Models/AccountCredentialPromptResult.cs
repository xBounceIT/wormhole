namespace Wormhole.Models;

public sealed record AccountCredentialPromptResult(
    string? Username,
    string Password,
    CredentialProfile? SelectedCredential,
    bool SaveCredentialToConnection);
