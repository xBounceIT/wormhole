namespace Wormhole.Models;

public sealed record CredentialDraft(
    string Name,
    ProtocolType Protocol,
    string Username,
    string? Domain,
    string Password,
    CredentialSecretProvider SecretProvider = CredentialSecretProvider.Local,
    string? BitwardenItemId = null,
    string? BitwardenItemName = null,
    string? BitwardenFieldPath = null);
