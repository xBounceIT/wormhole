namespace Wormhole.Models;

public sealed record CredentialDraft(
    string Name,
    ProtocolType Protocol,
    string Username,
    string? Domain,
    string Password);
