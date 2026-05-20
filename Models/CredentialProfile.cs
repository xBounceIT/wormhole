using System;

namespace Wormhole.Models;

public class CredentialProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string? Domain { get; set; }
    public CredentialKind Kind { get; set; } = CredentialKind.Password;
    public string? PrivateKeyFileName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public enum CredentialKind
{
    Password,
    SshKey,
}
