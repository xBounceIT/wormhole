namespace Wormhole.Models;

public class CredentialProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string? Domain { get; set; }
    public CredentialKind Kind { get; set; } = CredentialKind.Password;
    public string? PrivateKeyFileName { get; set; }
    public ProtocolType Protocol { get; set; } = ProtocolType.Ssh;
    public CredentialSecretProvider SecretProvider { get; set; } = CredentialSecretProvider.Local;
    public string? BitwardenItemId { get; set; }
    public string? BitwardenItemName { get; set; }
    private string? _bitwardenFieldPath = BitwardenDefaults.PasswordFieldPath;
    public string? BitwardenFieldPath
    {
        get => string.IsNullOrWhiteSpace(_bitwardenFieldPath) ? BitwardenDefaults.PasswordFieldPath : _bitwardenFieldPath;
        set => _bitwardenFieldPath = string.IsNullOrWhiteSpace(value) ? BitwardenDefaults.PasswordFieldPath : value;
    }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool IsBitwarden => SecretProvider == CredentialSecretProvider.Bitwarden;
    public bool IsVirtualBitwarden { get; set; }
    public bool IsReadOnly => IsVirtualBitwarden;
    public string ProtocolLabel => IsVirtualBitwarden ? "ANY" : Protocol.ToString().ToUpperInvariant();
}

public enum CredentialKind
{
    Password,
    SshKey,
}

public enum CredentialSecretProvider
{
    Local = 0,
    Bitwarden = 1,
}

public static class BitwardenDefaults
{
    public const string PasswordFieldPath = "login.password";
}
