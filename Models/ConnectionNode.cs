namespace Wormhole.Models;

public class ConnectionNode
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid? ParentId { get; set; }
    public string Name { get; set; } = string.Empty;
    public NodeKind Kind { get; set; }
    public int SortOrder { get; set; }

    public ProtocolType? Protocol { get; set; }
    public string? Host { get; set; }
    public int? Port { get; set; }
    public string? Username { get; set; }
    public Guid? CredentialId { get; set; }

    public string? RdpDomain { get; set; }
    public string? RdpScreenSize { get; set; }
    public bool? RdpFullScreen { get; set; }

    public string? SshKeyFileName { get; set; }
    public string? SshKnownHostFingerprint { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
