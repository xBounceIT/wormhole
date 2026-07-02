namespace Wormhole.Models;

public sealed class BitwardenCredentialCacheEntry
{
    public string ItemId { get; set; } = string.Empty;
    public Guid SshCredentialId { get; set; }
    public Guid RdpCredentialId { get; set; }
    public Guid VncCredentialId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string? RevisionDate { get; set; }
    public DateTimeOffset LastSeenSyncUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }

    public Guid GetCredentialId(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => SshCredentialId,
        ProtocolType.Rdp => RdpCredentialId,
        ProtocolType.Vnc => VncCredentialId,
        _ => Guid.Empty,
    };
}
