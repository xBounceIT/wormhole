using System;

namespace Wormhole.Models;

public sealed record ConnectionProfile
{
    public required Guid NodeId { get; init; }
    public required string Name { get; init; }
    public required ProtocolType Protocol { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    public string? Username { get; init; }
    public Guid? CredentialId { get; init; }

    public string? RdpDomain { get; init; }
    public string? RdpScreenSize { get; init; }
    public bool RdpFullScreen { get; init; }

    public string? SshKeyFileName { get; init; }
    public string? SshKnownHostFingerprint { get; init; }
}
