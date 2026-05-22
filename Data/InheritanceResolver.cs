using Wormhole.Models;

namespace Wormhole.Data;

public sealed class InheritanceResolver
{
#pragma warning disable CA1822 // kept instance — registered via DI; see CLAUDE.md (load-bearing)
    public ConnectionProfile Resolve(ConnectionNode node, IReadOnlyDictionary<Guid, ConnectionNode> nodesById)
#pragma warning restore CA1822
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(nodesById);
        if (node.Kind != NodeKind.Connection)
        {
            throw new InvalidOperationException(
                $"InheritanceResolver can only resolve a connection node, but '{node.Name}' is a {node.Kind}.");
        }

        var chain = WalkParents(node, nodesById);

        ProtocolType? protocol = null;
        string? host = null;
        int? port = null;
        string? username = null;
        Guid? credentialId = null;
        string? rdpDomain = null;
        string? rdpScreenSize = null;
        bool? rdpFullScreen = null;
        string? sshKeyFileName = null;
        string? sshKnownHostFingerprint = null;
        bool? tunnelEnabled = null;
        Guid? tunnelConfigId = null;

        foreach (var ancestor in chain)
        {
            protocol ??= ancestor.Protocol;
            host ??= ancestor.Host;
            port ??= ancestor.Port;
            username ??= ancestor.Username;
            credentialId ??= ancestor.CredentialId;
            rdpDomain ??= ancestor.RdpDomain;
            rdpScreenSize ??= ancestor.RdpScreenSize;
            rdpFullScreen ??= ancestor.RdpFullScreen;
            sshKeyFileName ??= ancestor.SshKeyFileName;
            sshKnownHostFingerprint ??= ancestor.SshKnownHostFingerprint;
            tunnelEnabled ??= ancestor.TunnelEnabled;
            tunnelConfigId ??= ancestor.TunnelConfigId;
        }

        if (protocol is null)
        {
            throw new InvalidOperationException(
                $"Connection '{node.Name}' has no protocol set on itself or any ancestor folder.");
        }
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new InvalidOperationException(
                $"Connection '{node.Name}' has no host set on itself or any ancestor folder.");
        }

        return new ConnectionProfile
        {
            NodeId = node.Id,
            Name = node.Name,
            Protocol = protocol.Value,
            Host = host,
            Port = port ?? DefaultPortFor(protocol.Value),
            Username = username,
            CredentialId = credentialId,
            RdpDomain = rdpDomain,
            RdpScreenSize = rdpScreenSize,
            RdpFullScreen = rdpFullScreen ?? false,
            SshKeyFileName = sshKeyFileName,
            SshKnownHostFingerprint = sshKnownHostFingerprint,
            TunnelEnabled = tunnelEnabled ?? false,
            TunnelConfigId = tunnelConfigId,
        };
    }

    private static IEnumerable<ConnectionNode> WalkParents(
        ConnectionNode start, IReadOnlyDictionary<Guid, ConnectionNode> nodesById)
    {
        var seen = new HashSet<Guid>();
        var current = start;
        while (current is not null)
        {
            if (!seen.Add(current.Id))
            {
                throw new InvalidOperationException(
                    $"Detected a cycle in the node tree at '{current.Name}' ({current.Id}).");
            }
            yield return current;
            if (current.ParentId is null) yield break;
            if (!nodesById.TryGetValue(current.ParentId.Value, out var parent))
            {
                yield break;
            }
            current = parent;
        }
    }

    private static int DefaultPortFor(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Sftp => 22,
        ProtocolType.Rdp => 3389,
        _ => throw new ArgumentOutOfRangeException(nameof(protocol)),
    };
}
