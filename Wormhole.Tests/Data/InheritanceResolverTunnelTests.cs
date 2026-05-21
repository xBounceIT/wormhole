using System;
using System.Collections.Generic;
using Wormhole.Data;
using Wormhole.Models;
using Xunit;

namespace Wormhole.Tests.Data;

public class InheritanceResolverTunnelTests
{
    [Fact]
    public void Resolve_TunnelDefaultsToDisabledWhenNothingSet()
    {
        var node = ConnectionNode(host: "h.example", protocol: ProtocolType.Ssh);
        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.False(profile.TunnelEnabled);
        Assert.Null(profile.TunnelConfigId);
    }

    [Fact]
    public void Resolve_InheritsTunnelEnabledAndConfigIdFromAncestor()
    {
        var tunnelId = Guid.NewGuid();
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            TunnelEnabled = true,
            TunnelConfigId = tunnelId,
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "edge",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "edge.prod",
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [leaf.Id] = leaf,
        };

        var profile = new InheritanceResolver().Resolve(leaf, nodes);

        Assert.True(profile.TunnelEnabled);
        Assert.Equal(tunnelId, profile.TunnelConfigId);
    }

    [Fact]
    public void Resolve_ChildExplicitlyDisablesInheritedTunnel()
    {
        // Folder says tunnel ON; child sets TunnelEnabled = false explicitly. The child's
        // explicit "false" must beat the parent's "true" — that's the whole point of the
        // tri-state. (null on the child would inherit; here we test the off override.)
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "edge",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "edge.prod",
            TunnelEnabled = false,
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [leaf.Id] = leaf,
        };

        var profile = new InheritanceResolver().Resolve(leaf, nodes);

        Assert.False(profile.TunnelEnabled);
        // ConfigId still inherits — that's harmless because TunnelEnabled gates the launch.
    }

    [Fact]
    public void Resolve_ChildOverridesAncestorTunnelConfigId()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
        };
        var ownConfig = Guid.NewGuid();
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "edge",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "edge.prod",
            TunnelConfigId = ownConfig,
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [leaf.Id] = leaf,
        };

        var profile = new InheritanceResolver().Resolve(leaf, nodes);

        Assert.True(profile.TunnelEnabled);
        Assert.Equal(ownConfig, profile.TunnelConfigId);
    }

    private static ConnectionNode ConnectionNode(string host, ProtocolType protocol) =>
        new()
        {
            Id = Guid.NewGuid(),
            Name = "n",
            Kind = NodeKind.Connection,
            Host = host,
            Protocol = protocol,
        };
}
