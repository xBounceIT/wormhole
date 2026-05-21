using Wormhole.Data;
using Wormhole.Models;
using Xunit;

namespace Wormhole.Tests.Data;

public class InheritanceResolverTests
{
    [Fact]
    public void Resolve_OwnFieldsOnly_ReturnsExactValues()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod-db",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "db.example.com",
            Port = 2222,
            Username = "alice",
        };

        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(ProtocolType.Ssh, profile.Protocol);
        Assert.Equal("db.example.com", profile.Host);
        Assert.Equal(2222, profile.Port);
        Assert.Equal("alice", profile.Username);
    }

    [Fact]
    public void Resolve_InheritsUsernameAndPortFromParentFolder()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            Username = "deploy",
            Port = 2222,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal("deploy", profile.Username);
        Assert.Equal(2222, profile.Port);
        Assert.Equal("web-1.prod", profile.Host);
    }

    [Fact]
    public void Resolve_ChildOverridesParent()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            Username = "deploy",
            Port = 22,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "bastion",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "bastion.prod",
            Username = "alice",
            Port = 2222,
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal("alice", profile.Username);
        Assert.Equal(2222, profile.Port);
    }

    [Fact]
    public void Resolve_WalksMultipleAncestorsForMissingFields()
    {
        var root = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "all",
            Kind = NodeKind.Folder,
            Username = "root-user",
            CredentialId = Guid.NewGuid(),
        };
        var mid = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = root.Id,
            Name = "prod",
            Kind = NodeKind.Folder,
            Port = 22,
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = mid.Id,
            Name = "edge",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "edge.prod",
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [root.Id] = root,
            [mid.Id] = mid,
            [leaf.Id] = leaf,
        };

        var profile = new InheritanceResolver().Resolve(leaf, nodes);

        Assert.Equal("root-user", profile.Username);
        Assert.Equal(root.CredentialId, profile.CredentialId);
        Assert.Equal(22, profile.Port);
    }

    [Fact]
    public void Resolve_DefaultsPortFromProtocolWhenNoneInherited()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "rdp-target",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Rdp,
            Host = "vm.example.com",
        };

        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(3389, profile.Port);
    }

    [Fact]
    public void Resolve_ThrowsWhenProtocolMissing()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "broken",
            Kind = NodeKind.Connection,
            Host = "host",
        };

        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        Assert.Throws<InvalidOperationException>(() => new InheritanceResolver().Resolve(node, nodes));
    }

    [Fact]
    public void Resolve_ThrowsWhenHostMissing()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "broken",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
        };

        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        Assert.Throws<InvalidOperationException>(() => new InheritanceResolver().Resolve(node, nodes));
    }

    [Fact]
    public void Resolve_ThrowsOnCycle()
    {
        var a = new ConnectionNode { Id = Guid.NewGuid(), Name = "a", Kind = NodeKind.Folder };
        var b = new ConnectionNode { Id = Guid.NewGuid(), Name = "b", Kind = NodeKind.Folder, ParentId = a.Id };
        a.ParentId = b.Id;
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = a.Id,
            Name = "leaf",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "host",
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [a.Id] = a,
            [b.Id] = b,
            [leaf.Id] = leaf,
        };

        Assert.Throws<InvalidOperationException>(() => new InheritanceResolver().Resolve(leaf, nodes));
    }

    [Fact]
    public void Resolve_ThrowsWhenNodeIsAFolder()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "folder",
            Kind = NodeKind.Folder,
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [folder.Id] = folder };
        Assert.Throws<InvalidOperationException>(() => new InheritanceResolver().Resolve(folder, nodes));
    }
}
