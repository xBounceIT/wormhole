using Wormhole.Data;
using Wormhole.Helpers;
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
    public void Resolve_ParentFolderName_UsesImmediateParentOnly()
    {
        var root = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "root",
            Kind = NodeKind.Folder,
        };
        var mid = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = root.Id,
            Name = "prod",
            Kind = NodeKind.Folder,
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

        Assert.Equal("prod", profile.ParentFolderName);
    }

    [Fact]
    public void Resolve_CredentialModeSaved_InheritsFromParentFolder()
    {
        var credId = Guid.NewGuid();
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            Username = "deploy",
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = credId,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
            CredentialMode = CredentialBindingMode.Inherit,
        };

        var profile = new InheritanceResolver().Resolve(node, new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        });

        Assert.Equal(credId, profile.CredentialId);
        Assert.Equal("deploy", profile.Username);
    }

    [Fact]
    public void Resolve_CredentialModeNone_OnChildStopsInheritedFolderCredential()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
            CredentialMode = CredentialBindingMode.None,
        };

        var profile = new InheritanceResolver().Resolve(node, new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        });

        Assert.Null(profile.CredentialId);
    }

    [Fact]
    public void Resolve_CredentialModeSaved_OnChildOverridesParentFolder()
    {
        var parentCredId = Guid.NewGuid();
        var childCredId = Guid.NewGuid();
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = parentCredId,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = childCredId,
        };

        var profile = new InheritanceResolver().Resolve(node, new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        });

        Assert.Equal(childCredId, profile.CredentialId);
    }

    [Fact]
    public void Resolve_MultipleFolderCredentials_ClosestFolderCredentialWins()
    {
        var rootCredId = Guid.NewGuid();
        var closestCredId = Guid.NewGuid();
        var root = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "all",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = rootCredId,
            Username = "root-user",
        };
        var closest = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = root.Id,
            Name = "prod",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = closestCredId,
            Username = "prod-user",
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = closest.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
            CredentialMode = CredentialBindingMode.Inherit,
        };

        var profile = new InheritanceResolver().Resolve(leaf, new Dictionary<Guid, ConnectionNode>
        {
            [root.Id] = root,
            [closest.Id] = closest,
            [leaf.Id] = leaf,
        });

        Assert.Equal(closestCredId, profile.CredentialId);
        Assert.Equal("prod-user", profile.Username);
    }

    [Fact]
    public void Resolve_ClosestSavedCredentialWithoutIdentity_DoesNotInheritDistantIdentity()
    {
        var root = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "all",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
            Username = "root-user",
            RdpDomain = "ROOT",
        };
        var closest = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = root.Id,
            Name = "prod",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = closest.Id,
            Name = "vm",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Rdp,
            Host = "vm.prod",
            CredentialMode = CredentialBindingMode.Inherit,
        };

        var profile = new InheritanceResolver().Resolve(leaf, new Dictionary<Guid, ConnectionNode>
        {
            [root.Id] = root,
            [closest.Id] = closest,
            [leaf.Id] = leaf,
        });

        Assert.Equal(closest.CredentialId, profile.CredentialId);
        Assert.Null(profile.Username);
        Assert.Null(profile.RdpDomain);
    }

    [Fact]
    public void Resolve_LegacyClosestCredentialWithoutIdentity_DoesNotInheritDistantUsername()
    {
        var root = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "all",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
            Username = "root-user",
        };
        var closest = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = root.Id,
            Name = "imported-prod",
            Kind = NodeKind.Folder,
            CredentialMode = null,
            CredentialId = Guid.NewGuid(),
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = closest.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
        };

        var profile = new InheritanceResolver().Resolve(leaf, new Dictionary<Guid, ConnectionNode>
        {
            [root.Id] = root,
            [closest.Id] = closest,
            [leaf.Id] = leaf,
        });

        Assert.Equal(closest.CredentialId, profile.CredentialId);
        Assert.Null(profile.Username);
    }

    [Fact]
    public void Resolve_LeafUsernameOverridesClosestFolderCredentialIdentity()
    {
        var root = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "all",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
            Username = "root-user",
        };
        var closest = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = root.Id,
            Name = "prod",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = closest.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
            Username = "leaf-user",
            CredentialMode = CredentialBindingMode.Inherit,
        };

        var profile = new InheritanceResolver().Resolve(leaf, new Dictionary<Guid, ConnectionNode>
        {
            [root.Id] = root,
            [closest.Id] = closest,
            [leaf.Id] = leaf,
        });

        Assert.Equal(closest.CredentialId, profile.CredentialId);
        Assert.Equal("leaf-user", profile.Username);
    }

    [Fact]
    public void Resolve_CredentialModeNone_StillInheritsUsernameForPrompt()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
            Username = "deploy",
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
            CredentialMode = CredentialBindingMode.None,
        };

        var profile = new InheritanceResolver().Resolve(node, new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        });

        Assert.Null(profile.CredentialId);
        Assert.Equal("deploy", profile.Username);
    }

    [Fact]
    public void Resolve_LegacyNullModeWithCredentialId_TreatsNodeAsSavedCredential()
    {
        var childCredId = Guid.NewGuid();
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "web-1.prod",
            CredentialMode = null,
            CredentialId = childCredId,
        };

        var profile = new InheritanceResolver().Resolve(node, new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        });

        Assert.Equal(childCredId, profile.CredentialId);
    }

    [Theory]
    [InlineData(ProtocolType.Ssh)]
    [InlineData(ProtocolType.Rdp)]
    public void Resolve_InlinePassword_OnChildSuppressesInheritedSavedCredential(ProtocolType protocol)
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Kind = NodeKind.Folder,
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = Guid.NewGuid(),
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "web-1",
            Kind = NodeKind.Connection,
            Protocol = protocol,
            Host = "web-1.prod",
            UseInlinePassword = true,
        };

        var profile = new InheritanceResolver().Resolve(node, new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        });

        Assert.True(profile.UseInlinePassword);
        Assert.Null(profile.CredentialId);
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

    [Theory]
    [InlineData(ProtocolType.Http, 80)]
    [InlineData(ProtocolType.Https, 443)]
    public void Resolve_DefaultsWebPortFromProtocol(ProtocolType protocol, int expectedPort)
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "fw-gui",
            Kind = NodeKind.Connection,
            Protocol = protocol,
            Host = "fw.example.com",
        };

        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(expectedPort, profile.Port);
    }

    [Fact]
    public void Resolve_Serial_DefaultsToPuttySerialSettings()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "console",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Serial,
            Host = "COM3",
        };

        var profile = new InheritanceResolver().Resolve(node, new Dictionary<Guid, ConnectionNode>
        {
            [node.Id] = node,
        });

        Assert.Equal(ProtocolType.Serial, profile.Protocol);
        Assert.Equal("COM3", profile.Host);
        Assert.Equal(0, profile.Port);
        Assert.Equal(SerialDefaults.BaudRate, profile.SerialBaudRate);
        Assert.Equal(SerialDefaults.DataBits, profile.SerialDataBits);
        Assert.Equal(SerialDefaults.StopBits, profile.SerialStopBits);
        Assert.Equal(SerialDefaults.Parity, profile.SerialParity);
        Assert.Equal(SerialDefaults.FlowControl, profile.SerialFlowControl);
    }

    [Fact]
    public void Resolve_Serial_InheritsSerialSettingsAndDropsCredentials()
    {
        var credentialId = Guid.NewGuid();
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "serial-folder",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Serial,
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
            SerialBaudRate = 115200,
            SerialDataBits = 7,
            SerialStopBits = SerialStopBitsMode.Two,
            SerialParity = SerialParityMode.Even,
            SerialFlowControl = SerialFlowControlMode.RtsCts,
            CredentialId = credentialId,
            Username = "ignored",
            SshKeyFileName = "key.pem",
            SshKnownHostFingerprint = "SHA256:ignored",
            SshAutoSudo = true,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "switch-console",
            Kind = NodeKind.Connection,
            Host = "COM7",
        };

        var profile = new InheritanceResolver().Resolve(node, new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        });

        Assert.Equal(ProtocolType.Serial, profile.Protocol);
        Assert.Equal(115200, profile.SerialBaudRate);
        Assert.Equal(7, profile.SerialDataBits);
        Assert.Equal(SerialStopBitsMode.Two, profile.SerialStopBits);
        Assert.Equal(SerialParityMode.Even, profile.SerialParity);
        Assert.Equal(SerialFlowControlMode.RtsCts, profile.SerialFlowControl);
        Assert.Null(profile.Username);
        Assert.Null(profile.CredentialId);
        Assert.Null(profile.SshKeyFileName);
        Assert.Null(profile.SshKnownHostFingerprint);
        Assert.False(profile.SshAutoSudo);
        Assert.False(profile.TunnelEnabled);
        Assert.Null(profile.TunnelConfigId);
    }

    // Repro for the reported bug: an appliance-GUI web connection (own Port unset) dropped into an
    // mRemoteNG-imported RDP folder that carries Protocol=Rdp + Port=3389. The web connection must
    // NOT inherit the folder's RDP port — it should fall back to the protocol default (443/80),
    // otherwise the embedded browser navigates to https://host:3389 and fails (connection refused).
    [Theory]
    [InlineData(ProtocolType.Http, 80)]
    [InlineData(ProtocolType.Https, 443)]
    public void Resolve_WebConnection_DoesNotInheritAncestorFolderPort(ProtocolType protocol, int expectedPort)
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "imported-rdp-folder",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Rdp,
            Port = 3389,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "wazuh-gui",
            Kind = NodeKind.Connection,
            Protocol = protocol,
            Host = "10.1.2.59",
            // Port deliberately unset — the leaf's own port is null; only the folder carries 3389.
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(expectedPort, profile.Port);
    }

    // A web connection's OWN port (the editor folds a "host:port" address into ConnectionNode.Port)
    // must still be honored — only inherited folder ports are dropped for web.
    [Fact]
    public void Resolve_WebConnection_HonorsOwnExplicitPort()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "imported-rdp-folder",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Rdp,
            Port = 3389,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "appliance-gui",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Https,
            Host = "10.1.2.59",
            Port = 8443,
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(8443, profile.Port);
    }

    // The cross-protocol port-inheritance guard is general, not web-only: a connection whose own
    // Port is unset must not inherit a port that an ancestor folder configured for a DIFFERENT
    // protocol. An SSH host in an mRemoteNG-imported RDP folder (Protocol=Rdp, Port=3389) would
    // otherwise try to SSH on 3389; it must fall back to SSH's default 22 — and symmetrically.
    [Theory]
    [InlineData(ProtocolType.Ssh, ProtocolType.Rdp, 3389, 22)]
    [InlineData(ProtocolType.Rdp, ProtocolType.Ssh, 22, 3389)]
    public void Resolve_DoesNotInheritPortConfiguredForADifferentProtocol(
        ProtocolType leafProtocol, ProtocolType folderProtocol, int folderPort, int expectedPort)
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "imported-folder",
            Kind = NodeKind.Folder,
            Protocol = folderProtocol,
            Port = folderPort,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "host",
            Kind = NodeKind.Connection,
            Protocol = leafProtocol,
            Host = "10.1.2.59",
            // Port deliberately unset — only the mismatched-protocol folder carries one.
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(expectedPort, profile.Port);
    }

    // The guard keys off the port owner's GOVERNING protocol, not just its own field: a folder that
    // pins a Port but INHERITS its protocol from its own parent (the shape mRemoteNG import produces
    // for an InheritProtocol container with an explicit Port) must still be caught. Here the mid
    // folder has no protocol of its own but resolves to Rdp via the root, so its 3389 must NOT reach
    // the SSH leaf — it falls back to SSH's default 22.
    [Fact]
    public void Resolve_DoesNotInheritPort_WhenPortOwnerInheritsADifferentProtocol()
    {
        var root = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "rdp-root",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Rdp,
        };
        var mid = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = root.Id,
            Name = "pins-port-inherits-protocol",
            Kind = NodeKind.Folder,
            // No Protocol of its own — inherits Rdp from root — but pins a port.
            Port = 3389,
        };
        var leaf = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = mid.Id,
            Name = "ssh-host",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "10.1.2.59",
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [root.Id] = root,
            [mid.Id] = mid,
            [leaf.Id] = leaf,
        };

        var profile = new InheritanceResolver().Resolve(leaf, nodes);

        Assert.Equal(22, profile.Port);
    }

    // The guard must not over-block: a folder that carries BOTH its protocol AND a non-default port
    // still passes that port down to a child of the SAME protocol that doesn't set its own.
    [Fact]
    public void Resolve_InheritsCustomPortFromSameProtocolFolder()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "rdp-farm",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Rdp,
            Port = 3390,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "vm",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Rdp,
            Host = "vm.example.com",
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(3390, profile.Port);
    }

    // A connection that INHERITS its protocol from a folder (own Protocol unset) still inherits a
    // port the same folder configures — the guard keys off the port owner's protocol, which here
    // equals the resolved protocol. Exercises the protocol-inheriting-leaf path (the guard reads
    // the resolved protocol, not the leaf's own).
    [Fact]
    public void Resolve_InheritsPortWhenProtocolIsAlsoInherited()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "https-appliances",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Https,
            Port = 8443,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "fw",
            Kind = NodeKind.Connection,
            Host = "fw.example.com",
            // Protocol deliberately unset — inherited from the folder.
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(ProtocolType.Https, profile.Protocol);
        Assert.Equal(8443, profile.Port);
    }

    [Fact]
    public void Resolve_HttpIgnoreCertErrors_DefaultsFalseWhenUnset()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "fw-gui",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Https,
            Host = "fw.example.com",
        };

        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.False(profile.HttpIgnoreCertErrors);
    }

    [Fact]
    public void Resolve_HttpIgnoreCertErrors_IsLeafOnly_NotInheritedFromParentFolder()
    {
        // Leaf-only (like UseInlinePassword): a folder value must NOT be inherited, so an unrelated edit
        // of a child (whose 2-state checkbox can't express "inherit") can't silently sever it.
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "appliances",
            Kind = NodeKind.Folder,
            HttpIgnoreCertErrors = true,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "fw-gui",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Https,
            Host = "fw.example.com",
            // own value unset (null) -> resolves false, regardless of the folder's true
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.False(profile.HttpIgnoreCertErrors);
    }

    [Fact]
    public void Resolve_HttpIgnoreCertErrors_UsesOwnLeafValue()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "fw-gui",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Https,
            Host = "fw.example.com",
            HttpIgnoreCertErrors = true,
        };

        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.True(profile.HttpIgnoreCertErrors);
    }

    [Theory]
    [InlineData(ProtocolType.Http)]
    [InlineData(ProtocolType.Https)]
    public void Resolve_WebProtocol_DropsInheritedAuthMaterial(ProtocolType webProtocol)
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "appliances",
            Kind = NodeKind.Folder,
            CredentialId = Guid.NewGuid(),
            CredentialMode = CredentialBindingMode.Saved,
            Username = "admin",
            SshKeyFileName = "shared-admin-key",
            SshKnownHostFingerprint = "SHA256:inherited-pin",
            SshAutoSudo = true,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "fw-gui",
            Kind = NodeKind.Connection,
            Protocol = webProtocol,
            Host = "fw.example.com",
        };

        var nodes = new Dictionary<Guid, ConnectionNode>
        {
            [folder.Id] = folder,
            [node.Id] = node,
        };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        // A credential-less web node must not carry the parent folder's credential identity or
        // SSH key metadata into the resolved web profile.
        Assert.Null(profile.CredentialId);
        Assert.Null(profile.Username);
        Assert.Null(profile.SshKeyFileName);
        Assert.Null(profile.SshKnownHostFingerprint);
        Assert.False(profile.SshAutoSudo);
        Assert.False(profile.UseInlinePassword);
    }

    [Theory]
    [InlineData(ProtocolType.Http)]
    [InlineData(ProtocolType.Https)]
    public void Resolve_WebProtocol_DropsOwnAuthMaterial(ProtocolType webProtocol)
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "fw-gui",
            Kind = NodeKind.Connection,
            Protocol = webProtocol,
            Host = "fw.example.com",
            CredentialId = Guid.NewGuid(),
            CredentialMode = CredentialBindingMode.Saved,
            Username = "admin",
            UseInlinePassword = true,
            SshKeyFileName = "stale-admin-key",
            SshKnownHostFingerprint = "SHA256:stale-pin",
            SshAutoSudo = true,
        };

        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };
        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Null(profile.CredentialId);
        Assert.Null(profile.Username);
        Assert.Null(profile.SshKeyFileName);
        Assert.Null(profile.SshKnownHostFingerprint);
        Assert.False(profile.SshAutoSudo);
        Assert.False(profile.UseInlinePassword);
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

    [Fact]
    public void Resolve_RdpColorDepth_InheritsFromParentFolder()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "rdp-folder",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Rdp,
            RdpColorDepth = 24,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "vm",
            Kind = NodeKind.Connection,
            Host = "vm.example.com",
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [folder.Id] = folder, [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(24, profile.RdpColorDepth);
    }

    [Fact]
    public void Resolve_RdpDefaults_AppliedWhenNothingSetInChain()
    {
        // A bare RDP node with no RDP-specific fields set should still produce a usable
        // profile with mstsc-style defaults: 32-bit color, clipboard on, auto-reconnect on,
        // connection speed = auto-detect, gateway disabled, server authentication = warn.
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "bare-rdp",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Rdp,
            Host = "host",
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(32, profile.RdpColorDepth);
        Assert.True(profile.RdpRedirectClipboard);
        Assert.True(profile.RdpAutoReconnect);
        Assert.Equal(7, profile.RdpConnectionSpeed);
        Assert.Equal(0, profile.RdpGatewayUsageMethod);
        Assert.Equal(2, profile.RdpServerAuthentication);
        Assert.Equal(2, profile.RdpKeyboardHookMode); // full-screen-only
        Assert.True(profile.RdpDesktopBackground);
        Assert.True(profile.RdpVisualStyles);
        Assert.True(profile.RdpBitmapCaching);
        Assert.True(profile.RdpGatewayBypassLocal);
        Assert.Equal(string.Empty, profile.RdpRedirectDrives);
        Assert.False(profile.RdpUseExternalClient); // embedded ActiveX is the default; opt-in routes through mstsc.exe.
    }

    [Fact]
    public void Resolve_RdpFullScreenTrue_OverridesInheritedFixedScreenSize()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "rdp-folder",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Rdp,
            RdpScreenSize = "1024x768",
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "vm",
            Kind = NodeKind.Connection,
            Host = "vm.example.com",
            RdpFullScreen = true,
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [folder.Id] = folder, [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(RdpScreenSizes.FullConnectionContent, profile.RdpScreenSize);
    }

    [Fact]
    public void Resolve_RdpScreenSize_OverridesSameNodeLegacyFullScreenFlag()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "vm",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Rdp,
            Host = "vm.example.com",
            RdpScreenSize = "1024x768",
            RdpFullScreen = true,
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal("1024x768", profile.RdpScreenSize);
    }

    [Fact]
    public void Resolve_RdpRedirectClipboardFalseOnChild_OverridesParentTrue()
    {
        // ??= walks ancestors child → root, so a child's explicit `false` for a bool? must
        // win over a parent's `true`. This regression-checks the null-coalesce semantics
        // for bool? (not `if (!current) current = ancestor` which would skip falses).
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "rdp-folder",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Rdp,
            RdpRedirectClipboard = true,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "no-clipboard",
            Kind = NodeKind.Connection,
            Host = "host",
            RdpRedirectClipboard = false,
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [folder.Id] = folder, [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.False(profile.RdpRedirectClipboard);
    }

    [Fact]
    public void Resolve_RdpGatewayCredentialId_InheritsFromAncestor()
    {
        var credId = Guid.NewGuid();
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "behind-gw",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Rdp,
            RdpGatewayUsageMethod = 1,
            RdpGatewayHostname = "gw.example.com",
            RdpGatewayCredentialId = credId,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "behind-gw-vm",
            Kind = NodeKind.Connection,
            Host = "vm",
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [folder.Id] = folder, [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.Equal(1, profile.RdpGatewayUsageMethod);
        Assert.Equal("gw.example.com", profile.RdpGatewayHostname);
        Assert.Equal(credId, profile.RdpGatewayCredentialId);
    }

    [Fact]
    public void Resolve_SshAutoSudo_DefaultsFalseWhenUnset()
    {
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "plain-ssh",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Ssh,
            Host = "host",
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.False(profile.SshAutoSudo);
    }

    [Fact]
    public void Resolve_SshAutoSudo_InheritsFromParentFolder()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "elevated",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Ssh,
            SshAutoSudo = true,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "box",
            Kind = NodeKind.Connection,
            Host = "box.example.com",
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [folder.Id] = folder, [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.True(profile.SshAutoSudo);
    }

    [Fact]
    public void Resolve_SshAutoSudoFalseOnChild_OverridesParentTrue()
    {
        var folder = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Name = "elevated",
            Kind = NodeKind.Folder,
            Protocol = ProtocolType.Ssh,
            SshAutoSudo = true,
        };
        var node = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            ParentId = folder.Id,
            Name = "no-sudo",
            Kind = NodeKind.Connection,
            Host = "host",
            SshAutoSudo = false,
        };
        var nodes = new Dictionary<Guid, ConnectionNode> { [folder.Id] = folder, [node.Id] = node };

        var profile = new InheritanceResolver().Resolve(node, nodes);

        Assert.False(profile.SshAutoSudo);
    }
}
