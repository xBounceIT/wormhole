using System.Text;
using Wormhole.Services.MRemoteNg;
using Xunit;

namespace Wormhole.Tests.Services;

public class MRemoteNgXmlReaderTests
{
    private const string EmptyConnections = """
        <?xml version="1.0" encoding="utf-8"?>
        <mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connessioni" Export="false"
            EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="10000"
            FullFileEncryption="false" Protected="ABCD" ConfVersion="2.7">
        </mrng:Connections>
        """;

    private const string NestedTree = """
        <?xml version="1.0" encoding="utf-8"?>
        <mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Root" Export="false"
            EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="10000"
            FullFileEncryption="false" Protected="ABCD" ConfVersion="2.7">
            <Node Name="Folder1" Type="Container" Protocol="RDP">
                <Node Name="Leaf-SSH" Type="Connection" Protocol="SSH2" Hostname="ssh.example.com" Port="22" Username="alice" Password="" />
                <Node Name="Inner" Type="Container">
                    <Node Name="Leaf-RDP" Type="Connection" Protocol="RDP" Hostname="rdp.example.com" Port="3389" Username="bob" Domain="ACME" Password="encrypted" Resolution="1920x1080" />
                </Node>
            </Node>
            <Node Name="Leaf-VNC" Type="Connection" Protocol="VNC" Hostname="vnc.example.com" />
        </mrng:Connections>
        """;

    [Fact]
    public void Parse_ReadsRootAttributes()
    {
        using var stream = ToStream(EmptyConnections);

        var root = MRemoteNgXmlReader.Parse(stream, out var roots);

        Assert.Equal("2.7", root.ConfVersion);
        Assert.Equal("AES", root.EncryptionEngine);
        Assert.Equal("GCM", root.BlockCipherMode);
        Assert.Equal("ABCD", root.Protected);
        Assert.Equal(10000, root.KdfIterations);
        Assert.False(root.FullFileEncryption);
        Assert.Empty(roots);
    }

    [Fact]
    public void Parse_BuildsNestedTreeInDocumentOrder()
    {
        using var stream = ToStream(NestedTree);

        MRemoteNgXmlReader.Parse(stream, out var roots);

        // Top level: Folder1 (Container) and Leaf-VNC (Connection).
        Assert.Equal(2, roots.Count);
        Assert.Equal("Folder1", roots[0].Name);
        Assert.Equal("Container", roots[0].Type);
        Assert.Equal("Leaf-VNC", roots[1].Name);
        Assert.Equal("Connection", roots[1].Type);

        var folder1 = roots[0];
        Assert.Equal(2, folder1.Children.Count);
        Assert.Equal("Leaf-SSH", folder1.Children[0].Name);
        Assert.Equal("SSH2", folder1.Children[0].Protocol);
        Assert.Equal("ssh.example.com", folder1.Children[0].Hostname);
        Assert.Equal("22", folder1.Children[0].Port);
        Assert.Equal("alice", folder1.Children[0].Username);

        var inner = folder1.Children[1];
        Assert.Equal("Container", inner.Type);
        var leafRdp = Assert.Single(inner.Children);
        Assert.Equal("RDP", leafRdp.Protocol);
        Assert.Equal("ACME", leafRdp.Domain);
        Assert.Equal("encrypted", leafRdp.PasswordCipher);
        Assert.Equal("1920x1080", leafRdp.Resolution);
    }

    [Fact]
    public void Parse_PreservesUnknownProtocolForCallerToSkip()
    {
        using var stream = ToStream(NestedTree);

        MRemoteNgXmlReader.Parse(stream, out var roots);

        // VNC leaf is preserved verbatim — the caller (import service) decides to skip it.
        Assert.Equal("VNC", roots[1].Protocol);
    }

    [Fact]
    public void Parse_ReportsWhetherAnyNodeHasPasswordPayload()
    {
        using var emptyStream = ToStream(EmptyConnections);
        MRemoteNgXmlReader.Parse(emptyStream, out _, out var emptyHasPasswordPayload);

        using var nestedStream = ToStream(NestedTree);
        MRemoteNgXmlReader.Parse(nestedStream, out _, out var nestedHasPasswordPayload);

        Assert.False(emptyHasPasswordPayload);
        Assert.True(nestedHasPasswordPayload);
    }

    [Fact]
    public void Parse_RejectsNonMRemoteNgRoot()
    {
        using var stream = ToStream("<?xml version=\"1.0\"?><Wrong/>");

        Assert.Throws<InvalidDataException>(() => MRemoteNgXmlReader.Parse(stream, out _));
    }

    [Fact]
    public void Parse_RejectsMalformedXml()
    {
        using var stream = ToStream("<not <valid xml");

        Assert.Throws<InvalidDataException>(() => MRemoteNgXmlReader.Parse(stream, out _));
    }

    [Fact]
    public void Parse_DefaultsKdfIterationsWhenAttributeMissing()
    {
        const string noKdf = """
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" Protected="X" ConfVersion="2.6"></mrng:Connections>
            """;
        using var stream = ToStream(noKdf);

        var root = MRemoteNgXmlReader.Parse(stream, out _);

        // 1000 was the historical mRemoteNG default before KdfIterations was added.
        Assert.Equal(1000, root.KdfIterations);
    }

    [Fact]
    public void Parse_ReadsInheritAttributes()
    {
        const string inheritXml = """
            <?xml version="1.0" encoding="utf-8"?>
            <mrng:Connections xmlns:mrng="http://mremoteng.org" EncryptionEngine="AES"
                BlockCipherMode="GCM" KdfIterations="1000" Protected="X" ConfVersion="2.6">
                <Node Name="N" Type="Connection" Protocol="RDP" Hostname="h"
                    InheritUsername="true" InheritDomain="false" InheritPassword="true" />
            </mrng:Connections>
            """;
        using var stream = ToStream(inheritXml);

        MRemoteNgXmlReader.Parse(stream, out var roots);
        var leaf = Assert.Single(roots);

        Assert.True(leaf.InheritUsername);
        Assert.False(leaf.InheritDomain);
        Assert.True(leaf.InheritPassword);
    }

    private static MemoryStream ToStream(string xml) => new(Encoding.UTF8.GetBytes(xml));
}
