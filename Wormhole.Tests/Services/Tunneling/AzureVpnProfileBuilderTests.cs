using System;
using System.Collections.Generic;
using System.Linq;
using Wormhole.Models;
using Wormhole.Services.Tunneling.AzureVpn;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class AzureVpnProfileBuilderTests
{
    private static AzureVpnSettings BaseSettings() => new()
    {
        Servers = new List<string> { "azuregateway-0000.vpn.azure.com" },
        Protocol = AzureVpnTransport.Tcp,
        TenantId = "11111111-2222-3333-4444-555555555555",
        Audience = "c632b3df-fb67-4d84-bdcf-b95ad541b5c8",
    };

    private static string ValidServerSecret() => string.Concat(Enumerable.Repeat("0123456789abcdef", 32)); // 512 hex

    [Fact]
    public void Build_EmitsCoreDirectives()
    {
        var profile = AzureVpnProfileBuilder.Build(BaseSettings());

        Assert.Contains("client\n", profile);
        Assert.Contains("dev tun\n", profile);
        Assert.Contains("proto tcp-client\n", profile);
        Assert.Contains("remote azuregateway-0000.vpn.azure.com 443\n", profile);
        Assert.Contains("remote-cert-tls server\n", profile);
        // No hostname pin: the Entra profile validates the gateway by CA chain, and its cert
        // subject (a GatewayID name) isn't the connection FQDN, so pinning it would break auth/HA.
        Assert.DoesNotContain("verify-x509-name", profile);
        Assert.Contains("auth SHA256\n", profile);
        Assert.Contains("cipher AES-256-GCM\n", profile);
        Assert.Contains("tls-version-min 1.2\n", profile);
        // The provider supplies username AzureAD / password = access token at connect time; the
        // profile must declare auth-user-pass or the sidecar's creds go unused.
        Assert.Contains("auth-user-pass\n", profile);
        // No serversecret → no tls-auth block.
        Assert.DoesNotContain("tls-auth", profile);
    }

    [Fact]
    public void Build_DefaultCa_IsDigiCertGlobalRootG2()
    {
        var profile = AzureVpnProfileBuilder.Build(BaseSettings());
        Assert.Contains("<ca>\n-----BEGIN CERTIFICATE-----", profile);
        Assert.Contains("-----END CERTIFICATE-----\n</ca>", profile);
        // First payload line of the DigiCert Global Root G2 PEM — guards against the constant
        // being swapped for a different cert.
        Assert.Contains("MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh", profile);
    }

    [Fact]
    public void Build_UdpTransport_EmitsProtoUdp()
    {
        var settings = BaseSettings();
        settings.Protocol = AzureVpnTransport.Udp;
        Assert.Contains("proto udp\n", AzureVpnProfileBuilder.Build(settings));
    }

    [Fact]
    public void Build_MultiServer_EmitsAllRemotes_WithoutHostnamePin()
    {
        var settings = BaseSettings();
        settings.Servers = new List<string> { "primary.vpn.azure.com", "secondary.vpn.azure.com" };

        var profile = AzureVpnProfileBuilder.Build(settings);

        Assert.Contains("remote primary.vpn.azure.com 443\n", profile);
        Assert.Contains("remote secondary.vpn.azure.com 443\n", profile);
        // No verify-x509-name pin — pinning the primary FQDN would reject failover to the secondary
        // gateway (different cert subject), so HA relies on the shared CA chain instead.
        Assert.DoesNotContain("verify-x509-name", profile);
    }

    [Fact]
    public void Build_ServerSecret_BecomesInlineTlsAuthKey()
    {
        var settings = BaseSettings();
        settings.ServerSecretHex = ValidServerSecret();

        var profile = AzureVpnProfileBuilder.Build(settings);

        Assert.Contains("key-direction 1\n", profile);
        Assert.Contains("<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n", profile);
        Assert.Contains("-----END OpenVPN Static key V1-----\n</tls-auth>\n", profile);
        // 512 hex chars → exactly 16 body lines of 32 chars.
        var body = profile.Split("-----BEGIN OpenVPN Static key V1-----\n")[1]
            .Split("\n-----END OpenVPN Static key V1-----")[0];
        var lines = body.Split('\n');
        Assert.Equal(16, lines.Length);
        Assert.All(lines, l => Assert.Equal(32, l.Length));
    }

    [Fact]
    public void Build_CustomCaPem_OverridesBundledRoot()
    {
        var settings = BaseSettings();
        settings.CaPem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----";

        var profile = AzureVpnProfileBuilder.Build(settings);

        Assert.Contains("<ca>\n-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n</ca>", profile);
        Assert.DoesNotContain("MIIDjjCCAnag", profile);
    }

    [Fact]
    public void Build_NoServers_Throws()
    {
        var settings = BaseSettings();
        settings.Servers = new List<string>();
        Assert.Throws<InvalidOperationException>(() => AzureVpnProfileBuilder.Build(settings));
    }

    [Theory]
    [InlineData("evil.com\nup /tmp/pwn")] // newline → directive injection
    [InlineData("evil.com remote2")]      // space → extra remote args
    [InlineData("evil\"quoted\"")]
    public void Build_HostileServerValue_IsRejected(string server)
    {
        var settings = BaseSettings();
        settings.Servers = new List<string> { server };
        Assert.Throws<InvalidOperationException>(() => AzureVpnProfileBuilder.Build(settings));
    }

    [Theory]
    [InlineData("deadbeef")]   // too short
    [InlineData("zz")]         // not hex
    public void Build_MalformedServerSecret_IsRejectedWithClearMessage(string secret)
    {
        var settings = BaseSettings();
        settings.ServerSecretHex = secret;
        var ex = Assert.Throws<InvalidOperationException>(() => AzureVpnProfileBuilder.Build(settings));
        Assert.Contains("512", ex.Message);
    }

    [Fact]
    public void Build_CaPemWithAngleBrackets_IsRejected()
    {
        // A literal </ca> in the PEM would close the inline block early and turn the rest of the
        // field into directives.
        var settings = BaseSettings();
        settings.CaPem = "-----BEGIN CERTIFICATE-----\n</ca>\nup /tmp/pwn\n<ca>\n-----END CERTIFICATE-----";
        Assert.Throws<InvalidOperationException>(() => AzureVpnProfileBuilder.Build(settings));
    }
}
