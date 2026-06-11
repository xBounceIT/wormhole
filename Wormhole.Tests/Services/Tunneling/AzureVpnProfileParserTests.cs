using System;
using Wormhole.Models;
using Wormhole.Services.Tunneling.AzureVpn;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class AzureVpnProfileParserTests
{
    // Shape of a real azurevpnconfig.xml as emitted by the Azure portal for an Entra-auth P2S
    // gateway (DataContractSerializer output, with the i: schema-instance prefix and nil
    // sentinels alongside populated siblings).
    private const string RealisticProfileXml = """
        <AzVpnProfile xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
          <any>true</any>
          <version>1</version>
          <name>contoso-p2s</name>
          <serverlist>
            <ServerEntry>
              <fqdn>azuregateway-0000-0000.vpn.azure.com</fqdn>
              <displayname>azuregateway-0000-0000.vpn.azure.com</displayname>
            </ServerEntry>
          </serverlist>
          <clientauth>
            <type>aad</type>
            <aad>
              <issuer>https://sts.windows.net/11111111-2222-3333-4444-555555555555/</issuer>
              <tenant>https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/</tenant>
              <audience>c632b3df-fb67-4d84-bdcf-b95ad541b5c8</audience>
              <cachesigninuser>true</cachesigninuser>
            </aad>
            <cert i:nil="true" />
          </clientauth>
          <protocolconfig>
            <sslprotocolConfig>
              <transportprotocol>tcp</transportprotocol>
            </sslprotocolConfig>
          </protocolconfig>
          <servervalidation>
            <serversecret>0123456789abcdef</serversecret>
            <cert>
              <hash>df3c24f9bfd666761b268073fe06d1cc8d4f82a4</hash>
            </cert>
          </servervalidation>
        </AzVpnProfile>
        """;

    [Fact]
    public void Parse_RealisticProfile_ExtractsAllFields()
    {
        var result = AzureVpnProfileParser.Parse(RealisticProfileXml);

        Assert.Equal("contoso-p2s", result.ProfileName);
        Assert.Equal("azuregateway-0000-0000.vpn.azure.com", Assert.Single(result.Settings.Servers));
        Assert.Equal(AzureVpnTransport.Tcp, result.Settings.Protocol);
        Assert.Equal("11111111-2222-3333-4444-555555555555", result.Settings.TenantId);
        Assert.Equal("c632b3df-fb67-4d84-bdcf-b95ad541b5c8", result.Settings.Audience);
        Assert.Equal("https://sts.windows.net/11111111-2222-3333-4444-555555555555/", result.Settings.Issuer);
        Assert.Null(result.Settings.ApplicationId);
        Assert.Equal("0123456789abcdef", result.Settings.ServerSecretHex);
        // No <applicationid> → the audience doubles as the OAuth client id.
        Assert.Equal("c632b3df-fb67-4d84-bdcf-b95ad541b5c8", result.Settings.ClientId);
    }

    [Fact]
    public void Parse_DefaultNamespacedProfile_StillParses()
    {
        // DataContractSerializer emits a default namespace on the root; element lookups must be
        // namespace-agnostic or every field comes back empty.
        var xml = """
            <AzVpnProfile xmlns="http://schemas.datacontract.org/2004/07/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
              <serverlist><ServerEntry><fqdn>gw.example.vpn.azure.com</fqdn></ServerEntry></serverlist>
              <clientauth><type>aad</type><aad>
                <tenant>https://login.microsoftonline.com/contoso.onmicrosoft.com</tenant>
                <audience>41b23e61-6c1e-4545-b367-cd054e0ed4b4</audience>
              </aad></clientauth>
            </AzVpnProfile>
            """;

        var result = AzureVpnProfileParser.Parse(xml);

        Assert.Equal("gw.example.vpn.azure.com", Assert.Single(result.Settings.Servers));
        Assert.Equal("contoso.onmicrosoft.com", result.Settings.TenantId);
        Assert.Equal("41b23e61-6c1e-4545-b367-cd054e0ed4b4", result.Settings.Audience);
        Assert.Null(result.ProfileName);
    }

    [Fact]
    public void Parse_MultiServerHaProfile_KeepsAllEntriesInOrder()
    {
        var xml = """
            <AzVpnProfile>
              <serverlist>
                <ServerEntry><fqdn>primary.vpn.azure.com</fqdn></ServerEntry>
                <ServerEntry><fqdn>secondary.vpn.azure.com</fqdn></ServerEntry>
              </serverlist>
              <clientauth><type>aad</type><aad>
                <tenant>https://login.microsoftonline.com/t/</tenant>
                <audience>aud</audience>
              </aad></clientauth>
            </AzVpnProfile>
            """;

        var result = AzureVpnProfileParser.Parse(xml);
        Assert.Collection(result.Settings.Servers,
            s => Assert.Equal("primary.vpn.azure.com", s),
            s => Assert.Equal("secondary.vpn.azure.com", s));
    }

    [Fact]
    public void Parse_UdpTransportAndApplicationId_AreRespected()
    {
        var xml = """
            <AzVpnProfile>
              <serverlist><ServerEntry><fqdn>gw.vpn.azure.com</fqdn></ServerEntry></serverlist>
              <clientauth><type>aad</type><aad>
                <tenant>https://login.microsoftonline.com/t/</tenant>
                <audience>aud-guid</audience>
                <applicationid>custom-app-guid</applicationid>
              </aad></clientauth>
              <protocolconfig><sslprotocolConfig><transportprotocol>udp</transportprotocol></sslprotocolConfig></protocolconfig>
            </AzVpnProfile>
            """;

        var result = AzureVpnProfileParser.Parse(xml);
        Assert.Equal(AzureVpnTransport.Udp, result.Settings.Protocol);
        Assert.Equal("custom-app-guid", result.Settings.ApplicationId);
        Assert.Equal("custom-app-guid", result.Settings.ClientId);
    }

    [Fact]
    public void Parse_CertificateAuthProfile_IsRejectedWithActionableMessage()
    {
        // Importing a cert-auth profile would create a tunnel that can never connect (no client
        // cert support in this provider) — reject at import time, naming the auth type.
        var xml = """
            <AzVpnProfile>
              <serverlist><ServerEntry><fqdn>gw.vpn.azure.com</fqdn></ServerEntry></serverlist>
              <clientauth><type>cert</type></clientauth>
            </AzVpnProfile>
            """;

        var ex = Assert.Throws<InvalidOperationException>(() => AzureVpnProfileParser.Parse(xml));
        Assert.Contains("cert", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Entra", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_NonProfileXml_IsRejected()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => AzureVpnProfileParser.Parse("<html></html>"));
        Assert.Contains("AzVpnProfile", ex.Message);
    }

    [Fact]
    public void Parse_NotXml_IsRejected()
    {
        Assert.Throws<InvalidOperationException>(() => AzureVpnProfileParser.Parse("not xml at all"));
    }

    [Fact]
    public void Parse_MissingServers_IsRejected()
    {
        var xml = """
            <AzVpnProfile>
              <serverlist></serverlist>
              <clientauth><type>aad</type><aad>
                <tenant>https://login.microsoftonline.com/t/</tenant>
                <audience>aud</audience>
              </aad></clientauth>
            </AzVpnProfile>
            """;
        var ex = Assert.Throws<InvalidOperationException>(() => AzureVpnProfileParser.Parse(xml));
        Assert.Contains("server", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_NilServerSecret_TreatedAsAbsent()
    {
        // DataContractSerializer emits <serversecret i:nil="true"/> when the gateway has no
        // tls-auth key; reading it as an empty string would later fail the 512-hex check.
        var xml = """
            <AzVpnProfile xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
              <serverlist><ServerEntry><fqdn>gw.vpn.azure.com</fqdn></ServerEntry></serverlist>
              <clientauth><type>aad</type><aad>
                <tenant>https://login.microsoftonline.com/t/</tenant>
                <audience>aud</audience>
              </aad></clientauth>
              <servervalidation><serversecret i:nil="true" /></servervalidation>
            </AzVpnProfile>
            """;

        var result = AzureVpnProfileParser.Parse(xml);
        Assert.Null(result.Settings.ServerSecretHex);
    }

    [Theory]
    [InlineData("https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/", "11111111-2222-3333-4444-555555555555")]
    [InlineData("https://login.microsoftonline.com/contoso.onmicrosoft.com", "contoso.onmicrosoft.com")]
    [InlineData("11111111-2222-3333-4444-555555555555", "11111111-2222-3333-4444-555555555555")]
    public void ExtractTenantId_HandlesUrlAndBareForms(string input, string expected)
    {
        Assert.Equal(expected, AzureVpnProfileParser.ExtractTenantId(input));
    }
}
