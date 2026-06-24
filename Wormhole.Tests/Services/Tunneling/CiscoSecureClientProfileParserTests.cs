using System;
using Wormhole.Services.Tunneling.CiscoSecureClient;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class CiscoSecureClientProfileParserTests
{
    private const string ProvidedProfileXml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
            <ClientInitialization>
                <AllowManualHostInput>true</AllowManualHostInput>
            </ClientInitialization>
            <ServerList>
                <HostEntry>
                    <HostName>Example.Profile</HostName>
                    <HostAddress>vpn.example.com</HostAddress>
                    <UserGroup>Example.Profile</UserGroup>
                </HostEntry>
            </ServerList>
        </AnyConnectProfile>
        """;

    [Fact]
    public void Parse_ProvidedSoapNamespacedProfile_ExtractsGatewayGroupAndName()
    {
        var result = CiscoSecureClientProfileParser.Parse(ProvidedProfileXml);

        Assert.Equal("Example.Profile", result.ProfileName);
        Assert.Equal("vpn.example.com", result.Settings.Host);
        Assert.Equal(443, result.Settings.Port);
        Assert.Equal("Example.Profile", result.Settings.Group);
        Assert.Equal(string.Empty, result.Settings.Username);
        Assert.Equal(string.Empty, result.Settings.Password);
        Assert.Null(result.Settings.TotpSecret);
        Assert.Null(result.Settings.SecondaryPassword);
    }

    [Fact]
    public void Parse_HostAddressWithPort_UsesExplicitPort()
    {
        var xml = """
            <AnyConnectProfile>
              <ServerList>
                <HostEntry>
                  <HostName>Contractors</HostName>
                  <HostAddress>vpn.example.com:8443</HostAddress>
                  <UserGroup>Contractors</UserGroup>
                </HostEntry>
              </ServerList>
            </AnyConnectProfile>
            """;

        var result = CiscoSecureClientProfileParser.Parse(xml);

        Assert.Equal("vpn.example.com", result.Settings.Host);
        Assert.Equal(8443, result.Settings.Port);
        Assert.Equal("Contractors", result.Settings.Group);
        Assert.Equal("Contractors", result.ProfileName);
    }

    [Fact]
    public void Parse_MissingHostAddress_UsesHostNameAsGateway()
    {
        var xml = """
            <AnyConnectProfile>
              <ServerList>
                <HostEntry>
                  <HostName>vpn.example.com</HostName>
                  <UserGroup>Employees</UserGroup>
                </HostEntry>
              </ServerList>
            </AnyConnectProfile>
            """;

        var result = CiscoSecureClientProfileParser.Parse(xml);

        Assert.Equal("vpn.example.com", result.Settings.Host);
        Assert.Equal(443, result.Settings.Port);
        Assert.Equal("Employees", result.Settings.Group);
        Assert.Equal("vpn.example.com", result.ProfileName);
    }

    [Fact]
    public void Parse_MultipleEntries_UsesFirstEntryWithHostAddress()
    {
        var xml = """
            <AnyConnectProfile>
              <ServerList>
                <HostEntry><UserGroup>No gateway</UserGroup></HostEntry>
                <HostEntry>
                  <HostName>First usable</HostName>
                  <HostAddress>first.example.com</HostAddress>
                </HostEntry>
                <HostEntry>
                  <HostName>Second usable</HostName>
                  <HostAddress>second.example.com</HostAddress>
                </HostEntry>
              </ServerList>
            </AnyConnectProfile>
            """;

        var result = CiscoSecureClientProfileParser.Parse(xml);

        Assert.Equal("first.example.com", result.Settings.Host);
        Assert.Equal("First usable", result.ProfileName);
    }

    [Fact]
    public void Parse_NonProfileXml_IsRejected()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => CiscoSecureClientProfileParser.Parse("<html></html>"));
        Assert.Contains("AnyConnectProfile", ex.Message);
    }

    [Fact]
    public void Parse_MissingGatewayFields_IsRejected()
    {
        var xml = """
            <AnyConnectProfile>
              <ServerList><HostEntry><UserGroup>No address</UserGroup></HostEntry></ServerList>
            </AnyConnectProfile>
            """;

        var ex = Assert.Throws<InvalidOperationException>(() => CiscoSecureClientProfileParser.Parse(xml));
        Assert.Contains("HostAddress or HostName", ex.Message);
    }

    [Fact]
    public void Parse_NonHttpsUrl_IsRejected()
    {
        var xml = """
            <AnyConnectProfile>
              <ServerList><HostEntry><HostAddress>http://vpn.example.com</HostAddress></HostEntry></ServerList>
            </AnyConnectProfile>
            """;

        var ex = Assert.Throws<InvalidOperationException>(() => CiscoSecureClientProfileParser.Parse(xml));
        Assert.Contains("https", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_InvalidPort_IsRejected()
    {
        var xml = """
            <AnyConnectProfile>
              <ServerList><HostEntry><HostAddress>vpn.example.com:notaport</HostAddress></HostEntry></ServerList>
            </AnyConnectProfile>
            """;

        var ex = Assert.Throws<InvalidOperationException>(() => CiscoSecureClientProfileParser.Parse(xml));
        Assert.Contains("port", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
