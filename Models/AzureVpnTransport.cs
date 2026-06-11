namespace Wormhole.Models;

/// <summary>
/// Transport for the Azure P2S OpenVPN data plane, mirroring the
/// <c>&lt;protocolconfig&gt;&lt;sslprotocolConfig&gt;&lt;transportprotocol&gt;</c> element of
/// <c>azurevpnconfig.xml</c>. Azure gateways default to TCP/443; UDP is offered on gateways
/// provisioned with the UDP listener enabled.
/// </summary>
public enum AzureVpnTransport
{
    Tcp = 0,
    Udp = 1,
}
