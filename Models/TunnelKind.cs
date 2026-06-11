namespace Wormhole.Models;

public enum TunnelKind
{
    WireGuard = 0,
    OpenVpn = 1,
    Fortinet = 2,
    Watchguard = 3,
    Stormshield = 4,
    AzureVpn = 5,
    CiscoSecureClient = 6,
}
