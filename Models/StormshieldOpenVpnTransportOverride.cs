namespace Wormhole.Models;

/// <summary>
/// Optional transport override for the OpenVPN remotes inside a Stormshield profile.
/// Auto preserves the firewall-provided profile order and protocols.
/// </summary>
public enum StormshieldOpenVpnTransportOverride
{
    Auto = 0,
    ForceTcp = 1,
    ForceUdp = 2,
}
