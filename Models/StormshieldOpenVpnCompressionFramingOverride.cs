namespace Wormhole.Models;

/// <summary>
/// Optional compatibility override for legacy OpenVPN no-compression framing.
/// </summary>
public enum StormshieldOpenVpnCompressionFramingOverride
{
    Auto = 0,
    ForceLegacyStub = 1,
}
