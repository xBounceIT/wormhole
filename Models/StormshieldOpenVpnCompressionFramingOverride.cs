namespace Wormhole.Models;

/// <summary>
/// Compatibility policy for OpenVPN compression/framing directives.
/// </summary>
public enum StormshieldOpenVpnCompressionFramingOverride
{
    /// <summary>Leave the firewall-provided profile directives unchanged.</summary>
    PreserveProfile = 0,

    /// <summary>Add the legacy no-compression framing marker when the profile has no compression framing directive.</summary>
    ForceLegacyStub = 1,
}
