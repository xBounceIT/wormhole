namespace Wormhole.Models;

/// <summary>
/// Compatibility policy for legacy OpenVPN no-compression framing.
/// </summary>
public enum StormshieldOpenVpnCompressionFramingOverride
{
    /// <summary>Add the legacy no-compression framing marker when the profile omits one.</summary>
    Auto = 0,

    /// <summary>Explicitly add the legacy no-compression framing marker when the profile omits one.</summary>
    ForceLegacyStub = 1,
}
