using System.Collections.Generic;

namespace Wormhole.Helpers;

/// <summary>
/// Shared RDP screen-size constants. The editor's screen-size picker and the ActiveX host's
/// resolver both look at the same strings — if the sentinel was duplicated as a literal
/// (and one got renamed for localisation), the resolver would silently fall back to its
/// fixed-size default instead of fitting the embedded RDP surface.
/// </summary>
public static class RdpScreenSizes
{
    /// <summary>Sentinel meaning "fill the available RDP surface". Pinned at the bottom of
    /// the editor's preset list.</summary>
    public const string FullScreenSentinel = "Full screen";

    /// <summary>Preset list surfaced by the editor's screen-size combo. Mirrors the mstsc
    /// resolution presets, with the full-screen sentinel last.</summary>
    public static IReadOnlyList<string> Presets { get; } = new[]
    {
        "640x480", "800x600", "1024x768", "1280x800", "1280x1024",
        "1366x768", "1440x900", "1600x900", "1680x1050", "1920x1080",
        FullScreenSentinel,
    };
}
