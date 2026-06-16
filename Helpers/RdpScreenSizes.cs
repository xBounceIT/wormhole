using System;
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
    /// <summary>Canonical editor value meaning "size the remote desktop to the available
    /// embedded connection content area".</summary>
    public const string FullConnectionContent = "Full connection content";

    /// <summary>Legacy value saved by older Wormhole builds for the same dynamic sizing mode.</summary>
    public const string LegacyFullScreenSentinel = "Full screen";

    /// <summary>Legacy value imported from mRemoteNG for the same dynamic sizing mode.</summary>
    public const string MRemoteNgFitToWindowSentinel = "FitToWindow";

    /// <summary>Back-compat alias for existing callers/tests that still refer to the old constant name.</summary>
    [Obsolete("Use FullConnectionContent for new UI and IsFullConnectionContent for policy checks.")]
    public const string FullScreenSentinel = LegacyFullScreenSentinel;

    /// <summary>Preset list surfaced by the editor's screen-size combo. Mirrors the mstsc
    /// resolution presets, with the content-sized dynamic mode first.</summary>
    public static IReadOnlyList<string> Presets { get; } = new[]
    {
        FullConnectionContent,
        "640x480", "800x600", "1024x768", "1280x800", "1280x1024",
        "1366x768", "1440x900", "1600x900", "1680x1050", "1920x1080",
    };

    /// <summary>
    /// True when the requested screen size should track the embedded connection surface instead
    /// of pinning a fixed remote desktop resolution. Null/empty keeps the historical default,
    /// old saved "Full screen" rows keep working, and mRemoteNG "FitToWindow" imports get the
    /// same dynamic remote-resolution behavior instead of a scaled fixed fallback.
    /// </summary>
    public static bool IsFullConnectionContent(string? screenSize) =>
        string.IsNullOrWhiteSpace(screenSize) ||
        string.Equals(screenSize, FullConnectionContent, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(screenSize, LegacyFullScreenSentinel, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(screenSize, MRemoteNgFitToWindowSentinel, StringComparison.OrdinalIgnoreCase);

    /// <summary>Map saved/imported dynamic aliases onto the canonical picker item while
    /// preserving null as "inherit/default".</summary>
    public static string? NormalizeForPicker(string? screenSize)
    {
        if (string.IsNullOrWhiteSpace(screenSize)) return null;
        return IsFullConnectionContent(screenSize) ? FullConnectionContent : screenSize;
    }
}
