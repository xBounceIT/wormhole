using System;
namespace Wormhole.Helpers;

/// <summary>
/// RDP screen-size aliases accepted by the ActiveX host. These values remain compatible with
/// current Electron profiles and older databases imported by the Go backend.
/// </summary>
internal static class RdpScreenSizes
{
    /// <summary>Canonical profile value meaning "size the remote desktop to the available
    /// embedded connection content area".</summary>
    public const string FullConnectionContent = "Full connection content";

    /// <summary>Legacy value saved by older Wormhole builds for the same dynamic sizing mode.</summary>
    public const string LegacyFullScreenSentinel = "Full screen";

    /// <summary>Legacy value imported from mRemoteNG for the same dynamic sizing mode.</summary>
    public const string MRemoteNgFitToWindowSentinel = "FitToWindow";

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
}
