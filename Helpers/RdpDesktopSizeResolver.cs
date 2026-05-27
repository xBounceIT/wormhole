namespace Wormhole.Helpers;

/// <summary>
/// Pure RDP desktop-size policy shared by the ActiveX host and tests. The host supplies the
/// monitor fallback; this helper decides when the embedded surface should win.
/// </summary>
public static class RdpDesktopSizeResolver
{
    public const int MinimumWidth = 640;
    public const int MinimumHeight = 480;
    public const int DefaultWidth = 1280;
    public const int DefaultHeight = 800;

    public static (int Width, int Height) Resolve(
        string? screenSize,
        int initialSurfaceWidth,
        int initialSurfaceHeight,
        int fallbackWidth,
        int fallbackHeight)
    {
        if (string.IsNullOrWhiteSpace(screenSize) ||
            string.Equals(screenSize, RdpScreenSizes.FullScreenSentinel, StringComparison.OrdinalIgnoreCase))
        {
            if (initialSurfaceWidth > 0 && initialSurfaceHeight > 0)
            {
                return (Math.Max(MinimumWidth, initialSurfaceWidth), Math.Max(MinimumHeight, initialSurfaceHeight));
            }

            return (Math.Max(MinimumWidth, fallbackWidth), Math.Max(MinimumHeight, fallbackHeight));
        }

        var size = screenSize.AsSpan();
        var separator = size.IndexOfAny('x', 'X');
        if (separator >= 0 &&
            size[(separator + 1)..].IndexOfAny('x', 'X') < 0 &&
            int.TryParse(size[..separator].Trim(), out var w) &&
            int.TryParse(size[(separator + 1)..].Trim(), out var h) &&
            w >= MinimumWidth &&
            h >= MinimumHeight)
        {
            return (w, h);
        }

        return (DefaultWidth, DefaultHeight);
    }
}
