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

    /// <summary>
    /// Bounds the RDP Display Control channel (MS-RDPEDISP <c>DISPLAYCONTROL_MONITOR_LAYOUT</c>)
    /// accepts for a dynamic resolution change: each dimension must be 200..8192, and the width
    /// must additionally be even. Separate from <see cref="MinimumWidth"/>/<see cref="MinimumHeight"/>,
    /// which guard connect-time logon-UI visibility rather than a live resize request.
    /// </summary>
    public const int DynamicResizeMinDimension = 200;
    public const int DynamicResizeMaxDimension = 8192;

    /// <summary>
    /// Clamp a client pixel size to the range the RDP Display Control channel accepts for a
    /// dynamic resolution change, forcing an even width (MS-RDPEDISP requires the monitor width
    /// to be even — an odd width is silently rejected, which reads as "resize did nothing").
    /// Pure helper so the constraint is unit-testable without the OCX.
    /// </summary>
    public static (int Width, int Height) ClampDynamicResolution(int widthPx, int heightPx)
    {
        var w = Math.Clamp(widthPx, DynamicResizeMinDimension, DynamicResizeMaxDimension);
        var h = Math.Clamp(heightPx, DynamicResizeMinDimension, DynamicResizeMaxDimension);
        // Decrement to the nearest even value. Safe: the clamp floor (200) is even, so this can
        // never drop below DynamicResizeMinDimension.
        if ((w & 1) == 1) w--;
        return (w, h);
    }

    public static (int Width, int Height) Resolve(
        string? screenSize,
        int initialSurfaceWidth,
        int initialSurfaceHeight,
        int fallbackWidth,
        int fallbackHeight)
    {
        if (RdpScreenSizes.IsFullConnectionContent(screenSize))
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
