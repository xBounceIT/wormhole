using Wormhole.Helpers;
using Xunit;

namespace Wormhole.Tests.Helpers;

public class RdpDesktopSizeResolverTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(RdpScreenSizes.FullConnectionContent)]
    [InlineData(RdpScreenSizes.LegacyFullScreenSentinel)]
    [InlineData(RdpScreenSizes.MRemoteNgFitToWindowSentinel)]
    public void DynamicScreenSize_UsesEmbeddedSurfaceBounds_WhenMeasured(string? screenSize)
    {
        var size = RdpDesktopSizeResolver.Resolve(
            screenSize,
            initialSurfaceWidth: 1600,
            initialSurfaceHeight: 900,
            fallbackWidth: 3440,
            fallbackHeight: 1440);

        Assert.Equal((1600, 900), size);
    }

    [Fact]
    public void DynamicScreenSize_ClampsSeedSurfaceBounds_ToRdpMinimum()
    {
        var size = RdpDesktopSizeResolver.Resolve(
            RdpScreenSizes.FullConnectionContent,
            initialSurfaceWidth: 1,
            initialSurfaceHeight: 1,
            fallbackWidth: 3440,
            fallbackHeight: 1440);

        Assert.Equal((RdpDesktopSizeResolver.MinimumWidth, RdpDesktopSizeResolver.MinimumHeight), size);
    }

    [Fact]
    public void DynamicScreenSize_UsesMonitorFallback_WhenSurfaceNotMeasured()
    {
        var size = RdpDesktopSizeResolver.Resolve(
            RdpScreenSizes.FullConnectionContent,
            initialSurfaceWidth: 0,
            initialSurfaceHeight: 0,
            fallbackWidth: 3440,
            fallbackHeight: 1440);

        Assert.Equal((3440, 1440), size);
    }

    [Fact]
    public void FixedResolutionPreset_IsPreserved()
    {
        var size = RdpDesktopSizeResolver.Resolve(
            "1024x768",
            initialSurfaceWidth: 1600,
            initialSurfaceHeight: 900,
            fallbackWidth: 3440,
            fallbackHeight: 1440);

        Assert.Equal((1024, 768), size);
    }

    [Theory]
    [InlineData("bad")]
    [InlineData("320x200")]
    [InlineData("1024x768x32")]
    public void InvalidResolution_FallsBackToFixedDefault(string screenSize)
    {
        var size = RdpDesktopSizeResolver.Resolve(
            screenSize,
            initialSurfaceWidth: 1600,
            initialSurfaceHeight: 900,
            fallbackWidth: 3440,
            fallbackHeight: 1440);

        Assert.Equal((RdpDesktopSizeResolver.DefaultWidth, RdpDesktopSizeResolver.DefaultHeight), size);
    }

    [Fact]
    public void ClampDynamicResolution_PassesThroughEvenInRangeSize()
    {
        Assert.Equal((1600, 900), RdpDesktopSizeResolver.ClampDynamicResolution(1600, 900));
    }

    [Theory]
    [InlineData(1365, 1364)] // odd → previous even
    [InlineData(1601, 1600)]
    [InlineData(201, 200)]
    public void ClampDynamicResolution_ForcesEvenWidth(int widthPx, int expectedWidth)
    {
        var (w, _) = RdpDesktopSizeResolver.ClampDynamicResolution(widthPx, 1080);
        Assert.Equal(expectedWidth, w);
        Assert.Equal(0, w & 1);
    }

    [Theory]
    [InlineData(10, 10, RdpDesktopSizeResolver.DynamicResizeMinDimension, RdpDesktopSizeResolver.DynamicResizeMinDimension)]
    [InlineData(100000, 100000, RdpDesktopSizeResolver.DynamicResizeMaxDimension, RdpDesktopSizeResolver.DynamicResizeMaxDimension)]
    public void ClampDynamicResolution_ClampsToChannelRange(int widthPx, int heightPx, int expectedWidth, int expectedHeight)
    {
        var (w, h) = RdpDesktopSizeResolver.ClampDynamicResolution(widthPx, heightPx);
        Assert.Equal(expectedWidth, w);
        Assert.Equal(expectedHeight, h);
        // Max dimension (8192) is even, so the even-width rule never pushes below it.
        Assert.Equal(0, w & 1);
    }
}
