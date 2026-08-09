using Wormhole.Helpers;

namespace Wormhole.RdpHost.Tests;

public sealed class RdpDesktopSizeResolverTests
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

    [Theory]
    [InlineData(1600, 900, 1600, 900)]
    [InlineData(1365, 1080, 1364, 1080)]
    [InlineData(10, 10, RdpDesktopSizeResolver.DynamicResizeMinDimension, RdpDesktopSizeResolver.DynamicResizeMinDimension)]
    [InlineData(100000, 100000, RdpDesktopSizeResolver.DynamicResizeMaxDimension, RdpDesktopSizeResolver.DynamicResizeMaxDimension)]
    public void ClampDynamicResolution_EnforcesChannelBoundsAndEvenWidth(
        int width,
        int height,
        int expectedWidth,
        int expectedHeight)
    {
        var actual = RdpDesktopSizeResolver.ClampDynamicResolution(width, height);

        Assert.Equal((expectedWidth, expectedHeight), actual);
        Assert.Equal(0, actual.Width & 1);
    }
}
