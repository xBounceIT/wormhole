using Wormhole.Helpers;
using Wormhole.Interop.Rdp;
using Xunit;

namespace Wormhole.Tests.Interop.Rdp;

public sealed class RdpHostBoundsWindowPosTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void BuildFlags_WhenRevealFalse_DoesNotShowWindow(bool sizeChanged)
    {
        var flags = RdpHostBoundsWindowPos.BuildFlags(sizeChanged, reveal: false);

        Assert.Equal(0u, flags & Win32Interop.SWP_SHOWWINDOW);
    }

    [Fact]
    public void BuildFlags_WhenRevealTrue_IncludesShowWindow()
    {
        var flags = RdpHostBoundsWindowPos.BuildFlags(sizeChanged: true, reveal: true);

        Assert.NotEqual(0u, flags & Win32Interop.SWP_SHOWWINDOW);
    }
}
