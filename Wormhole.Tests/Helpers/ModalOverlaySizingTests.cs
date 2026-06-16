using Windows.Foundation;
using Wormhole.Helpers;
using Xunit;

namespace Wormhole.Tests.Helpers;

public sealed class ModalOverlaySizingTests
{
    [Fact]
    public void Calculate_UsesRatioWithinBounds()
    {
        var sizing = new ModalOverlaySizing(0.92, 0.88, 820, 560, 1720, 900);

        var size = sizing.Calculate(new Size(1200, 800), margin: 24);

        Assert.Equal(1104, size.Width);
        Assert.Equal(704, size.Height);
    }

    [Fact]
    public void Calculate_NeverExceedsAvailableHostSpace()
    {
        var sizing = new ModalOverlaySizing(0.92, 0.88, 820, 560, 1720, 900);

        var size = sizing.Calculate(new Size(800, 500), margin: 24);

        Assert.Equal(752, size.Width);
        Assert.Equal(452, size.Height);
    }
}
