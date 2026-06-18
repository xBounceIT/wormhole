using Wormhole.Services.Security;
using Xunit;

namespace Wormhole.Tests.Services.Security;

public sealed class RemoteDesktopSessionDetectorTests
{
    [Fact]
    public void IsRemoteDesktopSession_WhenSystemMetricIsSet_ReturnsTrue()
    {
        var detector = new RemoteDesktopSessionDetector(
            _ => 1,
            _ => "Console");

        Assert.True(detector.IsRemoteDesktopSession());
    }

    [Fact]
    public void IsRemoteDesktopSession_WhenSessionNameIsRdp_ReturnsTrue()
    {
        var detector = new RemoteDesktopSessionDetector(
            _ => 0,
            _ => "RDP-Tcp#4");

        Assert.True(detector.IsRemoteDesktopSession());
    }

    [Fact]
    public void IsRemoteDesktopSession_WhenLocalConsole_ReturnsFalse()
    {
        var detector = new RemoteDesktopSessionDetector(
            _ => 0,
            _ => "Console");

        Assert.False(detector.IsRemoteDesktopSession());
    }
}
