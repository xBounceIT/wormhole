using Wormhole.Helpers;

namespace Wormhole.RdpHost.Tests;

public sealed class RdpDriveListTests
{
    [Fact]
    public void ParseLetters_DistinguishesAllFromNone()
    {
        Assert.Null(RdpDriveList.ParseLetters(" ALL "));
        Assert.Empty(RdpDriveList.ParseLetters(null)!);
        Assert.Empty(RdpDriveList.ParseLetters("   ")!);
    }

    [Fact]
    public void ParseLetters_NormalizesAndDeduplicatesValidDriveLetters()
    {
        var drives = RdpDriveList.ParseLetters("c; D e,c,invalid,1");

        Assert.NotNull(drives);
        Assert.True(drives.SetEquals(['C', 'D', 'E']));
    }
}
