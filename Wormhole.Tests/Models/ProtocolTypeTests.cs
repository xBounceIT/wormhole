using Wormhole.Models;
using Xunit;

namespace Wormhole.Tests.Models;

public sealed class ProtocolTypeTests
{
    [Fact]
    public void PersistedProtocolValues_RemainStable()
    {
        Assert.Equal(0, (int)ProtocolType.Ssh);
        Assert.Equal(1, (int)ProtocolType.Rdp);
        Assert.Equal(3, (int)ProtocolType.Http);
        Assert.Equal(4, (int)ProtocolType.Https);
        Assert.Equal(5, (int)ProtocolType.Serial);
        Assert.Equal(6, (int)ProtocolType.Vnc);
    }
}
