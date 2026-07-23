using Wormhole.Models;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Tests.ViewModels.Sessions.Layout;

internal sealed class StubSessionTab : SessionTabViewModel
{
    public StubSessionTab(string title)
    {
        Title = title;
    }

    public override ProtocolType Protocol => ProtocolType.Ssh;
}
