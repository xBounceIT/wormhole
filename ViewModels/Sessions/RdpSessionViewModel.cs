using Wormhole.Models;

namespace Wormhole.ViewModels.Sessions;

public sealed partial class RdpSessionViewModel : SessionTabViewModel
{
    public override ProtocolType Protocol => ProtocolType.Rdp;
}
