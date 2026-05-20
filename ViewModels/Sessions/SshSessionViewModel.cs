using Wormhole.Models;

namespace Wormhole.ViewModels.Sessions;

public sealed partial class SshSessionViewModel : SessionTabViewModel
{
    public override ProtocolType Protocol => ProtocolType.Ssh;
}
