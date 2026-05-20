using Wormhole.Models;

namespace Wormhole.ViewModels.Sessions;

public sealed partial class SftpSessionViewModel : SessionTabViewModel
{
    public override ProtocolType Protocol => ProtocolType.Sftp;
}
