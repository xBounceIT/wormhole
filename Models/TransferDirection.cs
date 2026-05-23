namespace Wormhole.Models;

public enum TransferDirection
{
    LocalToRemote,
    RemoteToLocal,
    /// <summary>Local-to-local: same-pane drop. Currently rejected by the orchestrator
    /// but defined so the drop-handler switch is exhaustive.</summary>
    LocalToLocal,
    /// <summary>Remote-to-remote: same-pane drop. Same rejection rationale.</summary>
    RemoteToRemote,
}
