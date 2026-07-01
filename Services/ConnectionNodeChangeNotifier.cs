using Wormhole.Models;

namespace Wormhole.Services;

public sealed class ConnectionNodeChangeNotifier : IConnectionNodeChangeNotifier
{
    public event EventHandler<ConnectionNodeChangedEventArgs>? ConnectionNodeUpdated;

    public void PublishConnectionNodeUpdated(ConnectionNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        ConnectionNodeUpdated?.Invoke(this, new ConnectionNodeChangedEventArgs(node.Clone()));
    }
}
