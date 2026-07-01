using Wormhole.Models;

namespace Wormhole.Services;

public sealed class ConnectionNodeChangedEventArgs : EventArgs
{
    public ConnectionNodeChangedEventArgs(ConnectionNode node)
    {
        Node = node;
    }

    public ConnectionNode Node { get; }
}

public interface IConnectionNodeChangeNotifier
{
    event EventHandler<ConnectionNodeChangedEventArgs>? ConnectionNodeUpdated;

    void PublishConnectionNodeUpdated(ConnectionNode node);
}
