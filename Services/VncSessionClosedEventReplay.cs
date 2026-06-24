namespace Wormhole.Services;

internal sealed class VncSessionClosedEventReplay : IDisposable
{
    private readonly object _sender;
    private readonly object _gate = new();
    private EventHandler<VncSessionClosedEventArgs>? _closed;
    private VncSessionClosedEventArgs? _terminalClose;
    private bool _disposed;

    public VncSessionClosedEventReplay(object sender) => _sender = sender;

    public event EventHandler<VncSessionClosedEventArgs>? Closed
    {
        add
        {
            if (value is null) return;
            VncSessionClosedEventArgs? replay;
            lock (_gate)
            {
                if (_disposed) return;
                replay = _terminalClose;
                if (replay is null)
                {
                    _closed += value;
                    return;
                }
            }

            value.Invoke(_sender, replay);
        }
        remove
        {
            if (value is null) return;
            lock (_gate)
            {
                _closed -= value;
            }
        }
    }

    public bool TryRaise(VncSessionClosedEventArgs args)
    {
        ArgumentNullException.ThrowIfNull(args);
        EventHandler<VncSessionClosedEventArgs>? closed;
        lock (_gate)
        {
            if (_disposed || _terminalClose is not null) return false;
            _terminalClose = args;
            closed = _closed;
        }

        closed?.Invoke(_sender, args);
        return true;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _closed = null;
        }
    }
}
