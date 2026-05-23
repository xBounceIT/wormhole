using System;

namespace Wormhole.Interop.Terminal;

/// <summary>
/// Fixed-capacity ring buffer of recent terminal output bytes. Append on the SSH
/// read-pump thread; snapshot on the UI thread for replay into a freshly-created
/// xterm.js after a view detach/reattach. Thread-safe via a single intrinsic lock —
/// uncontended in the common case (one writer thread; reads are rare).
/// </summary>
internal sealed class TerminalReplayBuffer
{
    private readonly byte[] _buffer;
    private readonly object _lock = new();
    private int _head;
    private int _count;

    public TerminalReplayBuffer(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _buffer = new byte[capacity];
    }

    public int Capacity => _buffer.Length;

    public void Append(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;
        lock (_lock)
        {
            var capacity = _buffer.Length;
            if (data.Length >= capacity)
            {
                data.Slice(data.Length - capacity).CopyTo(_buffer);
                _head = 0;
                _count = capacity;
                return;
            }

            var firstSegment = Math.Min(data.Length, capacity - _head);
            data.Slice(0, firstSegment).CopyTo(_buffer.AsSpan(_head));
            var remaining = data.Length - firstSegment;
            if (remaining > 0)
            {
                data.Slice(firstSegment, remaining).CopyTo(_buffer.AsSpan(0));
            }
            _head = (_head + data.Length) % capacity;
            _count = Math.Min(_count + data.Length, capacity);
        }
    }

    public byte[] Snapshot()
    {
        lock (_lock)
        {
            if (_count == 0) return Array.Empty<byte>();
            var result = new byte[_count];
            if (_count < _buffer.Length)
            {
                Array.Copy(_buffer, 0, result, 0, _count);
            }
            else
            {
                var firstPart = _buffer.Length - _head;
                Array.Copy(_buffer, _head, result, 0, firstPart);
                Array.Copy(_buffer, 0, result, firstPart, _head);
            }
            return result;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _head = 0;
            _count = 0;
        }
    }
}
