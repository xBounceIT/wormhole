using System;

namespace Wormhole.Interop.Terminal;

/// <summary>
/// Fixed-capacity ring buffer of recent terminal output bytes. Append on the SSH
/// read-pump thread; snapshot or drain on the UI thread for replay after a view
/// detach/reattach. Thread-safe via a single intrinsic lock — uncontended in the
/// common case (one writer thread; reads are rare).
/// </summary>
internal sealed class TerminalReplayBuffer
{
    private readonly int _capacity;
    private readonly object _lock = new();
    private byte[]? _buffer;
    private int _head;
    private int _count;
    private bool _hasTruncated;

    public TerminalReplayBuffer(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _capacity = capacity;
    }

    public int Capacity => _capacity;

    public int Count
    {
        get { lock (_lock) return _count; }
    }

    public bool HasTruncated
    {
        get { lock (_lock) return _hasTruncated; }
    }

    public void Append(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;
        lock (_lock)
        {
            var buffer = _buffer ??= new byte[_capacity];
            var capacity = _capacity;
            if (data.Length >= capacity)
            {
                _hasTruncated |= _count > 0 || data.Length > capacity;
                data.Slice(data.Length - capacity).CopyTo(buffer);
                _head = 0;
                _count = capacity;
                return;
            }

            if (_count + data.Length > capacity)
            {
                _hasTruncated = true;
            }

            var firstSegment = Math.Min(data.Length, capacity - _head);
            data.Slice(0, firstSegment).CopyTo(buffer.AsSpan(_head));
            var remaining = data.Length - firstSegment;
            if (remaining > 0)
            {
                data.Slice(firstSegment, remaining).CopyTo(buffer.AsSpan(0));
            }
            _head = (_head + data.Length) % capacity;
            _count = Math.Min(_count + data.Length, capacity);
        }
    }

    /// <summary>
    /// Places older, not-yet-posted output before the newer detached suffix already retained.
    /// If the combined data exceeds capacity, the newest tail wins and replay is marked inexact.
    /// </summary>
    public void Prepend(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;
        lock (_lock)
        {
            var available = _capacity - _count;
            if (data.Length > available) _hasTruncated = true;
            if (available == 0) return;

            var retainedLength = Math.Min(data.Length, available);
            var buffer = _buffer ??= new byte[_capacity];
            // A non-full ring is linear from index zero. Span.CopyTo is overlap-safe.
            if (_count > 0)
            {
                buffer.AsSpan(0, _count).CopyTo(buffer.AsSpan(retainedLength));
            }
            data.Slice(data.Length - retainedLength).CopyTo(buffer);
            _count += retainedLength;
            _head = _count == _capacity ? 0 : _count;
        }
    }

    public byte[] Snapshot()
    {
        lock (_lock)
        {
            return SnapshotUnderLock();
        }
    }

    public byte[] Drain()
    {
        lock (_lock)
        {
            var result = SnapshotUnderLock();
            _head = 0;
            _count = 0;
            _hasTruncated = false;
            return result;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _head = 0;
            _count = 0;
            _hasTruncated = false;
            _buffer = null;
        }
    }

    private byte[] SnapshotUnderLock()
    {
        if (_count == 0) return Array.Empty<byte>();
        var buffer = _buffer
            ?? throw new InvalidOperationException("Terminal replay buffer storage was unexpectedly absent.");
        var result = new byte[_count];
        if (_count < _capacity)
        {
            Array.Copy(buffer, 0, result, 0, _count);
        }
        else
        {
            var firstPart = _capacity - _head;
            Array.Copy(buffer, _head, result, 0, firstPart);
            Array.Copy(buffer, 0, result, firstPart, _head);
        }
        return result;
    }
}
