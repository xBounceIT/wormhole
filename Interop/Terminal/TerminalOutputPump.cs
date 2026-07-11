using System.Buffers;

namespace Wormhole.Interop.Terminal;

internal enum TerminalDrainRequest
{
    None,
    Immediate,
    Delayed,
}

/// <summary>
/// Thread-safe, credit-limited FIFO between a terminal producer and the WebView output sink.
/// Queued bytes and posted-but-unacknowledged bytes jointly drive producer backpressure, so a
/// stalled UI cannot accumulate an unbounded coalescer batch and then submit it all to xterm.js.
/// </summary>
/// <remarks>
/// The sink must consume or copy the supplied memory before returning. The memory is backed by an
/// <see cref="ArrayPool{T}"/> rental and is invalid after the callback returns. Once the sink has
/// committed a frame, it must return <see langword="true"/> and absorb any post-commit bookkeeping
/// failure; a thrown exception or <see langword="false"/> means the frame was not accepted.
/// </remarks>
internal sealed class TerminalOutputPump
{
    private const int QueueSegmentBytes = 64 * 1024;
    internal const int MaximumInFlightFrames = 32;

    private readonly int _highWatermarkBytes;
    private readonly int _lowWatermarkBytes;
    private readonly int _maxFrameBytes;
    private readonly int _immediateThresholdBytes;
    private readonly long _maximumBacklogBytes;
    private readonly Func<long, ReadOnlyMemory<byte>, bool> _postFrame;
    private readonly Action _pauseProducer;
    private readonly Action _resumeProducer;
    private readonly Action<Exception>? _onPostFailure;
    private readonly object _lock = new();
    private readonly Dictionary<long, int> _inFlightFrames = new();

    private QueueSegment? _queueHead;
    private QueueSegment? _queueTail;
    private long _queuedBytes;
    private long _inFlightBytes;
    private ulong _enqueuedSequence;
    private ulong _postedSequence;
    private long _lastPostedFrameId;
    private long _nextFrameId = 1;
    private bool _producerPaused;
    private bool _drainScheduled;
    private bool _drainInProgress;
    private bool _sealed;
    private bool _failed;
    private bool _disposed;

    public TerminalOutputPump(
        int highWatermarkBytes,
        int lowWatermarkBytes,
        int maxFrameBytes,
        int immediateThresholdBytes,
        Func<long, ReadOnlyMemory<byte>, bool> postFrame,
        Action pauseProducer,
        Action resumeProducer,
        Action<Exception>? onPostFailure = null,
        long maximumBacklogBytes = 64L * 1024 * 1024)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(highWatermarkBytes);
        ArgumentOutOfRangeException.ThrowIfNegative(lowWatermarkBytes);
        if (lowWatermarkBytes >= highWatermarkBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(lowWatermarkBytes),
                "Low watermark must be strictly below the high watermark.");
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxFrameBytes);
        if (maxFrameBytes > highWatermarkBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxFrameBytes),
                "Maximum frame size cannot exceed the high watermark.");
        }

        ArgumentOutOfRangeException.ThrowIfNegative(immediateThresholdBytes);
        if (maximumBacklogBytes < highWatermarkBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumBacklogBytes),
                "Maximum backlog must be at least the high watermark.");
        }

        _highWatermarkBytes = highWatermarkBytes;
        _lowWatermarkBytes = lowWatermarkBytes;
        _maxFrameBytes = maxFrameBytes;
        _immediateThresholdBytes = immediateThresholdBytes;
        _maximumBacklogBytes = maximumBacklogBytes;
        _postFrame = postFrame ?? throw new ArgumentNullException(nameof(postFrame));
        _pauseProducer = pauseProducer ?? throw new ArgumentNullException(nameof(pauseProducer));
        _resumeProducer = resumeProducer ?? throw new ArgumentNullException(nameof(resumeProducer));
        _onPostFailure = onPostFailure;
    }

    public long QueuedBytes
    {
        get { lock (_lock) return _queuedBytes; }
    }

    public long InFlightBytes
    {
        get { lock (_lock) return _inFlightBytes; }
    }

    public long BacklogBytes
    {
        get { lock (_lock) return _queuedBytes + _inFlightBytes; }
    }

    /// <summary>Total bytes accepted since construction; a stable FIFO barrier marker.</summary>
    public ulong EnqueuedSequence
    {
        get { lock (_lock) return _enqueuedSequence; }
    }

    /// <summary>Total prefix bytes successfully posted to the ordered sink.</summary>
    public ulong PostedSequence
    {
        get { lock (_lock) return _postedSequence; }
    }
    public long LastPostedFrameId
    {
        get { lock (_lock) return _lastPostedFrameId; }
    }

    public bool IsFrameInFlight(long frameId)
    {
        if (frameId <= 0) return false;
        lock (_lock) return _inFlightFrames.ContainsKey(frameId);
    }

    public int InFlightFrameCount
    {
        get { lock (_lock) return _inFlightFrames.Count; }
    }

    public long? OldestInFlightFrameId
    {
        get
        {
            lock (_lock)
            {
                if (_inFlightFrames.Count == 0) return null;
                var oldest = long.MaxValue;
                foreach (var frameId in _inFlightFrames.Keys)
                {
                    if (frameId < oldest) oldest = frameId;
                }
                return oldest;
            }
        }
    }

    public long NextFrameId
    {
        get { lock (_lock) return _nextFrameId; }
    }

    public bool IsProducerPaused
    {
        get { lock (_lock) return _producerPaused; }
    }

    public bool IsFailed
    {
        get { lock (_lock) return _failed; }
    }
    public bool IsSealed
    {
        get { lock (_lock) return _sealed; }
    }
    public bool IsDisposed
    {
        get { lock (_lock) return _disposed; }
    }

    /// <summary>
    /// Copies output into the FIFO and returns how the caller should schedule the next drain.
    /// Empty and post-disposal writes are ignored.
    /// </summary>
    public TerminalDrainRequest Enqueue(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return TerminalDrainRequest.None;

        lock (_lock)
        {
            if (_disposed || _sealed || _failed) return TerminalDrainRequest.None;
            if (_enqueuedSequence > ulong.MaxValue - (ulong)data.Length)
            {
                _failed = true;
                NotifyFailureUnderLock(new InvalidOperationException(
                    "Terminal output byte sequence space was exhausted."));
                return TerminalDrainRequest.None;
            }
            if (_queuedBytes + _inFlightBytes > _maximumBacklogBytes - data.Length)
            {
                _failed = true;
                NotifyFailureUnderLock(new IOException(
                    $"Terminal output backlog exceeded the {_maximumBacklogBytes} byte safety limit."));
                return TerminalDrainRequest.None;
            }

            AppendQueuedBytesUnderLock(data);
            _enqueuedSequence = checked(_enqueuedSequence + (ulong)data.Length);
            ReconcileProducerUnderLock();
            return RequestDrainUnderLock(preferImmediate: _queuedBytes <= _immediateThresholdBytes);
        }
    }

    /// <summary>
    /// Posts FIFO frames until the in-flight window is full or the queue is empty. A failed or
    /// throwing sink leaves the head bytes and frame id untouched and requests a delayed retry.
    /// </summary>
    public TerminalDrainRequest Drain()
    {
        lock (_lock)
        {
            if (_disposed || _failed || _drainInProgress) return TerminalDrainRequest.None;

            _drainScheduled = false;
            _drainInProgress = true;
            try
            {
                while (_queuedBytes > 0 &&
                       _inFlightBytes < _highWatermarkBytes &&
                       _inFlightFrames.Count < MaximumInFlightFrames)
                {
                    if (_nextFrameId == long.MaxValue)
                    {
                        _failed = true;
                        NotifyFailureUnderLock(new InvalidOperationException(
                            "Terminal output frame id space was exhausted."));
                        return TerminalDrainRequest.None;
                    }

                    var credit = _highWatermarkBytes - _inFlightBytes;
                    var frameLength = (int)Math.Min(
                        Math.Min((long)_maxFrameBytes, credit),
                        _queuedBytes);
                    if (frameLength <= 0) break;

                    var frame = ArrayPool<byte>.Shared.Rent(frameLength);
                    try
                    {
                        CopyQueuedPrefixUnderLock(frame.AsSpan(0, frameLength));

                        var frameId = _nextFrameId;
                        // Reserve the ledger entry before invoking the sink so even a synchronous,
                        // re-entrant acknowledgement can be matched exactly once.
                        _inFlightFrames.Add(frameId, frameLength);
                        _inFlightBytes += frameLength;

                        bool posted;
                        Exception? postException = null;
                        try
                        {
                            posted = _postFrame(frameId, frame.AsMemory(0, frameLength));
                        }
                        catch (Exception ex)
                        {
                            posted = false;
                            postException = ex;
                        }

                        if (_disposed)
                        {
                            return TerminalDrainRequest.None;
                        }

                        if (!posted)
                        {
                            RollBackFrameReservationUnderLock(frameId);
                            ReconcileProducerUnderLock();
                            if (postException is not null)
                            {
                                NotifyFailureUnderLock(postException);
                                if (_disposed) return TerminalDrainRequest.None;
                            }
                            return RequestDelayedRetryUnderLock();
                        }

                        ConsumeQueuedPrefixUnderLock(frameLength);
                        _lastPostedFrameId = frameId;
                        _postedSequence = checked(_postedSequence + (ulong)frameLength);
                        _nextFrameId++;
                        ReconcileProducerUnderLock();
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(frame);
                    }
                }

                return TerminalDrainRequest.None;
            }
            finally
            {
                _drainInProgress = false;
            }
        }
    }

    /// <summary>
    /// Releases exactly the frame identified by <paramref name="frameId"/>. Duplicate, unknown,
    /// non-positive, and post-disposal acknowledgements are ignored.
    /// </summary>
    public TerminalDrainRequest Acknowledge(long frameId)
    {
        if (frameId <= 0) return TerminalDrainRequest.None;

        lock (_lock)
        {
            if (_disposed || _failed || !_inFlightFrames.Remove(frameId, out var byteCount))
            {
                return TerminalDrainRequest.None;
            }

            _inFlightBytes -= byteCount;
            if (_inFlightBytes < 0)
            {
                // Defensive invariant guard; exact ledger removal should make this unreachable.
                _inFlightBytes = 0;
            }

            ReconcileProducerUnderLock();
            return RequestDrainUnderLock(preferImmediate: true);
        }
    }

    /// <summary>
    /// Atomically stops accepting new bytes while allowing the already accepted FIFO and ACK
    /// ledger to drain. The caller can therefore keep the WebView listener alive until every
    /// parser response caused by the sealed prefix has been delivered.
    /// </summary>
    public TerminalDrainRequest Seal()
    {
        lock (_lock)
        {
            if (_disposed || _failed || _sealed) return TerminalDrainRequest.None;
            _sealed = true;
            return RequestDrainUnderLock(preferImmediate: true);
        }
    }

    /// <summary>
    /// Stops the pump, returns bytes that were never handed to the sink, records whether
    /// posted frames still lacked an xterm ACK, and releases a paused producer. The ACK state
    /// is part of replay correctness: an owner cannot know whether those frames produced
    /// terminal replies before the renderer disappeared.
    /// </summary>
    public TerminalOutputRetirement DisposeAndTakeRetirementState()
    {
        lock (_lock)
        {
            if (_disposed) return TerminalOutputRetirement.Empty;

            _disposed = true;
            _drainScheduled = false;

            var retirement = new TerminalOutputRetirement(
                SnapshotQueuedBytesUnderLock(),
                HadUnacknowledgedOutput: _inFlightFrames.Count > 0);
            ClearQueuedBytesUnderLock();
            _inFlightFrames.Clear();
            _inFlightBytes = 0;

            if (_producerPaused)
            {
                _producerPaused = false;
                try { _resumeProducer(); }
                catch (Exception ex) { NotifyFailureUnderLock(ex); }
            }

            return retirement;
        }
    }

    private TerminalDrainRequest RequestDrainUnderLock(bool preferImmediate)
    {
        if (_disposed ||
            _failed ||
            _drainScheduled ||
            _drainInProgress ||
            _queuedBytes == 0 ||
            _inFlightBytes >= _highWatermarkBytes ||
            _inFlightFrames.Count >= MaximumInFlightFrames)
        {
            return TerminalDrainRequest.None;
        }

        _drainScheduled = true;
        return preferImmediate ? TerminalDrainRequest.Immediate : TerminalDrainRequest.Delayed;
    }

    private TerminalDrainRequest RequestDelayedRetryUnderLock()
    {
        if (_disposed ||
            _failed ||
            _queuedBytes == 0 ||
            _inFlightBytes >= _highWatermarkBytes ||
            _inFlightFrames.Count >= MaximumInFlightFrames)
        {
            return TerminalDrainRequest.None;
        }

        _drainScheduled = true;
        return TerminalDrainRequest.Delayed;
    }

    private void ReconcileProducerUnderLock()
    {
        if (_failed) return;

        var backlog = _queuedBytes + _inFlightBytes;
        if (!_producerPaused && backlog >= _highWatermarkBytes)
        {
            // These callbacks intentionally run under the same lock that owns the desired state.
            // Applying them later/outside the lock allows a concurrent ACK to Resume before a stale
            // Pause lands, parking the real producer while the state machine believes it is running.
            _producerPaused = true;
            try { _pauseProducer(); }
            catch (Exception ex)
            {
                _producerPaused = false;
                NotifyFailureUnderLock(ex);
            }
        }
        else if (_producerPaused && backlog <= _lowWatermarkBytes)
        {
            _producerPaused = false;
            try { _resumeProducer(); }
            catch (Exception ex) { NotifyFailureUnderLock(ex); }
        }
    }

    private void NotifyFailureUnderLock(Exception exception)
    {
        if (_onPostFailure is null) return;
        try { _onPostFailure(exception); }
        catch
        {
            // Failure reporting must never corrupt the pump ledger or strand pooled buffers.
        }
    }
    private void RollBackFrameReservationUnderLock(long frameId)
    {
        if (_inFlightFrames.Remove(frameId, out var byteCount))
        {
            _inFlightBytes -= byteCount;
        }
    }

    private void AppendQueuedBytesUnderLock(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
        {
            if (_queueTail is null || _queueTail.End == _queueTail.Buffer.Length)
            {
                var segment = new QueueSegment(ArrayPool<byte>.Shared.Rent(QueueSegmentBytes));
                if (_queueTail is null)
                {
                    _queueHead = segment;
                }
                else
                {
                    _queueTail.Next = segment;
                }
                _queueTail = segment;
            }

            var writable = _queueTail.Buffer.Length - _queueTail.End;
            var copyLength = Math.Min(writable, data.Length);
            data[..copyLength].CopyTo(_queueTail.Buffer.AsSpan(_queueTail.End, copyLength));
            _queueTail.End += copyLength;
            _queuedBytes += copyLength;
            data = data[copyLength..];
        }
    }

    private void CopyQueuedPrefixUnderLock(Span<byte> destination)
    {
        var segment = _queueHead;
        var written = 0;
        while (written < destination.Length && segment is not null)
        {
            var available = segment.End - segment.Start;
            var copyLength = Math.Min(available, destination.Length - written);
            segment.Buffer.AsSpan(segment.Start, copyLength).CopyTo(destination[written..]);
            written += copyLength;
            segment = segment.Next;
        }

        if (written != destination.Length)
        {
            throw new InvalidOperationException("Terminal output queue contained fewer bytes than expected.");
        }
    }

    private void ConsumeQueuedPrefixUnderLock(int byteCount)
    {
        var remaining = byteCount;
        while (remaining > 0)
        {
            var segment = _queueHead
                ?? throw new InvalidOperationException("Terminal output queue was unexpectedly empty.");
            var available = segment.End - segment.Start;
            if (remaining < available)
            {
                segment.Start += remaining;
                remaining = 0;
                break;
            }

            remaining -= available;
            _queueHead = segment.Next;
            if (_queueHead is null) _queueTail = null;
            ArrayPool<byte>.Shared.Return(segment.Buffer);
        }

        _queuedBytes -= byteCount;
    }

    private byte[] SnapshotQueuedBytesUnderLock()
    {
        if (_queuedBytes == 0) return Array.Empty<byte>();
        if (_queuedBytes > int.MaxValue)
        {
            throw new InvalidOperationException("Terminal output queue is too large to return as one byte array.");
        }

        var snapshot = new byte[(int)_queuedBytes];
        CopyQueuedPrefixUnderLock(snapshot);
        return snapshot;
    }

    private void ClearQueuedBytesUnderLock()
    {
        var segment = _queueHead;
        while (segment is not null)
        {
            var next = segment.Next;
            ArrayPool<byte>.Shared.Return(segment.Buffer);
            segment = next;
        }

        _queueHead = null;
        _queueTail = null;
        _queuedBytes = 0;
    }

    private sealed class QueueSegment(byte[] buffer)
    {
        public byte[] Buffer { get; } = buffer;
        public int Start { get; set; }
        public int End { get; set; }
        public QueueSegment? Next { get; set; }
    }
}
