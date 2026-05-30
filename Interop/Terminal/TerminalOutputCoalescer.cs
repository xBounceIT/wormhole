using System;
using System.Buffers;

namespace Wormhole.Interop.Terminal;

/// <summary>
/// Batches SSH read-pump output into WebView2 posts without forcing prompt-sized output
/// through the full coalesce delay. A small first chunk takes an immediate dispatcher
/// hop, then a short cooldown window batches any follow-up burst; large first chunks use
/// the delayed path from the start. Threading: <see cref="Append"/> may be called from
/// any thread (the SSH pump); <see cref="Flush"/> and <see cref="FlushImmediately"/> run
/// on the UI thread (the post callback) — the lock keeps the two consistent without
/// forcing a thread hop on every byte.
///
/// The actual UI-thread post and the timer arming are provided by the caller as
/// delegates so this class stays free of WebView2 / DispatcherQueue dependencies and
/// can be unit-tested without a real WinUI dispatcher.
/// </summary>
internal sealed class TerminalOutputCoalescer : IDisposable
{
    // After a one-off burst grows the buffer past this size, shrink back to the initial
    // capacity on the next flush. Without trimming, a single `cat huge_file` would pin
    // the buffer at its peak size for the lifetime of the bridge — multiplied across
    // long-lived terminal tabs, that's a real memory leak.
    private const int InitialCapacityBytes = 8 * 1024;
    private const int ShrinkThresholdBytes = 256 * 1024;
    private const int ImmediateFlushThresholdBytes = 512;

    private readonly Func<ReadOnlyMemory<byte>, bool> _post;
    private readonly Action _armTimer;
    private readonly Action _armImmediateFlush;
    private readonly object _lock = new();
    private byte[] _buffer = new byte[InitialCapacityBytes];
    private int _length;
    private bool _flushScheduled;
    private bool _cooldownTimerPending;
    private bool _suspended;
    private bool _disposed;

    public TerminalOutputCoalescer(Func<ReadOnlyMemory<byte>, bool> post, Action armTimer)
        : this(post, armTimer, armTimer)
    {
    }

    public TerminalOutputCoalescer(
        Func<ReadOnlyMemory<byte>, bool> post,
        Action armTimer,
        Action armImmediateFlush)
    {
        _post = post ?? throw new ArgumentNullException(nameof(post));
        _armTimer = armTimer ?? throw new ArgumentNullException(nameof(armTimer));
        _armImmediateFlush = armImmediateFlush ?? throw new ArgumentNullException(nameof(armImmediateFlush));
    }

    /// <summary>True if bytes are waiting to be flushed (test/diagnostic helper).</summary>
    public bool HasPending
    {
        get { lock (_lock) return _length > 0; }
    }

    /// <summary>
    /// Append bytes from any thread. Returns immediately after the copy; the caller's
    /// arm-timer delegate is invoked outside the lock (so the UI dispatcher can free
    /// up the SSH pump thread) only on the transition from empty → buffered.
    /// </summary>
    public void Append(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;
        bool armImmediate = false;
        bool armDelayed = false;
        lock (_lock)
        {
            if (_disposed || _suspended) return;
            EnsureCapacityForAppend(data.Length);
            data.CopyTo(_buffer.AsSpan(_length));
            _length += data.Length;
            if (!_flushScheduled)
            {
                _flushScheduled = true;
                if (!_cooldownTimerPending && _length <= ImmediateFlushThresholdBytes)
                {
                    armImmediate = true;
                }
                else
                {
                    armDelayed = true;
                }
            }
        }
        if (armImmediate) _armImmediateFlush();
        else if (armDelayed) _armTimer();
    }

    /// <summary>
    /// Drop any pending bytes and stop accepting new ones. Called when the bridge is
    /// being torn down (e.g. view unload) so no late timer tick posts to a disposed
    /// WebView. Idempotent.
    /// </summary>
    public void Suspend()
    {
        lock (_lock)
        {
            _suspended = true;
            _length = 0;
            _flushScheduled = false;
            _cooldownTimerPending = false;
        }
    }

    /// <summary>
    /// Resume accepting bytes after a prior <see cref="Suspend"/>. Idempotent.
    /// </summary>
    public void Resume()
    {
        lock (_lock) _suspended = false;
    }

    /// <summary>
    /// Drain the buffer and invoke the post delegate exactly once. Caller must run
    /// this on the UI thread (the post delegate touches WebView2). Safe to call
    /// when empty / suspended / disposed — those cases short-circuit.
    /// </summary>
    public void Flush() => FlushCore(startCooldownAfterPost: false);

    /// <summary>
    /// Flush latency-sensitive output without waiting for the coalesce timer, then keep
    /// a short delayed window armed so any follow-up burst is still batched.
    /// </summary>
    public void FlushImmediately() => FlushCore(startCooldownAfterPost: true);

    private void FlushCore(bool startCooldownAfterPost)
    {
        byte[]? rented = null;
        int length;
        var armCooldownTimer = false;
        lock (_lock)
        {
            if (_disposed || _suspended)
            {
                _flushScheduled = false;
                _cooldownTimerPending = false;
                return;
            }

            if (_length == 0)
            {
                _flushScheduled = false;
                _cooldownTimerPending = false;
                return;
            }

            length = _length;
            rented = ArrayPool<byte>.Shared.Rent(length);
            _buffer.AsSpan(0, length).CopyTo(rented);
            _length = 0;
            if (startCooldownAfterPost)
            {
                _cooldownTimerPending = true;
                // Keep _flushScheduled true until the cooldown timer fires; appends during
                // that window are accumulated instead of scheduling one immediate UI hop per
                // SSH packet in a bulk-output stream.
                armCooldownTimer = true;
            }
            else
            {
                _flushScheduled = false;
                _cooldownTimerPending = false;
            }
            // Trim back to default after a one-off burst grew the buffer past the
            // shrink threshold — without this, a single `cat huge_file` would pin the
            // buffer at its peak size for the lifetime of the bridge.
            if (_buffer.Length > ShrinkThresholdBytes)
            {
                _buffer = new byte[InitialCapacityBytes];
            }
        }
        try
        {
            _post(rented.AsMemory(0, length));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }

        if (armCooldownTimer)
        {
            _armTimer();
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _disposed = true;
            _length = 0;
            _flushScheduled = false;
            _cooldownTimerPending = false;
        }
    }

    private void EnsureCapacityForAppend(int incoming)
    {
        var required = _length + incoming;
        if (required <= _buffer.Length) return;
        var newSize = _buffer.Length;
        while (newSize < required) newSize *= 2;
        Array.Resize(ref _buffer, newSize);
    }
}
