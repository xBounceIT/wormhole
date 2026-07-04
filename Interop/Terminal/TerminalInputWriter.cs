using System.Buffers;

namespace Wormhole.Interop.Terminal;

/// <summary>
/// Serializes terminal input writes off the WebView2 UI thread. A single keystroke
/// starts writing immediately; bytes that arrive while that write is still in
/// flight are coalesced into the next write so rapid typing or paste bursts don't
/// create one SSH.NET write task per browser message.
/// </summary>
internal sealed class TerminalInputWriter : IDisposable
{
    private const int InitialCapacityBytes = 256;
    private const int ShrinkThresholdBytes = 16 * 1024;

    private readonly Func<ReadOnlyMemory<byte>, Task> _writeAsync;
    private readonly Action<Exception> _onWriteFailed;
    private readonly object _lock = new();
    private byte[] _buffer = new byte[InitialCapacityBytes];
    private int _length;
    private bool _workerRunning;
    private bool _disposed;

    public TerminalInputWriter(
        Func<ReadOnlyMemory<byte>, Task> writeAsync,
        Action<Exception> onWriteFailed)
    {
        _writeAsync = writeAsync ?? throw new ArgumentNullException(nameof(writeAsync));
        _onWriteFailed = onWriteFailed ?? throw new ArgumentNullException(nameof(onWriteFailed));
    }

    public bool HasPending
    {
        get
        {
            lock (_lock) return _length > 0;
        }
    }

    public void Enqueue(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;

        var startWorker = false;
        lock (_lock)
        {
            if (_disposed) return;
            EnsureCapacityForAppend(data.Length);
            data.CopyTo(_buffer.AsSpan(_length));
            _length += data.Length;
            if (!_workerRunning)
            {
                _workerRunning = true;
                startWorker = true;
            }
        }

        if (startWorker)
        {
            _ = Task.Run(FlushLoopAsync);
        }
    }

    private async Task FlushLoopAsync()
    {
        while (true)
        {
            byte[] rented;
            int length;
            lock (_lock)
            {
                if (_length == 0)
                {
                    _workerRunning = false;
                    return;
                }

                length = _length;
                rented = ArrayPool<byte>.Shared.Rent(length);
                _buffer.AsSpan(0, length).CopyTo(rented);
                _length = 0;
                if (_buffer.Length > ShrinkThresholdBytes)
                {
                    _buffer = new byte[InitialCapacityBytes];
                }
            }

            try
            {
                await _writeAsync(rented.AsMemory(0, length)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _onWriteFailed(ex);
                Abort();
                return;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _disposed = true;
        }
    }

    private void Abort()
    {
        lock (_lock)
        {
            _disposed = true;
            _length = 0;
            _workerRunning = false;
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
