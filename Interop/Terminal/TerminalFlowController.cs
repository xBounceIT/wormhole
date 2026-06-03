using System;

namespace Wormhole.Interop.Terminal;

/// <summary>
/// Watermark-based flow control for the terminal output pipe. Tracks how many bytes have been
/// posted to xterm.js but not yet acknowledged (parsed), and tells the caller when to pause /
/// resume the SSH read pump so xterm's internal write buffer can't grow without bound and hit its
/// hard ~50 MB <c>DISCARD_WATERMARK</c> — past which <c>term.write()</c> throws and silently drops a
/// chunk, stranding the escape-sequence/UTF-8 parser mid-sequence. That is a sticky corruption only
/// a full reset clears (the reported "big tcpdump output then everything breaks until CTRL+L" bug).
/// See https://xtermjs.org/docs/guides/flowcontrol/.
///
/// The class is intentionally a pure state machine driven by two events (posted, acked) so it can be
/// unit-tested without a real WebView2 — the caller wires the returned pause/resume transitions to
/// <c>ISshSession.PauseReading/ResumeReading</c>.
///
/// Threading: all members are confined to the WebView2 UI thread. Posts run on the dispatcher
/// (coalescer flush / replay) and acks arrive via <c>CoreWebView2.WebMessageReceived</c>, which is
/// raised on the WebView2's owning thread — the same UI thread. No internal locking is needed and
/// callers MUST NOT invoke these from the SSH pump thread.
/// </summary>
internal sealed class TerminalFlowController
{
    private readonly long _highWatermark;
    private readonly long _lowWatermark;
    private long _outstanding;
    private bool _paused;

    public TerminalFlowController(long highWatermark, long lowWatermark)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(highWatermark);
        ArgumentOutOfRangeException.ThrowIfNegative(lowWatermark);
        if (lowWatermark >= highWatermark)
        {
            throw new ArgumentOutOfRangeException(
                nameof(lowWatermark),
                "Low watermark must be strictly below the high watermark (hysteresis avoids pause/resume flapping).");
        }
        _highWatermark = highWatermark;
        _lowWatermark = lowWatermark;
    }

    /// <summary>Bytes posted to xterm but not yet acknowledged. Test/diagnostic helper.</summary>
    public long Outstanding => _outstanding;

    /// <summary>True while the producer should be held paused.</summary>
    public bool IsPaused => _paused;

    /// <summary>
    /// Record a batch of bytes just posted to xterm. Returns true on exactly the transition that
    /// should pause the producer (outstanding crossed the high watermark while running) so the
    /// caller pauses the read pump once, not on every subsequent post.
    /// </summary>
    public bool OnPosted(int byteCount)
    {
        if (byteCount <= 0) return false;
        _outstanding += byteCount;
        if (!_paused && _outstanding >= _highWatermark)
        {
            _paused = true;
            return true;
        }
        return false;
    }

    /// <summary>
    /// Record that xterm has parsed <paramref name="byteCount"/> bytes. Returns true on exactly the
    /// transition that should resume the producer (outstanding fell to/below the low watermark while
    /// paused). Over-acks (more than outstanding) clamp at zero rather than going negative.
    /// </summary>
    public bool OnAcked(long byteCount)
    {
        if (byteCount <= 0) return false;
        _outstanding -= byteCount;
        if (_outstanding < 0) _outstanding = 0;
        if (_paused && _outstanding <= _lowWatermark)
        {
            _paused = false;
            return true;
        }
        return false;
    }

    /// <summary>
    /// Reset accounting on teardown. Returns true if the producer was paused, so the caller can
    /// release it — a pump parked on the pause gate when its bridge is disposed (e.g. a background
    /// tab detaching mid-flood) would otherwise never be resumed and the session would look frozen.
    /// </summary>
    public bool Reset()
    {
        var wasPaused = _paused;
        _paused = false;
        _outstanding = 0;
        return wasPaused;
    }
}
