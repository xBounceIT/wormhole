using System.Text;

namespace Wormhole.Services.Ssh;

/// <summary>
/// Replaces the MCP wrapper echo and markers only after the exact shell echo plus start marker prove
/// that a real shell executed the payload. Any mismatch fails open and returns every speculative byte,
/// so editors, pagers, REPLs, and asynchronous terminal output can never be hidden.
/// </summary>
internal sealed class ShellCommandPresentationFilter
{
    private const int MaxSpeculativeEchoBytes = 64 * 1024;
    private const int MaxEndMarkerDigits = 10;

    private enum FilterState
    {
        MatchingEcho,
        MatchingEchoLineEnding,
        AwaitStartMarker,
        SwallowStartLineEnding,
        SwallowOptionalLfThenPassing,
        Passing,
        SwallowEndLineEnding,
        SwallowOptionalLfThenPassThrough,
        PassThrough,
    }

    private readonly byte[] _expectedEcho;
    private readonly byte[] _presentation;
    private readonly byte[] _startMarker;
    private readonly byte[] _endMarkerPrefix;
    private readonly List<byte> _pending = new();

    private byte[]? _suppressedEcho;
    private int _matchedEchoBytes;
    private FilterState _state;

    public ShellCommandPresentationFilter(
        string command,
        string payload,
        string startMarker,
        string endMarkerPrefix)
    {
        var echoBody = payload.EndsWith('\r') ? payload[..^1] : payload;
        _expectedEcho = Encoding.UTF8.GetBytes(echoBody);
        _presentation = Encoding.UTF8.GetBytes(command + "\r\n");
        _startMarker = Encoding.ASCII.GetBytes(startMarker);
        _endMarkerPrefix = Encoding.ASCII.GetBytes(endMarkerPrefix);
        _state = _expectedEcho.Length <= MaxSpeculativeEchoBytes
            ? FilterState.MatchingEcho
            : FilterState.PassThrough;
        IsComplete = _state == FilterState.PassThrough;
    }

    public bool IsComplete { get; private set; }

    internal int EchoComparisonCountForTesting { get; private set; }

    public byte[] Filter(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return Array.Empty<byte>();
        if (_state == FilterState.PassThrough) return data.ToArray();

        foreach (var value in data) _pending.Add(value);

        var output = new List<byte>();
        while (true)
        {
            switch (_state)
            {
                case FilterState.MatchingEcho:
                    if (!MatchEchoOrFailOpen(output)) return output.ToArray();
                    break;

                case FilterState.MatchingEchoLineEnding:
                    if (!MatchEchoLineEndingOrFailOpen(output)) return output.ToArray();
                    break;

                case FilterState.AwaitStartMarker:
                    if (!MatchStartMarkerOrFailOpen(output)) return output.ToArray();
                    break;

                case FilterState.SwallowStartLineEnding:
                    if (!ConsumeLineEndingOrWait(FilterState.Passing, FilterState.SwallowOptionalLfThenPassing))
                        return output.ToArray();
                    break;

                case FilterState.SwallowOptionalLfThenPassing:
                    if (!ConsumeOptionalLfOrWait(FilterState.Passing)) return output.ToArray();
                    break;

                case FilterState.Passing:
                    if (!PassUntilEndMarker(output)) return output.ToArray();
                    break;

                case FilterState.SwallowEndLineEnding:
                    if (!ConsumeLineEndingOrWait(FilterState.PassThrough, FilterState.SwallowOptionalLfThenPassThrough))
                        return output.ToArray();
                    IsComplete = true;
                    break;

                case FilterState.SwallowOptionalLfThenPassThrough:
                    if (!ConsumeOptionalLfOrWait(FilterState.PassThrough)) return output.ToArray();
                    IsComplete = true;
                    break;

                case FilterState.PassThrough:
                    IsComplete = true;
                    DrainTo(output, _pending.Count);
                    return output.ToArray();
            }
        }
    }

    /// <summary>
    /// Releases bytes held only for speculative matching. Called on timeout, cancellation, or teardown
    /// before the filter is retired, ensuring an incomplete wrapper can never erase terminal output.
    /// </summary>
    public byte[] DrainPending()
    {
        var output = new List<byte>();
        if (_suppressedEcho is { Length: > 0 })
        {
            output.AddRange(_suppressedEcho);
            _suppressedEcho = null;
        }
        DrainTo(output, _pending.Count);
        _state = FilterState.PassThrough;
        IsComplete = true;
        return output.ToArray();
    }

    private bool MatchEchoOrFailOpen(List<byte> output)
    {
        while (_matchedEchoBytes < _pending.Count &&
               _matchedEchoBytes < _expectedEcho.Length)
        {
            EchoComparisonCountForTesting++;
            if (_pending[_matchedEchoBytes] != _expectedEcho[_matchedEchoBytes])
            {
                FailOpen(output);
                return true;
            }
            _matchedEchoBytes++;
        }

        if (_matchedEchoBytes < _expectedEcho.Length) return false;
        _state = FilterState.MatchingEchoLineEnding;
        return true;
    }

    private bool MatchEchoLineEndingOrFailOpen(List<byte> output)
    {
        var lineEndingStart = _expectedEcho.Length;
        if (_pending.Count <= lineEndingStart) return false;

        var first = _pending[lineEndingStart];
        if (first == (byte)'\n')
        {
            ConfirmEcho(lineEndingStart + 1);
            return true;
        }

        if (first != (byte)'\r')
        {
            FailOpen(output);
            return true;
        }

        if (_pending.Count == lineEndingStart + 1) return false;
        var echoLength = _pending[lineEndingStart + 1] == (byte)'\n'
            ? lineEndingStart + 2
            : lineEndingStart + 1;
        ConfirmEcho(echoLength);
        return true;
    }

    private void ConfirmEcho(int echoLength)
    {
        _suppressedEcho = _pending.GetRange(0, echoLength).ToArray();
        _pending.RemoveRange(0, echoLength);
        _matchedEchoBytes = 0;
        _state = FilterState.AwaitStartMarker;
    }

    private bool MatchStartMarkerOrFailOpen(List<byte> output)
    {
        if (_pending.Count == 0) return false;

        var comparable = Math.Min(_pending.Count, _startMarker.Length);
        for (var index = 0; index < comparable; index++)
        {
            if (_pending[index] == _startMarker[index]) continue;
            FailOpen(output);
            return true;
        }

        if (_pending.Count < _startMarker.Length) return false;

        _pending.RemoveRange(0, _startMarker.Length);
        _suppressedEcho = null;
        output.AddRange(_presentation);
        _state = FilterState.SwallowStartLineEnding;
        return true;
    }

    private void FailOpen(List<byte> output)
    {
        if (_suppressedEcho is { Length: > 0 })
        {
            output.AddRange(_suppressedEcho);
            _suppressedEcho = null;
        }
        DrainTo(output, _pending.Count);
        _matchedEchoBytes = 0;
        _state = FilterState.PassThrough;
        IsComplete = true;
    }

    private bool PassUntilEndMarker(List<byte> output)
    {
        var search = FindEndMarker();
        if (search.Found)
        {
            DrainTo(output, search.Start);
            _pending.RemoveRange(0, search.EndExclusive - search.Start);
            _state = FilterState.SwallowEndLineEnding;
            return true;
        }

        if (search.WaitStart >= 0)
        {
            DrainTo(output, search.WaitStart);
            return false;
        }

        var keep = LongestPrefixSuffixLength(_pending, _endMarkerPrefix);
        DrainTo(output, Math.Max(0, _pending.Count - keep));
        return false;
    }

    private EndMarkerSearch FindEndMarker()
    {
        for (var index = 0; index < _pending.Count; index++)
        {
            var prefixMatch = PrefixMatchLengthAt(index, _endMarkerPrefix);
            if (prefixMatch == 0) continue;
            if (prefixMatch < _endMarkerPrefix.Length)
            {
                if (index + prefixMatch == _pending.Count)
                {
                    return EndMarkerSearch.Wait(index);
                }
                continue;
            }

            var position = index + _endMarkerPrefix.Length;
            var digitStart = position;
            while (position < _pending.Count &&
                   position - digitStart <= MaxEndMarkerDigits &&
                   IsAsciiDigit(_pending[position]))
            {
                position++;
            }

            var digitCount = position - digitStart;
            if (digitCount > MaxEndMarkerDigits) continue;
            if (digitCount == 0)
            {
                if (position == _pending.Count) return EndMarkerSearch.Wait(index);
                continue;
            }

            if (position >= _pending.Count) return EndMarkerSearch.Wait(index);
            if (_pending[position] != (byte)'@') continue;
            if (position + 1 >= _pending.Count) return EndMarkerSearch.Wait(index);
            if (_pending[position + 1] != (byte)'@') continue;

            return EndMarkerSearch.FoundAt(index, position + 2);
        }

        return EndMarkerSearch.NotFound;
    }

    private bool ConsumeLineEndingOrWait(FilterState nextState, FilterState afterCrState)
    {
        if (_pending.Count == 0) return false;

        if (_pending[0] == (byte)'\r')
        {
            _pending.RemoveAt(0);
            if (_pending.Count == 0)
            {
                _state = afterCrState;
                return false;
            }
            if (_pending[0] == (byte)'\n') _pending.RemoveAt(0);
            _state = nextState;
            return true;
        }

        if (_pending[0] == (byte)'\n') _pending.RemoveAt(0);
        _state = nextState;
        return true;
    }

    private bool ConsumeOptionalLfOrWait(FilterState nextState)
    {
        if (_pending.Count == 0) return false;
        if (_pending[0] == (byte)'\n') _pending.RemoveAt(0);
        _state = nextState;
        return true;
    }

    private int PrefixMatchLengthAt(int index, byte[] prefix)
    {
        var matched = 0;
        while (matched < prefix.Length &&
               index + matched < _pending.Count &&
               _pending[index + matched] == prefix[matched])
        {
            matched++;
        }
        return matched;
    }

    private static int LongestPrefixSuffixLength(List<byte> source, byte[] prefix)
    {
        var max = Math.Min(source.Count, prefix.Length - 1);
        for (var length = max; length > 0; length--)
        {
            var sourceOffset = source.Count - length;
            var matches = true;
            for (var index = 0; index < length; index++)
            {
                if (source[sourceOffset + index] == prefix[index]) continue;
                matches = false;
                break;
            }
            if (matches) return length;
        }
        return 0;
    }

    private void DrainTo(List<byte> output, int count)
    {
        if (count <= 0) return;
        output.AddRange(_pending.GetRange(0, count));
        _pending.RemoveRange(0, count);
    }

    private static bool IsAsciiDigit(byte value) => value >= (byte)'0' && value <= (byte)'9';

    private readonly record struct EndMarkerSearch(bool Found, int Start, int EndExclusive, int WaitStart)
    {
        public static EndMarkerSearch NotFound { get; } = new(false, -1, -1, -1);
        public static EndMarkerSearch FoundAt(int start, int endExclusive) => new(true, start, endExclusive, -1);
        public static EndMarkerSearch Wait(int start) => new(false, -1, -1, start);
    }
}
