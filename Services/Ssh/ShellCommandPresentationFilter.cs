using System.Text;

namespace Wormhole.Services.Ssh;

/// <summary>
/// Removes the MCP run-command wrapper from the user-facing terminal stream while leaving the
/// raw stream intact for <see cref="ShellCommandRunner"/> capture/parsing.
/// </summary>
internal sealed class ShellCommandPresentationFilter
{
    private enum FilterState
    {
        SuppressUntilStartMarker,
        SwallowStartLineEnding,
        SwallowOptionalLfThenPassing,
        Passing,
        SwallowEndLineEnding,
        SwallowOptionalLfThenPassThrough,
        PassThrough,
    }

    private readonly byte[] _startMarker;
    private readonly byte[] _endMarkerPrefix;
    private readonly List<byte> _pending = new();

    private FilterState _state = FilterState.SuppressUntilStartMarker;

    public ShellCommandPresentationFilter(string startMarker, string endMarkerPrefix)
    {
        _startMarker = Encoding.ASCII.GetBytes(startMarker);
        _endMarkerPrefix = Encoding.ASCII.GetBytes(endMarkerPrefix);
    }

    public bool IsComplete { get; private set; }

    public byte[] Filter(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return Array.Empty<byte>();
        if (_state == FilterState.PassThrough) return data.ToArray();

        foreach (var b in data) _pending.Add(b);

        var output = new List<byte>();
        while (true)
        {
            switch (_state)
            {
                case FilterState.SuppressUntilStartMarker:
                    if (!SuppressUntilStartMarker()) return output.ToArray();
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

    private bool SuppressUntilStartMarker()
    {
        var markerIndex = IndexOf(_pending, _startMarker, 0);
        if (markerIndex < 0)
        {
            TrimPendingToSuffix(_startMarker.Length - 1);
            return false;
        }

        _pending.RemoveRange(0, markerIndex + _startMarker.Length);
        _state = FilterState.SwallowStartLineEnding;
        return true;
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
        var emit = Math.Max(0, _pending.Count - keep);
        DrainTo(output, emit);
        return false;
    }

    private EndMarkerSearch FindEndMarker()
    {
        for (var i = 0; i < _pending.Count; i++)
        {
            var prefixMatch = PrefixMatchLengthAt(i, _endMarkerPrefix);
            if (prefixMatch == 0) continue;
            if (prefixMatch < _endMarkerPrefix.Length)
            {
                return EndMarkerSearch.Wait(i);
            }

            var pos = i + _endMarkerPrefix.Length;
            var digitStart = pos;
            while (pos < _pending.Count && IsAsciiDigit(_pending[pos])) pos++;

            if (pos == digitStart)
            {
                if (pos == _pending.Count) return EndMarkerSearch.Wait(i);
                continue;
            }

            if (pos >= _pending.Count) return EndMarkerSearch.Wait(i);
            if (_pending[pos] != (byte)'@') continue;
            if (pos + 1 >= _pending.Count) return EndMarkerSearch.Wait(i);
            if (_pending[pos + 1] != (byte)'@') continue;

            return EndMarkerSearch.FoundAt(i, pos + 2);
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

        if (_pending[0] == (byte)'\n')
        {
            _pending.RemoveAt(0);
        }
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

    private static int IndexOf(List<byte> source, byte[] pattern, int start)
    {
        if (pattern.Length == 0) return start <= source.Count ? start : -1;
        for (var i = start; i <= source.Count - pattern.Length; i++)
        {
            var matched = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (source[i + j] == pattern[j]) continue;
                matched = false;
                break;
            }
            if (matched) return i;
        }
        return -1;
    }

    private static int LongestPrefixSuffixLength(List<byte> source, byte[] prefix)
    {
        var max = Math.Min(source.Count, prefix.Length - 1);
        for (var length = max; length > 0; length--)
        {
            var sourceOffset = source.Count - length;
            var matches = true;
            for (var i = 0; i < length; i++)
            {
                if (source[sourceOffset + i] == prefix[i]) continue;
                matches = false;
                break;
            }
            if (matches) return length;
        }
        return 0;
    }

    private void TrimPendingToSuffix(int count)
    {
        if (count < 0) count = 0;
        if (_pending.Count <= count) return;
        _pending.RemoveRange(0, _pending.Count - count);
    }

    private void DrainTo(List<byte> output, int count)
    {
        if (count <= 0) return;
        output.AddRange(_pending.GetRange(0, count));
        _pending.RemoveRange(0, count);
    }

    private static bool IsAsciiDigit(byte b) => b >= (byte)'0' && b <= (byte)'9';

    private readonly record struct EndMarkerSearch(bool Found, int Start, int EndExclusive, int WaitStart)
    {
        public static EndMarkerSearch NotFound { get; } = new(false, -1, -1, -1);
        public static EndMarkerSearch FoundAt(int start, int endExclusive) => new(true, start, endExclusive, -1);
        public static EndMarkerSearch Wait(int start) => new(false, -1, -1, start);
    }
}
