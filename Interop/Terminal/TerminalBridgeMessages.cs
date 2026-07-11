namespace Wormhole.Interop.Terminal;

internal enum TerminalInputOrigin
{
    User,
    Parser,
}

internal enum TerminalSessionlessReplayMessageDisposition
{
    Ignore,
    Ready,
    CurrentFailure,
    RecoverableFatal,
}

internal static class TerminalBridgeMessages
{
    public static bool IsPageFatalFrame(ReadOnlySpan<char> message) =>
        message.StartsWith("fatal:", StringComparison.Ordinal);

    public static TerminalSessionlessReplayMessageDisposition ClassifySessionlessReplayMessage(
        ReadOnlySpan<char> message,
        long currentStreamId)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(currentStreamId);

        if (TryParseParserBarrierReady(message, out var readyStreamId))
        {
            return readyStreamId == currentStreamId
                ? TerminalSessionlessReplayMessageDisposition.Ready
                : TerminalSessionlessReplayMessageDisposition.Ignore;
        }

        var isCurrentFailure =
            (TryParseOutputWriteFailure(message, out var writeStreamId, out _) &&
             writeStreamId == currentStreamId) ||
            (TryParseParserBarrierFailure(message, out var barrierStreamId) &&
             barrierStreamId == currentStreamId) ||
            (TryParseTerminalClearFailure(message, out var clearStreamId) &&
             clearStreamId == currentStreamId);
        if (isCurrentFailure)
        {
            return TerminalSessionlessReplayMessageDisposition.CurrentFailure;
        }

        return IsPageFatalFrame(message)
            ? TerminalSessionlessReplayMessageDisposition.RecoverableFatal
            : TerminalSessionlessReplayMessageDisposition.Ignore;
    }

    public static bool TryParseScopedGeometry(
        ReadOnlySpan<char> message,
        uint minimumColumns,
        uint minimumRows,
        out long streamId,
        out uint columns,
        out uint rows)
    {
        streamId = 0;
        columns = 0;
        rows = 0;

        if (!message.StartsWith("r:", StringComparison.Ordinal))
        {
            return false;
        }

        var payload = message[2..];
        var streamSeparator = payload.IndexOf(':');
        if (streamSeparator <= 0 ||
            streamSeparator >= payload.Length - 1 ||
            payload[(streamSeparator + 1)..].Contains(':') ||
            !TryParseCanonicalPositiveInt64(payload[..streamSeparator], out var parsedStreamId))
        {
            return false;
        }

        var size = payload[(streamSeparator + 1)..];
        var sizeSeparator = size.IndexOf('x');
        if (sizeSeparator <= 0 ||
            sizeSeparator >= size.Length - 1 ||
            !TryParseCanonicalUInt32(size[..sizeSeparator], out var parsedColumns) ||
            !TryParseCanonicalUInt32(size[(sizeSeparator + 1)..], out var parsedRows) ||
            parsedColumns < minimumColumns ||
            parsedRows < minimumRows)
        {
            return false;
        }

        streamId = parsedStreamId;
        columns = parsedColumns;
        rows = parsedRows;
        return true;
    }

    public static bool TryParsePasteRequest(
        ReadOnlySpan<char> message,
        out long requestId,
        out bool force)
    {
        requestId = 0;
        force = false;
        if (!message.StartsWith("p:", StringComparison.Ordinal))
        {
            return false;
        }

        var payload = message[2..];
        var separator = payload.IndexOf(':');
        if (separator <= 0 ||
            separator != payload.Length - 2 ||
            !TryParseCanonicalPositiveInt64(payload[..separator], out requestId) ||
            payload[^1] is not ('0' or '1'))
        {
            requestId = 0;
            return false;
        }

        force = payload[^1] == '1';
        return true;
    }

    public static bool TryParseParserBarrierFailure(
        ReadOnlySpan<char> message,
        out long streamId) =>
        TryParseScopedStreamMessage(message, "fatal:barrier:", out streamId);

    public static bool TryParseTerminalClearFailure(
        ReadOnlySpan<char> message,
        out long streamId) =>
        TryParseScopedStreamMessage(message, "fatal:clear:", out streamId);

    private static bool TryParseScopedStreamMessage(
        ReadOnlySpan<char> message,
        ReadOnlySpan<char> prefix,
        out long streamId)
    {
        if (!message.StartsWith(prefix, StringComparison.Ordinal))
        {
            streamId = 0;
            return false;
        }
        return TryParseCanonicalPositiveInt64(message[prefix.Length..], out streamId);
    }
    public static bool TryParseParserBarrierReady(
        ReadOnlySpan<char> message,
        out long streamId) =>
        TryParseScopedStreamMessage(message, "barrier:", out streamId);

    public static bool TryParseFocusReady(ReadOnlySpan<char> message, out long streamId) =>
        TryParseScopedStreamMessage(message, "focus:", out streamId);

    public static bool TryParseInputFrame(
        ReadOnlySpan<char> message,
        out long streamId,
        out TerminalInputOrigin origin,
        out int encodedPayloadOffset)
    {
        streamId = 0;
        origin = default;
        encodedPayloadOffset = 0;
        if (!message.StartsWith("b:", StringComparison.Ordinal))
        {
            return false;
        }

        var payload = message[2..];
        var streamSeparator = payload.IndexOf(':');
        if (streamSeparator <= 0 ||
            streamSeparator >= payload.Length - 3 ||
            payload[streamSeparator + 2] != ':' ||
            payload[(streamSeparator + 3)..].Contains(':') ||
            !TryParseCanonicalPositiveInt64(payload[..streamSeparator], out streamId))
        {
            streamId = 0;
            return false;
        }

        origin = payload[streamSeparator + 1] switch
        {
            'u' => TerminalInputOrigin.User,
            'p' => TerminalInputOrigin.Parser,
            _ => default,
        };
        if (payload[streamSeparator + 1] is not ('u' or 'p'))
        {
            streamId = 0;
            origin = default;
            return false;
        }

        encodedPayloadOffset = 2 + streamSeparator + 3;
        return true;
    }

    public static bool TryParseOutputAck(
        ReadOnlySpan<char> message,
        out long streamId,
        out long frameId)
    {
        if (!message.StartsWith("a:", StringComparison.Ordinal))
        {
            streamId = 0;
            frameId = 0;
            return false;
        }

        return TryParseScopedFrameIds(message[2..], out streamId, out frameId);
    }

    public static bool TryParseOutputWriteFailure(
        ReadOnlySpan<char> message,
        out long streamId,
        out long frameId)
    {
        const string prefix = "fatal:write:";
        if (!message.StartsWith(prefix, StringComparison.Ordinal))
        {
            streamId = 0;
            frameId = 0;
            return false;
        }

        return TryParseScopedFrameIds(message[prefix.Length..], out streamId, out frameId);
    }

    private static bool TryParseScopedFrameIds(
        ReadOnlySpan<char> payload,
        out long streamId,
        out long frameId)
    {
        streamId = 0;
        frameId = 0;
        var separator = payload.IndexOf(':');
        if (separator <= 0 || separator >= payload.Length - 1 ||
            payload[(separator + 1)..].Contains(':'))
        {
            return false;
        }

        if (!TryParseCanonicalPositiveInt64(payload[..separator], out var parsedStreamId) ||
            !TryParseCanonicalPositiveInt64(payload[(separator + 1)..], out var parsedFrameId))
        {
            return false;
        }

        streamId = parsedStreamId;
        frameId = parsedFrameId;
        return true;
    }

    private static bool TryParseCanonicalUInt32(ReadOnlySpan<char> value, out uint parsed)
    {
        parsed = 0;
        return !value.IsEmpty &&
            (value.Length == 1 || value[0] != '0') &&
            uint.TryParse(
                value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out parsed);
    }

    private static bool TryParseCanonicalPositiveInt64(
        ReadOnlySpan<char> value,
        out long parsed)
    {
        parsed = 0;
        return !value.IsEmpty &&
            (value.Length == 1 || value[0] != '0') &&
            long.TryParse(
                value,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out parsed) &&
            parsed > 0;
    }
    public static string EncodeOutputFrame(long streamId, long frameId, ReadOnlyMemory<byte> data) =>
        EncodeFrame('d', streamId, frameId, data);

    public static string EncodeReplayFrame(long streamId, long frameId, ReadOnlyMemory<byte> data) =>
        EncodeFrame('q', streamId, frameId, data);

    private static string EncodeFrame(
        char frameType,
        long streamId,
        long frameId,
        ReadOnlyMemory<byte> data)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(streamId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(frameId);
        if (data.IsEmpty) throw new ArgumentException("Terminal output frame cannot be empty.", nameof(data));

        var streamText = streamId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var frameText = frameId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var prefixLength = 2 + streamText.Length + 1 + frameText.Length + 1;
        var encodedLength = ((data.Length + 2) / 3) * 4;

        return string.Create(
            prefixLength + encodedLength,
            (frameType, streamText, frameText, data),
            static (destination, state) =>
            {
                destination[0] = state.frameType;
                destination[1] = ':';
                state.streamText.AsSpan().CopyTo(destination[2..]);
                var offset = 2 + state.streamText.Length;
                destination[offset++] = ':';
                state.frameText.AsSpan().CopyTo(destination[offset..]);
                offset += state.frameText.Length;
                destination[offset++] = ':';
                if (!Convert.TryToBase64Chars(state.data.Span, destination[offset..], out var written) ||
                    written != destination.Length - offset)
                {
                    throw new FormatException("Failed to encode terminal output for WebView.");
                }
            });
    }

    public static byte[] DecodeBase64Bytes(ReadOnlySpan<char> encoded)
    {
        if (encoded.IsEmpty) return Array.Empty<byte>();

        var decodedLength = GetBase64DecodedLength(encoded);
        if (decodedLength < 0)
        {
            throw new FormatException("Invalid base64 payload from terminal WebView.");
        }

        var buffer = new byte[decodedLength];
        if (!Convert.TryFromBase64Chars(encoded, buffer, out var bytesWritten) ||
            bytesWritten != decodedLength)
        {
            throw new FormatException("Invalid base64 payload from terminal WebView.");
        }

        return buffer;
    }

    private static int GetBase64DecodedLength(ReadOnlySpan<char> encoded)
    {
        if (encoded.Length % 4 != 0) return -1;

        var padding = 0;
        if (encoded[^1] == '=') padding++;
        if (encoded.Length > 1 && encoded[^2] == '=') padding++;

        return (encoded.Length / 4 * 3) - padding;
    }
}
