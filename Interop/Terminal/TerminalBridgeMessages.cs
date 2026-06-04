using System.Text;

namespace Wormhole.Interop.Terminal;

internal static class TerminalBridgeMessages
{
    public static bool TryParseGeometry(
        ReadOnlySpan<char> message,
        uint minimumColumns,
        uint minimumRows,
        out uint columns,
        out uint rows)
    {
        columns = 0;
        rows = 0;

        if (!message.StartsWith("r:", StringComparison.Ordinal))
        {
            return false;
        }

        var size = message[2..];
        var separator = size.IndexOf('x');
        if (separator <= 0 || separator >= size.Length - 1)
        {
            return false;
        }

        if (!uint.TryParse(size[..separator], out var parsedColumns) ||
            !uint.TryParse(size[(separator + 1)..], out var parsedRows))
        {
            return false;
        }

        if (parsedColumns < minimumColumns || parsedRows < minimumRows)
        {
            return false;
        }

        columns = parsedColumns;
        rows = parsedRows;
        return true;
    }

    public static byte[] EncodeUtf8(ReadOnlySpan<char> text)
    {
        var payload = new byte[Encoding.UTF8.GetByteCount(text)];
        Encoding.UTF8.GetBytes(text, payload);
        return payload;
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
