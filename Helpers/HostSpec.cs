namespace Wormhole.Helpers;

public readonly record struct HostSpec(string? User, string Host, int? Port);

public static class HostSpecParser
{
    /// <summary>
    /// Parses a connection target in any of the forms:
    /// <code>host</code>, <code>host:port</code>, <code>user@host</code>, <code>user@host:port</code>,
    /// <code>[ipv6]:port</code>, <code>user@[ipv6]:port</code>, or a bare bracketless IPv6 literal.
    /// </summary>
    public static HostSpec Parse(string input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        var s = input.Trim();

        string? user = null;
        var at = s.IndexOf('@');
        if (at > 0)
        {
            user = s.Substring(0, at);
            s = s.Substring(at + 1);
        }

        // Bracketed form: [host]:port — host may contain colons (IPv6).
        if (s.StartsWith('['))
        {
            var closeBracket = s.IndexOf(']');
            if (closeBracket < 0)
            {
                throw new FormatException(
                    $"Invalid host specifier '{input}': missing ']' to close bracketed host.");
            }
            var host = s.Substring(1, closeBracket - 1);
            var rest = s.Substring(closeBracket + 1);
            if (host.Length == 0)
            {
                throw new FormatException(
                    $"Invalid host specifier '{input}': bracketed host is empty.");
            }
            if (rest.Length == 0)
            {
                return new HostSpec(user, host, null);
            }
            if (rest.Length > 1 && rest[0] == ':' && TryParsePort(rest.AsSpan(1), out var bp))
            {
                return new HostSpec(user, host, bp);
            }
            // Reject garbage after the closing bracket so callers don't silently
            // connect to the wrong endpoint with the trailing chars stripped.
            throw new FormatException(
                $"Invalid host specifier '{input}': unexpected characters after ']'.");
        }

        // Bracketless IPv6 literal: more than one ':' means we can't tell which is the port
        // separator; treat the whole string as host and let the caller fall back to the
        // protocol default port. Users who want an explicit IPv6 port must bracket the host.
        if (CountChar(s, ':') > 1)
        {
            if (s.Length == 0)
                throw new FormatException($"Invalid host specifier '{input}': host is empty.");
            return new HostSpec(user, s, null);
        }

        int? port = null;
        var colon = s.LastIndexOf(':');
        if (colon > 0 && TryParsePort(s.AsSpan(colon + 1), out var p))
        {
            port = p;
            s = s.Substring(0, colon);
        }

        if (s.Length == 0)
        {
            throw new FormatException(
                $"Invalid host specifier '{input}': host is empty.");
        }

        return new HostSpec(user, s, port);
    }

    private static bool TryParsePort(ReadOnlySpan<char> text, out int port)
    {
        if (int.TryParse(text, out port) && port >= 1 && port <= 65535)
        {
            return true;
        }
        port = 0;
        return false;
    }

    private static int CountChar(string s, char c)
    {
        var n = 0;
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == c) n++;
        }
        return n;
    }
}
