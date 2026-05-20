using System;

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
            if (closeBracket > 0)
            {
                var host = s.Substring(1, closeBracket - 1);
                var rest = s.Substring(closeBracket + 1);
                int? bracketPort = null;
                if (rest.Length > 1 && rest[0] == ':' && int.TryParse(rest.AsSpan(1), out var bp))
                {
                    bracketPort = bp;
                }
                return new HostSpec(user, host, bracketPort);
            }
        }

        // Bracketless IPv6 literal: more than one ':' means we can't tell which is the port
        // separator; treat the whole string as host and let the caller fall back to the
        // protocol default port. Users who want an explicit IPv6 port must bracket the host.
        if (CountChar(s, ':') > 1)
        {
            return new HostSpec(user, s, null);
        }

        int? port = null;
        var colon = s.LastIndexOf(':');
        if (colon > 0 && int.TryParse(s.AsSpan(colon + 1), out var p))
        {
            port = p;
            s = s.Substring(0, colon);
        }

        return new HostSpec(user, s, port);
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
