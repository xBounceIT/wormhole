using System;
using System.Collections.Generic;

namespace Wormhole.Helpers;

/// <summary>
/// Parser for the RDP drive-redirection value received from the Go backend: <c>""</c>
/// redirects nothing, <c>"all"</c> redirects every fixed drive, and a delimited letter
/// list such as <c>"C,D,E"</c> redirects only those drives.
/// </summary>
internal static class RdpDriveList
{
    public const string AllSentinel = "all";

    /// <summary>
    /// Parse a raw user-entered or persisted string into a set of upper-case drive letters.
    /// Tokens are split on <c>, ; SPACE</c>; any token that isn't a single A–Z letter is
    /// silently dropped. Returns an empty set for <c>""</c>; returns null for the <c>"all"</c>
    /// sentinel so callers can distinguish "no letters" from "everything".
    /// </summary>
    public static IReadOnlySet<char>? ParseLetters(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return new HashSet<char>();
        if (string.Equals(raw.Trim(), AllSentinel, StringComparison.OrdinalIgnoreCase)) return null;

        var seen = new HashSet<char>();
        var remaining = raw.AsSpan();
        while (TryReadNextToken(ref remaining, out var token))
        {
            if (TryParseLetter(token, out var ch)) seen.Add(ch);
        }
        return seen;
    }

    private static bool TryReadNextToken(ref ReadOnlySpan<char> remaining, out ReadOnlySpan<char> token)
    {
        while (!remaining.IsEmpty)
        {
            var separator = remaining.IndexOfAny(',', ';', ' ');
            var rawToken = separator >= 0 ? remaining[..separator] : remaining;
            remaining = separator >= 0 ? remaining[(separator + 1)..] : ReadOnlySpan<char>.Empty;

            token = rawToken.Trim();
            if (!token.IsEmpty)
                return true;
        }

        token = ReadOnlySpan<char>.Empty;
        return false;
    }

    private static bool TryParseLetter(ReadOnlySpan<char> token, out char ch)
    {
        if (token.Length != 1)
        {
            ch = default;
            return false;
        }
        ch = char.ToUpperInvariant(token[0]);
        return ch >= 'A' && ch <= 'Z';
    }
}
