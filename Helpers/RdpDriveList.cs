using System;
using System.Collections.Generic;

namespace Wormhole.Helpers;

/// <summary>
/// Shared parser for the persisted RDP drive-redirection string. The value is stored on
/// <c>ConnectionNode.RdpRedirectDrives</c> as one of: <c>""</c> (no redirect), <c>"all"</c>
/// (redirect every fixed drive), or a comma-separated upper-case letter list like
/// <c>"C,D,E"</c>. Both the editor view-model (validation, normalisation) and the ActiveX
/// host (per-letter toggle on the OCX DriveCollection) parse it — they go through this
/// helper so the canonical form stays consistent.
/// </summary>
internal static class RdpDriveList
{
    public const string AllSentinel = "all";

    private static readonly char[] Separators = { ',', ';', ' ' };

    private static string[] Tokenise(string raw) =>
        raw.Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Parse a raw user-entered or persisted string into a set of upper-case drive letters.
    /// Tokens are split on <c>, ; SPACE</c>; any token that isn't a single A–Z letter is
    /// silently dropped. Returns an empty set for <c>""</c>; returns null for the <c>"all"</c>
    /// sentinel so callers can distinguish "no letters" from "everything".
    /// </summary>
    public static IReadOnlySet<char>? ParseLetters(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return new HashSet<char>();
        if (string.Equals(raw, AllSentinel, StringComparison.OrdinalIgnoreCase)) return null;

        var seen = new HashSet<char>();
        foreach (var token in Tokenise(raw))
        {
            if (TryParseLetter(token, out var ch)) seen.Add(ch);
        }
        return seen;
    }

    /// <summary>
    /// Strict validation for the editor's custom-list input. Returns an error string suitable
    /// for an InfoBar, or null if the input is well-formed.
    /// </summary>
    public static string? Validate(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "Specify at least one drive letter (e.g. C,D).";
        var pieces = Tokenise(raw);
        if (pieces.Length == 0) return "Specify at least one drive letter (e.g. C,D).";
        var seen = new HashSet<char>();
        foreach (var p in pieces)
        {
            if (p.Length != 1) return $"'{p}' is not a single drive letter.";
            var ch = char.ToUpperInvariant(p[0]);
            if (ch < 'A' || ch > 'Z') return $"'{p}' is not a drive letter (A-Z).";
            if (!seen.Add(ch)) return $"Drive '{ch}' is listed more than once.";
        }
        return null;
    }

    /// <summary>Canonical form for the persisted string: comma-joined, upper-case, de-duplicated,
    /// preserving the user's input order. Single pass over the raw input.</summary>
    public static string Normalise(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        if (string.Equals(raw, AllSentinel, StringComparison.OrdinalIgnoreCase)) return AllSentinel;

        var seen = new HashSet<char>();
        var ordered = new List<char>(4);
        foreach (var token in Tokenise(raw))
        {
            if (!TryParseLetter(token, out var ch)) continue;
            if (seen.Add(ch)) ordered.Add(ch);
        }
        return string.Join(',', ordered);
    }

    private static bool TryParseLetter(string token, out char ch)
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
