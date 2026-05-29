using System.Text.RegularExpressions;

namespace Wormhole.Services.Ssh;

/// <summary>
/// Helpers for turning raw PTY byte streams (which carry ANSI/VT escape sequences, OSC
/// strings, and bare carriage returns) into readable plain text for an AI agent.
/// Best-effort: it removes control sequences rather than emulating a screen, so cursor
/// positioning is flattened, not faithfully rendered.
/// </summary>
internal static partial class TerminalText
{
    // CSI: ESC [ ... final-byte (e.g. colors, cursor moves, "[0m").
    [GeneratedRegex(@"\x1B\[[0-?]*[ -/]*[@-~]", RegexOptions.Compiled)]
    private static partial Regex CsiRegex();

    // OSC: ESC ] ... terminated by BEL (\x07) or ST (ESC \). Used for window titles,
    // hyperlinks, clipboard, etc. Non-greedy so two OSCs in a row don't merge.
    [GeneratedRegex(@"\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)", RegexOptions.Compiled)]
    private static partial Regex OscRegex();

    // Other two-byte escapes (ESC followed by a single intermediate/final byte): charset
    // selection, keypad mode, etc. Excludes '[' and ']' which the patterns above own.
    [GeneratedRegex(@"\x1B[@-Z\\-_]", RegexOptions.Compiled)]
    private static partial Regex EscRegex();

    /// <summary>
    /// Strip ANSI/VT control sequences and normalize line endings to "\n". A lone
    /// carriage return (cursor-to-column-0 without a newline, common in progress bars)
    /// is dropped; CRLF collapses to LF.
    /// </summary>
    public static string StripAnsi(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        text = OscRegex().Replace(text, string.Empty);
        text = CsiRegex().Replace(text, string.Empty);
        text = EscRegex().Replace(text, string.Empty);
        // Collapse CRLF first, then drop any remaining bare CRs so progress-bar redraws
        // don't leave stray carriage returns in the captured text.
        text = text.Replace("\r\n", "\n").Replace("\r", string.Empty);
        return text;
    }
}
