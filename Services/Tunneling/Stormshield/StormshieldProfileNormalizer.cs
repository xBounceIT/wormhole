using System;
using System.Text;

namespace Wormhole.Services.Tunneling.Stormshield;

/// <summary>
/// Normalizes an OpenVPN profile served by (or downloaded from) a Stormshield SNS firewall before
/// it is handed to the OpenVPN3 sidecar. Two real-world interop issues, both confirmed against
/// captured Stormshield <c>.ovpn</c> files, are fixed here:
///
/// <list type="number">
///   <item><b>Cipher negotiation.</b> Older firewalls emit only <c>cipher AES-256-CBC</c> with no
///   <c>data-ciphers</c> NCP list. Modern OpenVPN 2.6 / OpenSSL 3.x then aborts with
///   "Data channel cipher negotiation failed (no shared cipher)". When a profile pins a single
///   <c>cipher</c> but carries no <c>data-ciphers</c>, we append a negotiation list that offers the
///   modern AEAD suites first and keeps CBC as the fallback so both old and new firewalls connect.
///   (This mirrors what <c>WatchguardProfileBuilder</c> emits for the same reason.)</item>
///   <item><b>Compression.</b> Stormshield profiles historically carry <c>compress lz4</c>, but
///   Stormshield itself now recommends disabling compression because of the VORACLE class of attacks.
///   Any <c>compress</c> / <c>comp-lzo</c> / <c>comp-noadapt</c> directive is stripped.</item>
/// </list>
///
/// <para>
/// The transform is line-oriented and deliberately conservative: inline <c>&lt;ca&gt;</c> /
/// <c>&lt;cert&gt;</c> / <c>&lt;key&gt;</c> / <c>&lt;tls-crypt&gt;</c> (etc.) blocks are copied
/// byte-for-byte — their base64 bodies are NEVER interpreted as directives (a PEM line can begin
/// with letters that collide with directive keywords, so tracking block boundaries is correctness,
/// not just tidiness). Pure — no IO, no clock — to keep tests deterministic.
/// </para>
/// </summary>
public static class StormshieldProfileNormalizer
{
    private const string DataCiphersList = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC";
    private const string DataCiphersFallback = "AES-256-CBC";

    public static string Normalize(string ovpn)
    {
        if (string.IsNullOrWhiteSpace(ovpn))
            throw new InvalidOperationException("The Stormshield OpenVPN profile is empty.");

        var sb = new StringBuilder(ovpn.Length + 160);
        var hasCipher = false;
        var hasDataCiphers = false;
        // Name of the inline block we're currently inside (e.g. "ca"), or null when outside one.
        string? openBlock = null;

        foreach (var rawLine in EnumerateLines(ovpn))
        {
            var trimmed = rawLine.Trim();

            // Inside an inline block: copy verbatim until the matching close tag. Do not inspect
            // the base64 body for directives.
            if (openBlock is not null)
            {
                sb.Append(rawLine).Append('\n');
                if (IsCloseTag(trimmed, openBlock)) openBlock = null;
                continue;
            }

            // Entering an inline block: a line that is exactly "<word>" (not "</word>").
            if (TryReadOpenTag(trimmed, out var blockName))
            {
                openBlock = blockName;
                sb.Append(rawLine).Append('\n');
                continue;
            }

            var firstToken = FirstToken(trimmed);

            // Drop compression directives (VORACLE — Stormshield recommends disabling).
            if (Eq(firstToken, "compress") || Eq(firstToken, "comp-lzo") || Eq(firstToken, "comp-noadapt"))
                continue;

            if (Eq(firstToken, "cipher")) hasCipher = true;
            if (Eq(firstToken, "data-ciphers")) hasDataCiphers = true;

            sb.Append(rawLine).Append('\n');
        }

        // Legacy single-cipher profile without an NCP list → add one so modern OpenVPN negotiates.
        if (hasCipher && !hasDataCiphers)
        {
            sb.Append("data-ciphers ").Append(DataCiphersList).Append('\n');
            sb.Append("data-ciphers-fallback ").Append(DataCiphersFallback).Append('\n');
        }

        return sb.ToString();
    }

    // Split on LF after collapsing CRLF/CR to LF, so the normalized profile is byte-stable
    // regardless of where the input was pasted from (Windows clipboard, Unix file, HTTP body).
    private static string[] EnumerateLines(string text) =>
        text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

    private static bool TryReadOpenTag(string trimmed, out string name)
    {
        name = string.Empty;
        if (trimmed.Length < 3 || trimmed[0] != '<' || trimmed[^1] != '>' || trimmed[1] == '/')
            return false;
        name = trimmed[1..^1];
        // A directive value can contain '<' (rare), so require the interior to look like a bare
        // tag name (no whitespace / angle brackets) before treating it as a block opener.
        foreach (var ch in name)
        {
            if (char.IsWhiteSpace(ch) || ch == '<' || ch == '>') return false;
        }
        return name.Length > 0;
    }

    private static bool IsCloseTag(string trimmed, string blockName) =>
        trimmed.Length == blockName.Length + 3
        && trimmed[0] == '<' && trimmed[1] == '/' && trimmed[^1] == '>'
        && trimmed.AsSpan(2, blockName.Length).Equals(blockName, StringComparison.OrdinalIgnoreCase);

    private static string FirstToken(string line)
    {
        if (line.Length == 0 || line[0] == '#' || line[0] == ';') return string.Empty;
        var end = 0;
        while (end < line.Length && line[end] != ' ' && line[end] != '\t') end++;
        return line[..end];
    }

    private static bool Eq(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);
}
