using System;
using System.Collections.Generic;
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
    // The modern AEAD suites we always offer first. The profile's OWN declared cipher is then
    // appended to this list and used as the data-ciphers-fallback, so negotiation also succeeds
    // against legacy CBC-only gateways — including the small Stormshield appliances that use
    // AES-128-CBC (and AES-192-CBC), not just AES-256-CBC.
    private const string AeadDataCiphers = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305";
    private const string DefaultCbcCipher = "AES-256-CBC";

    public static string Normalize(string ovpn)
    {
        if (string.IsNullOrWhiteSpace(ovpn))
            throw new InvalidOperationException("The Stormshield OpenVPN profile is empty.");

        var sb = new StringBuilder(ovpn.Length + 160);
        var hasCipher = false;
        var hasDataCiphers = false;
        // The value of the profile's `cipher` directive (e.g. "AES-128-CBC"), used to derive the
        // data-ciphers fallback so it matches the gateway's actual cipher rather than assuming 256.
        string? profileCipher = null;
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

            if (Eq(firstToken, "cipher"))
            {
                hasCipher = true;
                // Capture the declared cipher (last one wins, matching OpenVPN directive semantics).
                profileCipher = ParseDirectiveValue(trimmed, "cipher") ?? profileCipher;
            }
            if (Eq(firstToken, "data-ciphers")) hasDataCiphers = true;

            sb.Append(rawLine).Append('\n');
        }

        // Legacy single-cipher profile without an NCP list → add one so modern OpenVPN negotiates.
        // Derive the fallback (and ensure it's offered) from the profile's own cipher so AES-128/192
        // -CBC gateways negotiate too, not just AES-256-CBC.
        if (hasCipher && !hasDataCiphers)
        {
            var fallback = string.IsNullOrEmpty(profileCipher) ? DefaultCbcCipher : profileCipher!;
            sb.Append("data-ciphers ").Append(BuildDataCiphersList(fallback)).Append('\n');
            sb.Append("data-ciphers-fallback ").Append(fallback).Append('\n');
        }

        return sb.ToString();
    }

    /// <summary>
    /// Inlines file-referenced key material into an OpenVPN profile: a directive such as
    /// <c>ca "CA.cert.pem"</c> / <c>cert "x.pem"</c> / <c>key "y.pem"</c> (also <c>tls-crypt</c> /
    /// <c>tls-auth</c> / <c>tls-crypt-v2</c> / <c>extra-certs</c>) is replaced with the equivalent
    /// inline <c>&lt;ca&gt;…&lt;/ca&gt;</c> block, reading the referenced file's text via
    /// <paramref name="resolveFile"/>. This is needed for the Stormshield v5 native flow, whose
    /// <c>auth/config.html</c> download returns an <c>openvpn_client.zip</c> bundle that ships the
    /// <c>.ovpn</c> and its PEMs as <em>separate</em> files referenced by name — the OpenVPN sidecar
    /// wants a self-contained profile. A directive whose file can't be resolved (or that is already an
    /// inline block) is left untouched. Conservative and line-oriented, mirroring <see cref="Normalize"/>:
    /// bytes inside an existing inline block are never reinterpreted as directives. Pure — the caller
    /// supplies the file lookup, so this stays IO-free and deterministically testable.
    /// </summary>
    public static string InlineFileReferences(string ovpn, Func<string, string?> resolveFile)
        => InlineFileReferences(ovpn, resolveFile, out _);

    /// <summary>
    /// Overload that also reports any file-referenced directive whose file could NOT be resolved (left
    /// as a dangling reference). The v5 bundle assembler treats a non-empty list as a fatal "incomplete
    /// bundle", so a truncated / renamed bundle fails with an actionable message instead of silently
    /// producing a profile the OpenVPN sidecar can't load.
    /// </summary>
    public static string InlineFileReferences(
        string ovpn, Func<string, string?> resolveFile, out IReadOnlyList<string> unresolvedReferences)
    {
        ArgumentNullException.ThrowIfNull(resolveFile);
        unresolvedReferences = Array.Empty<string>();
        if (string.IsNullOrEmpty(ovpn)) return ovpn;

        var unresolved = new List<string>();
        var sb = new StringBuilder(ovpn.Length + 256);
        string? openBlock = null;

        foreach (var rawLine in EnumerateLines(ovpn))
        {
            var trimmed = rawLine.Trim();

            if (openBlock is not null)
            {
                sb.Append(rawLine).Append('\n');
                if (IsCloseTag(trimmed, openBlock)) openBlock = null;
                continue;
            }
            if (TryReadOpenTag(trimmed, out var blockName))
            {
                openBlock = blockName;
                sb.Append(rawLine).Append('\n');
                continue;
            }

            var directive = FirstToken(trimmed);
            if (IsInlinable(directive))
            {
                // The firewall quotes the filename (cert "openvpnclient.cert.pem"); a quoted name may
                // legitimately contain spaces, so parse it quote-aware rather than splitting on space.
                var fileName = ParseFileArgument(trimmed, directive);
                if (!string.IsNullOrEmpty(fileName))
                {
                    var content = resolveFile(fileName!);
                    if (!string.IsNullOrEmpty(content))
                    {
                        var tag = directive.ToLowerInvariant();
                        sb.Append('<').Append(tag).Append(">\n");
                        sb.Append(content!.Replace("\r\n", "\n").Replace('\r', '\n').TrimEnd('\n')).Append('\n');
                        sb.Append("</").Append(tag).Append(">\n");
                        continue;
                    }
                    // Referenced a file the bundle didn't provide — record it; leave the line untouched.
                    unresolved.Add(fileName!);
                }
            }

            sb.Append(rawLine).Append('\n');
        }

        unresolvedReferences = unresolved;
        return sb.ToString();
    }

    // Reads a directive's filename argument quote-aware: a leading double-quote captures everything up
    // to the closing quote (OpenVPN filenames may contain spaces); otherwise the first whitespace-
    // delimited token. Distinct from ParseDirectiveValue (the cipher path), which always splits on space.
    private static string? ParseFileArgument(string trimmedLine, string directive)
    {
        if (trimmedLine.Length <= directive.Length) return null;
        var rest = trimmedLine.AsSpan(directive.Length);
        var i = 0;
        while (i < rest.Length && (rest[i] == ' ' || rest[i] == '\t')) i++;
        if (i >= rest.Length) return null;
        if (rest[i] == '"')
        {
            i++;
            var start = i;
            while (i < rest.Length && rest[i] != '"') i++;
            return rest[start..i].ToString();
        }
        var tokenStart = i;
        while (i < rest.Length && rest[i] != ' ' && rest[i] != '\t') i++;
        return rest[tokenStart..i].ToString();
    }

    private static bool IsInlinable(string directive) =>
        Eq(directive, "ca") || Eq(directive, "cert") || Eq(directive, "key")
        || Eq(directive, "tls-crypt") || Eq(directive, "tls-auth")
        || Eq(directive, "tls-crypt-v2") || Eq(directive, "extra-certs");

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

    // Reads the first argument of a directive from an already-trimmed line whose first token is
    // <paramref name="directive"/> (e.g. "AES-128-CBC" from "cipher AES-128-CBC"). Returns null when
    // the directive has no argument.
    private static string? ParseDirectiveValue(string trimmedLine, string directive)
    {
        if (trimmedLine.Length <= directive.Length) return null;
        var rest = trimmedLine[directive.Length..];
        var start = 0;
        while (start < rest.Length && (rest[start] == ' ' || rest[start] == '\t')) start++;
        var end = start;
        while (end < rest.Length && rest[end] != ' ' && rest[end] != '\t') end++;
        return end > start ? rest[start..end] : null;
    }

    // The negotiation list: the modern AEAD suites plus the profile's own cipher (so a CBC-only
    // gateway can still match). Skips appending the profile cipher when it's already one of the AEAD
    // suites, to avoid a duplicate entry.
    private static string BuildDataCiphersList(string profileCipher)
    {
        if (IsAeadSuite(profileCipher)) return AeadDataCiphers;
        return AeadDataCiphers + ":" + profileCipher;
    }

    private static bool IsAeadSuite(string cipher) =>
        Eq(cipher, "AES-256-GCM") || Eq(cipher, "AES-128-GCM") || Eq(cipher, "CHACHA20-POLY1305");
}
