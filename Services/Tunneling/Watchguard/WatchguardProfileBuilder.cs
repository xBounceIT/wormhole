using System;
using System.Text;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Watchguard;

/// <summary>
/// Synthesizes an OpenVPN profile (.ovpn text) from <see cref="WatchguardSettings"/>. The
/// directive set mirrors what a Firebox emits in its `.wgssl` bundle — TCP/443, NCP data
/// ciphers (newer Fireware) with AES-256-CBC fallback (older), SHA-256 auth, and inline
/// CA / client cert / client key blocks. The result is fed into the existing OpenVPN sidecar
/// via <see cref="Wormhole.Services.Tunneling.OpenVpn.OpenVpnSidecarConfig.ProfileOvpn"/>.
///
/// Pure — no IO, no logging, no clock — to keep golden-file tests deterministic.
///
/// Every user-supplied field that becomes part of an OpenVPN directive is validated before
/// concatenation. The .ovpn syntax is newline-terminated, so an unsanitized newline in any
/// field would let an attacker inject directives like `up /path/to/script` which OpenVPN
/// will execute under the sidecar's identity at connect time. We reject early with a clear
/// message rather than emit a malformed-but-dangerous profile.
/// </summary>
public static class WatchguardProfileBuilder
{
    public static string Build(WatchguardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (string.IsNullOrWhiteSpace(settings.Server))
            throw new InvalidOperationException("Server is required.");
        if (settings.Port is < 1 or > 65535)
            throw new InvalidOperationException("Port must be between 1 and 65535.");
        if (string.IsNullOrWhiteSpace(settings.CaPem))
            throw new InvalidOperationException("CA certificate (PEM) is required.");
        if (string.IsNullOrWhiteSpace(settings.ClientCertPem))
            throw new InvalidOperationException("Client certificate (PEM) is required.");
        if (string.IsNullOrWhiteSpace(settings.ClientKeyPem))
            throw new InvalidOperationException("Client private key (PEM) is required.");

        // Reject anything in Server / VerifyX509Name that would let the value inject extra
        // OpenVPN directives via newline or quote. A real hostname / DN never legitimately
        // contains these characters, so refusing them is a safe over-approximation.
        RejectControlCharsOrQuotes(settings.Server, "Server");
        if (!string.IsNullOrWhiteSpace(settings.VerifyX509Name))
            RejectControlCharsOrQuotes(settings.VerifyX509Name, "verify-x509-name subject");

        // PEM bodies are user-supplied content that we wrap in <ca>/<cert>/<key>. If they
        // contain the literal closing tag, OpenVPN's inline-block parser ends the block early
        // and treats whatever follows as more directives — same injection vector as Server.
        // RFC 7468 PEM only contains base64 + the BEGIN/END armor lines, so a `</ca>` (or
        // `</cert>`, `</key>`) inside the body is always either malformed or hostile.
        RejectInlineTagClose(settings.CaPem, "CA certificate", "ca");
        RejectInlineTagClose(settings.ClientCertPem, "Client certificate", "cert");
        RejectInlineTagClose(settings.ClientKeyPem, "Client private key", "key");

        var sb = new StringBuilder();
        // Use \n explicitly (not Environment.NewLine) so the synthesized profile is byte-identical
        // across platforms — keeps the golden-file test stable on CI vs. dev machines.
        sb.Append("client").Append('\n');
        sb.Append("dev tun").Append('\n');
        sb.Append("proto tcp-client").Append('\n');
        sb.Append("remote ").Append(settings.Server).Append(' ').Append(settings.Port).Append('\n');
        sb.Append("resolv-retry infinite").Append('\n');
        sb.Append("nobind").Append('\n');
        sb.Append("persist-key").Append('\n');
        sb.Append("persist-tun").Append('\n');
        sb.Append("remote-cert-tls server").Append('\n');
        // verify-x509-name pins the server cert subject so a MITM with a valid-but-different
        // cert can't impersonate the Firebox. Skipped when TrustServerCertificate is on so
        // self-signed Firebox deployments with non-stock cert subjects still connect — the CA
        // bundle the user provided is still enforced via remote-cert-tls + <ca> below.
        if (!settings.TrustServerCertificate && !string.IsNullOrWhiteSpace(settings.VerifyX509Name))
        {
            sb.Append("verify-x509-name \"").Append(settings.VerifyX509Name).Append("\" subject").Append('\n');
        }
        // NCP: newer Fireware negotiates AES-GCM, older falls back. Mirrors what the official
        // .wgssl profile carries on Fireware 12.x and matches what stock openvpn 2.5+ expects.
        sb.Append("data-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC").Append('\n');
        sb.Append("data-ciphers-fallback AES-256-CBC").Append('\n');
        sb.Append("cipher AES-256-CBC").Append('\n');
        sb.Append("auth SHA256").Append('\n');
        sb.Append("auth-user-pass").Append('\n');

        AppendPemBlock(sb, "ca", settings.CaPem);
        AppendPemBlock(sb, "cert", settings.ClientCertPem);
        AppendPemBlock(sb, "key", settings.ClientKeyPem);

        return sb.ToString();
    }

    private static void RejectControlCharsOrQuotes(string value, string fieldName)
    {
        foreach (var ch in value)
        {
            // Reject ALL control chars (including NUL, BEL, FF, VT, NEL, etc.) plus both
            // single and double quotes. Real hostnames and X.509 DNs use only printable
            // ASCII / Unicode without quotes or control bytes, so any of these in the field
            // is either malformed or hostile.
            if (char.IsControl(ch) || ch == '"' || ch == '\'')
                throw new InvalidOperationException(
                    $"{fieldName} contains a forbidden character (control char or quote).");
        }
    }

    private static void RejectInlineTagClose(string pem, string fieldName, string tag)
    {
        // RFC 7468 PEM never contains '<' or '>' characters in the body — they're not in the
        // base64 alphabet, BEGIN/END armor lines, or whitespace. Any '<' is therefore always
        // either malformed or an injection attempt. Rejecting the entire angle-bracket set is
        // strictly tighter than pattern-matching '</ca>' / '</ca >' / '< /ca>' / case variants,
        // and closes any future-parser-tolerance gap by construction.
        if (pem.Contains('<') || pem.Contains('>'))
            throw new InvalidOperationException(
                $"{fieldName} (PEM) contains angle bracket characters that don't belong in a PEM body — " +
                $"refusing to write a malformed/injectable profile (block tag: <{tag}>).");
    }

    private static void AppendPemBlock(StringBuilder sb, string tag, string pem)
    {
        sb.Append('<').Append(tag).Append('>').Append('\n');
        // Normalize CRLF/CR -> LF inside PEM bodies so the synthesized profile stays byte-stable
        // regardless of where the user pasted from (Windows clipboard, Unix file, browser).
        sb.Append(pem.Replace("\r\n", "\n").Replace("\r", "\n").TrimEnd('\n'));
        sb.Append('\n');
        sb.Append("</").Append(tag).Append('>').Append('\n');
    }
}
