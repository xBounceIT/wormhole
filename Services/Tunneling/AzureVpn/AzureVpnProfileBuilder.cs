using System;
using System.Text;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Synthesizes an OpenVPN profile (.ovpn text) from <see cref="AzureVpnSettings"/>. The directive
/// set mirrors what the native Azure VPN Client drives its embedded OpenVPN stack with: TLS to the
/// gateway FQDN on 443, server cert validated against DigiCert Global Root G2 with the subject
/// pinned to the gateway hostname, AES-256-GCM / SHA-256, an optional <c>tls-auth</c> static key
/// from the profile's <c>&lt;serversecret&gt;</c>, and <c>auth-user-pass</c> — the provider feeds
/// the Entra access token as the password at connect time. The result is fed into the existing
/// OpenVPN sidecar via <see cref="Wormhole.Services.Tunneling.OpenVpn.OpenVpnSidecarConfig.ProfileOvpn"/>.
///
/// Pure — no IO, no logging, no clock — to keep golden-file tests deterministic.
///
/// Every user-supplied field that becomes part of an OpenVPN directive is validated before
/// concatenation: the .ovpn syntax is newline-terminated, so an unsanitized newline in a server
/// name would let an imported profile inject directives like <c>up /path/to/script</c> which
/// OpenVPN executes at connect time.
/// </summary>
public static class AzureVpnProfileBuilder
{
    // DigiCert Global Root G2 — the root CA Azure P2S gateway TLS certificates
    // (*.vpn.azure.com) chain to. Public root certificate; safe to embed.
    internal const string DigiCertGlobalRootG2Pem = """
        -----BEGIN CERTIFICATE-----
        MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
        MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
        d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
        MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
        MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
        b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
        9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
        2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
        1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
        q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
        tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
        vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
        BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
        5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
        1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
        NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
        Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
        8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
        pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
        MrY=
        -----END CERTIFICATE-----
        """;

    /// <summary>Expected length of <c>&lt;serversecret&gt;</c>: a 2048-bit OpenVPN Static key V1 as hex.</summary>
    internal const int ServerSecretHexLength = 512;

    public static string Build(AzureVpnSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.Servers.Count == 0 || string.IsNullOrWhiteSpace(settings.Servers[0]))
            throw new InvalidOperationException("At least one gateway server FQDN is required.");

        ValidateFieldSafety(settings);

        var ca = string.IsNullOrWhiteSpace(settings.CaPem) ? DigiCertGlobalRootG2Pem : settings.CaPem;
        var primary = settings.Servers[0].Trim();

        var sb = new StringBuilder(2048 + ca.Length);
        // Use \n explicitly (not Environment.NewLine) so the synthesized profile is byte-identical
        // across platforms — keeps the golden-file test stable on CI vs. dev machines.
        sb.Append("client").Append('\n');
        sb.Append("dev tun").Append('\n');
        sb.Append(settings.Protocol == AzureVpnTransport.Udp ? "proto udp" : "proto tcp-client").Append('\n');
        // Every server entry becomes a `remote` — OpenVPN falls over to the next on connect
        // failure; HA gateway profiles carry multiple entries. Azure's OpenVPN listener is
        // always on 443.
        foreach (var server in settings.Servers)
        {
            if (string.IsNullOrWhiteSpace(server)) continue;
            sb.Append("remote ").Append(server.Trim()).Append(" 443").Append('\n');
        }
        sb.Append("nobind").Append('\n');
        sb.Append("persist-key").Append('\n');
        sb.Append("persist-tun").Append('\n');
        sb.Append("remote-cert-tls server").Append('\n');
        // Pin the primary gateway CN. HA pairs share a wildcard *.vpn.azure.com cert, so the
        // single allowed verify-x509-name directive covers failover in practice.
        sb.Append("verify-x509-name ").Append(primary).Append(" name").Append('\n');
        sb.Append("auth SHA256").Append('\n');
        sb.Append("cipher AES-256-GCM").Append('\n');
        sb.Append("tls-version-min 1.2").Append('\n');
        sb.Append("auth-user-pass").Append('\n');

        AppendPemBlock(sb, "ca", ca);

        if (!string.IsNullOrWhiteSpace(settings.ServerSecretHex))
        {
            sb.Append("key-direction 1").Append('\n');
            sb.Append("<tls-auth>").Append('\n');
            AppendStaticKey(sb, settings.ServerSecretHex.Trim());
            sb.Append("</tls-auth>").Append('\n');
        }

        return sb.ToString();
    }

    /// <summary>
    /// Rejects field content that could inject extra OpenVPN directives into the synthesized
    /// profile, plus a malformed <c>serversecret</c> (which would otherwise surface as an opaque
    /// handshake timeout instead of a clear client-side message). Shared with the save-time gate in
    /// <c>TunnelConfigsViewModel.ValidateAzureVpn</c> so the persistence layer rejects the
    /// identical inputs.
    /// </summary>
    internal static void ValidateFieldSafety(AzureVpnSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        foreach (var server in settings.Servers)
        {
            RejectControlCharsOrQuotes(server, "Server");
        }
        if (!IsServerSecretHexValid(settings.ServerSecretHex))
        {
            throw new InvalidOperationException(
                $"The server secret (tls-auth key) must be {ServerSecretHexLength} hexadecimal characters "
                + "(the <serversecret> value from azurevpnconfig.xml), or empty.");
        }
        // RFC 7468 PEM is only base64 + BEGIN/END armor, so any '<' or '>' is always either
        // malformed or hostile (a literal </ca> would close the inline block early and turn the
        // rest of the field into directives).
        if (!string.IsNullOrWhiteSpace(settings.CaPem) &&
            (settings.CaPem.Contains('<') || settings.CaPem.Contains('>')))
        {
            throw new InvalidOperationException(
                "CA certificate (PEM) contains angle bracket characters that don't belong in a PEM body — "
                + "refusing to write a malformed/injectable profile.");
        }
    }

    /// <summary>
    /// True when <paramref name="candidate"/> is a usable <c>serversecret</c>: either empty
    /// (gateway has no tls-auth key) or exactly <see cref="ServerSecretHexLength"/> hex characters
    /// after trimming. Shared by <see cref="ValidateFieldSafety"/> (the connect/save-time gate) and
    /// the tunnel editor's live validation so both apply one definition of "valid key".
    /// </summary>
    public static bool IsServerSecretHexValid(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return true;
        var secret = candidate.Trim();
        return secret.Length == ServerSecretHexLength && IsHex(secret);
    }

    private static void RejectControlCharsOrQuotes(string value, string fieldName)
    {
        for (var i = 0; i < value.Length; i++)
        {
            var ch = value[i];
            if (char.IsControl(ch) || ch == '"' || ch == '\'' || ch == ' ' || ch == '\t')
            {
                throw new InvalidOperationException(
                    $"{fieldName} contains a forbidden character (U+{(int)ch:X4}) at position {i}. "
                    + "Gateway entries must be bare FQDNs.");
            }
        }
    }

    private static bool IsHex(string value)
    {
        foreach (var ch in value)
        {
            if (!char.IsAsciiHexDigit(ch)) return false;
        }
        return true;
    }

    // 512 hex chars → the standard OpenVPN Static key V1 armor: 16 lines of 32 chars.
    private static void AppendStaticKey(StringBuilder sb, string hex)
    {
        sb.Append("-----BEGIN OpenVPN Static key V1-----").Append('\n');
        for (var i = 0; i < hex.Length; i += 32)
        {
            sb.Append(hex, i, Math.Min(32, hex.Length - i)).Append('\n');
        }
        sb.Append("-----END OpenVPN Static key V1-----").Append('\n');
    }

    private static void AppendPemBlock(StringBuilder sb, string tag, string pem)
    {
        sb.Append('<').Append(tag).Append('>').Append('\n');
        AppendNormalizedPemBody(sb, pem);
        sb.Append('\n');
        sb.Append("</").Append(tag).Append('>').Append('\n');
    }

    // Normalize CRLF/CR -> LF and strip leading indentation inside PEM bodies so the synthesized
    // profile stays byte-stable regardless of where the value came from (raw-string constant,
    // Windows clipboard, Unix file).
    private static void AppendNormalizedPemBody(StringBuilder sb, string pem)
    {
        var first = true;
        foreach (var rawLine in pem.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;
            if (!first) sb.Append('\n');
            sb.Append(line);
            first = false;
        }
    }
}
