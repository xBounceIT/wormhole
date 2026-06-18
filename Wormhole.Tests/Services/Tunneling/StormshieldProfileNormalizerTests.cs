using System;
using System.Collections.Generic;
using System.Linq;
using Wormhole.Models;
using Wormhole.Services.Tunneling.Stormshield;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class StormshieldProfileNormalizerTests
{
    [Fact]
    public void Normalize_InjectsDataCiphers_WhenOnlyLegacyCipherPresent()
    {
        // Older Stormshield firewalls emit `cipher AES-256-CBC` with no NCP list; modern OpenVPN 2.6
        // then aborts with "no shared cipher". The normalizer must add a data-ciphers list.
        const string ovpn = "client\ndev tun\nremote fw.example.com 443 tcp\ncipher AES-256-CBC\nauth SHA256\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.Contains("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC", result);
        Assert.Contains("data-ciphers-fallback AES-256-CBC", result);
        // Original directives are preserved untouched.
        Assert.Contains("cipher AES-256-CBC", result);
        Assert.Contains("remote fw.example.com 443 tcp", result);
    }

    [Fact]
    public void InlineFileReferences_InlinesReferencedFiles_AndReportsUnresolved()
    {
        const string ovpn = "client\nca \"CA.cert.pem\"\ncert \"client.pem\"\nkey \"missing.pem\"\n";
        var files = new Dictionary<string, string>
        {
            ["CA.cert.pem"] = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
            ["client.pem"] = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
        };

        var result = StormshieldProfileNormalizer.InlineFileReferences(
            ovpn, name => files.TryGetValue(name, out var c) ? c : null, out var unresolved);

        Assert.Contains("<ca>", result);
        Assert.Contains("<cert>", result);
        Assert.DoesNotContain("ca \"CA.cert.pem\"", result);
        // The missing key is left as a dangling reference AND reported to the caller.
        Assert.Equal("missing.pem", Assert.Single(unresolved));
        Assert.Contains("key \"missing.pem\"", result);
    }

    [Fact]
    public void InlineFileReferences_HandlesQuotedFilenameWithSpaces()
    {
        const string ovpn = "client\nca \"My CA.pem\"\n";

        var result = StormshieldProfileNormalizer.InlineFileReferences(
            ovpn, name => name == "My CA.pem" ? "PEMBODY" : null, out var unresolved);

        Assert.Empty(unresolved);
        Assert.Contains("<ca>\nPEMBODY\n</ca>", result);
    }

    [Fact]
    public void Normalize_PreservesExistingDataCiphers_OnRealV5Profile()
    {
        // The confirmed-live v5 bundle already declares `data-ciphers AES-256-CBC`; the normalizer must
        // NOT add a second data-ciphers / data-ciphers-fallback, and must preserve the auth directives
        // verbatim (the sidecar is OpenVPN3 + mbedTLS — no @SECLEVEL gate). It MUST, however, strip the
        // `tls-cipher` pin — the mbedTLS backend can't resolve that OpenSSL-named suite and the
        // control-channel handshake then silently times out (confirmed live).
        const string ovpn =
            "client\ndev tun\ncipher AES-256-CBC\ndata-ciphers AES-256-CBC\n"
            + "tls-cipher TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256\nauth SHA256\n"
            + "remote 151.84.99.155 1194 udp\nremote 151.84.99.155 443 tcp\n"
            + "<ca>\nINLINE-CA\n</ca>\nverb 0\nauth-user-pass\nauth-retry interact\nauth-nocache\nreneg-sec 0\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        var dataCiphersLines = result.Split('\n').Count(l => l.TrimStart().StartsWith("data-ciphers ", StringComparison.Ordinal));
        Assert.Equal(1, dataCiphersLines);
        Assert.Contains("data-ciphers AES-256-CBC", result);
        Assert.DoesNotContain("data-ciphers-fallback", result);
        Assert.DoesNotContain("tls-cipher", result);
        Assert.Contains("auth SHA256", result);
        Assert.Contains("auth-retry interact", result);
        Assert.Contains("auth-nocache", result);
        Assert.Contains("reneg-sec 0", result);
        Assert.Contains("<ca>\nINLINE-CA\n</ca>", result);
    }

    [Theory]
    [InlineData("tls-cipher TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256")]
    [InlineData("tls-cipher DEFAULT")]
    [InlineData("tls-ciphersuites TLS_AES_256_GCM_SHA384")]
    public void Normalize_StripsTlsCipherPin(string tlsLine)
    {
        // The sidecar's mbedTLS backend can't negotiate from the firewall's pinned OpenSSL/IANA-named
        // suite, so the directive must be removed to let mbedTLS use its default suite set. The rest of
        // the profile (including the data-channel `cipher`) is untouched.
        var ovpn = $"client\ndev tun\nremote fw 443\ncipher AES-256-CBC\n{tlsLine}\nauth SHA256\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.DoesNotContain(tlsLine.Split(' ')[0], result); // neither tls-cipher nor tls-ciphersuites
        Assert.Contains("cipher AES-256-CBC", result);
        Assert.Contains("auth SHA256", result);
    }

    [Theory]
    [InlineData("AES-128-CBC")]
    [InlineData("AES-192-CBC")]
    public void Normalize_DerivesDataCiphersFromProfileCipher(string profileCipher)
    {
        // Smaller Stormshield appliances use AES-128-CBC; the injected negotiation list AND the
        // fallback must offer the profile's actual cipher, not assume AES-256-CBC.
        var ovpn = $"client\ndev tun\nremote fw 443\ncipher {profileCipher}\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.Contains($"data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:{profileCipher}", result);
        Assert.Contains($"data-ciphers-fallback {profileCipher}", result);
    }

    [Fact]
    public void Normalize_DoesNotDuplicateAeadProfileCipher()
    {
        // A GCM profile cipher is already in the AEAD list — it must not be appended a second time.
        var ovpn = "client\ncipher AES-256-GCM\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.Contains("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n", result);
        Assert.Contains("data-ciphers-fallback AES-256-GCM", result);
    }

    [Fact]
    public void ApplyTransportOverride_Auto_ReturnsProfileUnchanged()
    {
        const string ovpn = "client\nproto udp\nremote fw.example.com 1194 udp\n";

        var result = StormshieldProfileNormalizer.ApplyTransportOverride(
            ovpn, StormshieldOpenVpnTransportOverride.Auto);

        Assert.Equal(ovpn, result);
    }

    [Fact]
    public void ApplyTransportOverride_ForceTcp_KeepsTcpRemoteAndRewritesGlobalProto()
    {
        const string ovpn =
            "client\nproto udp\nremote fw.example.com 1194 udp\nremote fw.example.com 443 tcp\n"
            + "<ca>\nremote text inside cert\n</ca>\n";

        var result = StormshieldProfileNormalizer.ApplyTransportOverride(
            ovpn, StormshieldOpenVpnTransportOverride.ForceTcp);

        Assert.Contains("proto tcp-client\n", result);
        Assert.DoesNotContain("remote fw.example.com 1194 udp", result);
        Assert.Contains("remote fw.example.com 443 tcp", result);
        Assert.Contains("<ca>\nremote text inside cert\n</ca>", result);
    }

    [Fact]
    public void ApplyTransportOverride_ForceUdp_KeepsUdpRemoteAndDropsTcpRemote()
    {
        const string ovpn = "client\nremote fw.example.com 1194 udp\nremote fw.example.com 443 tcp\n";

        var result = StormshieldProfileNormalizer.ApplyTransportOverride(
            ovpn, StormshieldOpenVpnTransportOverride.ForceUdp);

        Assert.Contains("remote fw.example.com 1194 udp", result);
        Assert.DoesNotContain("remote fw.example.com 443 tcp", result);
    }

    [Fact]
    public void ApplyTransportOverride_UnqualifiedRemote_AddsProtoWhenMissing()
    {
        const string ovpn = "client\nremote fw.example.com 443\n";

        var result = StormshieldProfileNormalizer.ApplyTransportOverride(
            ovpn, StormshieldOpenVpnTransportOverride.ForceTcp);

        Assert.Contains("remote fw.example.com 443", result);
        Assert.Contains("proto tcp-client\n", result);
    }

    [Fact]
    public void ApplyTransportOverride_NoMatchingRemote_Throws()
    {
        const string ovpn = "client\nremote fw.example.com 1194 udp\n";

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StormshieldProfileNormalizer.ApplyTransportOverride(
                ovpn, StormshieldOpenVpnTransportOverride.ForceTcp));

        Assert.Contains("no TCP remote", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ApplyTransportOverride_ConnectionBlocks_DropsOppositeTransportBlock()
    {
        const string ovpn =
            "client\n"
            + "<connection>\nremote fw.example.com 1194 udp\n</connection>\n"
            + "<connection>\nremote fw.example.com 443 tcp\n</connection>\n"
            + "<ca>\nremote should-stay-opaque 1194 udp\n</ca>\n";

        var result = StormshieldProfileNormalizer.ApplyTransportOverride(
            ovpn, StormshieldOpenVpnTransportOverride.ForceTcp);

        Assert.DoesNotContain("remote fw.example.com 1194 udp", result);
        Assert.Contains("<connection>\nremote fw.example.com 443 tcp\n</connection>", result);
        Assert.Contains("<ca>\nremote should-stay-opaque 1194 udp\n</ca>", result);
    }

    [Fact]
    public void ApplyTransportOverride_ConnectionBlockWithMixedRemotes_KeepsDesiredRemote()
    {
        const string ovpn =
            "client\n"
            + "<connection>\n"
            + "proto udp\n"
            + "remote fw.example.com 1194 udp\n"
            + "remote fw.example.com 443 tcp\n"
            + "</connection>\n";

        var result = StormshieldProfileNormalizer.ApplyTransportOverride(
            ovpn, StormshieldOpenVpnTransportOverride.ForceTcp);

        Assert.Contains("<connection>\nproto tcp-client\nremote fw.example.com 443 tcp\n</connection>", result);
        Assert.DoesNotContain("remote fw.example.com 1194 udp", result);
    }

    [Fact]
    public void ApplyTransportOverride_ConnectionBlockUnqualifiedRemote_InsertsProtoInsideBlock()
    {
        const string ovpn = "client\n<connection>\nremote fw.example.com 443\n</connection>\n";

        var result = StormshieldProfileNormalizer.ApplyTransportOverride(
            ovpn, StormshieldOpenVpnTransportOverride.ForceTcp);

        Assert.Contains("<connection>\nremote fw.example.com 443\nproto tcp-client\n</connection>", result);
    }

    [Fact]
    public void ApplyTransportOverride_ConnectionBlockProto_FiltersUnqualifiedRemote()
    {
        const string ovpn =
            "client\n"
            + "<connection>\nremote fw.example.com 1194\nproto udp\n</connection>\n"
            + "<connection>\nremote fw.example.com 443\nproto tcp\n</connection>\n";

        var result = StormshieldProfileNormalizer.ApplyTransportOverride(
            ovpn, StormshieldOpenVpnTransportOverride.ForceTcp);

        Assert.DoesNotContain("remote fw.example.com 1194", result);
        Assert.Contains("<connection>\nremote fw.example.com 443\nproto tcp-client\n</connection>", result);
    }

    [Fact]
    public void ApplyTransportOverride_ConnectionBlockProtoWithoutMatchingTransport_Throws()
    {
        const string ovpn = "client\n<connection>\nremote fw.example.com 1194\nproto udp\n</connection>\n";

        var ex = Assert.Throws<InvalidOperationException>(() =>
            StormshieldProfileNormalizer.ApplyTransportOverride(
                ovpn, StormshieldOpenVpnTransportOverride.ForceTcp));

        Assert.Contains("no TCP remote", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Normalize_DoesNotInjectDataCiphers_WhenAlreadyPresent()
    {
        const string ovpn = "client\ncipher AES-256-CBC\ndata-ciphers AES-256-GCM:AES-256-CBC\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.DoesNotContain("data-ciphers-fallback", result);
        Assert.Contains("data-ciphers AES-256-GCM:AES-256-CBC", result);
    }

    [Fact]
    public void Normalize_DoesNotInjectDataCiphers_WhenNoCipherDirective()
    {
        const string ovpn = "client\ndev tun\nremote fw.example.com 1194 udp\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.DoesNotContain("data-ciphers", result);
    }

    [Theory]
    [InlineData("compress lz4")]
    [InlineData("comp-lzo yes")]
    [InlineData("comp-noadapt")]
    public void Normalize_StripsRealCompressionDirectives(string compressionLine)
    {
        // Stormshield itself recommends disabling compression (VORACLE), so any compression directive
        // that can enable real compression is removed regardless of which variant the firewall emitted.
        var ovpn = $"client\ndev tun\nremote fw.example.com 443\n{compressionLine}\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.DoesNotContain(compressionLine, result);
        Assert.Contains("remote fw.example.com 443", result);
    }

    [Theory]
    [InlineData("comp-lzo no")]
    [InlineData("compress")]
    [InlineData("compress stub")]
    [InlineData("compress stub-v2")]
    public void Normalize_PreservesNoCompressionFramingDirectives(string compressionLine)
    {
        // These directives do not enable payload compression. They preserve legacy OpenVPN framing
        // where data-channel packets carry a NO_COMPRESS marker byte; old Stormshield gateways still
        // require that marker even though compression itself is disabled.
        var ovpn = $"client\ndev tun\nremote fw.example.com 443\n{compressionLine}\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.Contains(compressionLine, result);
        Assert.Contains("remote fw.example.com 443", result);
    }

    [Fact]
    public void ApplyLegacyCompressionStub_AddsCompLzoNo_WhenMissing()
    {
        const string ovpn = "client\ndev tun\nremote fw.example.com 443 tcp\n";

        var result = StormshieldProfileNormalizer.ApplyLegacyCompressionStub(ovpn);

        Assert.Contains("comp-lzo no\n", result);
    }

    [Theory]
    [InlineData("comp-lzo no")]
    [InlineData("compress")]
    [InlineData("compress stub")]
    public void ApplyLegacyCompressionStub_DoesNotDuplicateExistingFraming(string compressionLine)
    {
        var ovpn = $"client\ndev tun\n{compressionLine}\n";

        var result = StormshieldProfileNormalizer.ApplyLegacyCompressionStub(ovpn);

        Assert.Equal(1, result.Split('\n').Count(l => l.Trim().Equals(compressionLine, StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain("comp-lzo no\ncomp-lzo no", result);
    }

    [Fact]
    public void ApplyLegacyCompressionStub_IgnoresInlineBlockContent()
    {
        const string ovpn =
            "client\n" +
            "<ca>\n" +
            "compress\n" +
            "</ca>\n";

        var result = StormshieldProfileNormalizer.ApplyLegacyCompressionStub(ovpn);

        Assert.Contains("<ca>\ncompress\n</ca>", result);
        Assert.Contains("comp-lzo no\n", result);
    }

    [Fact]
    public void Normalize_PreservesInlineBlockContentVerbatim()
    {
        // A base64 body line can collide with a directive keyword (lowercase letters are valid
        // base64), so content inside <ca>/<cert>/<key> blocks must NEVER be filtered. Here a lone
        // "compress" line lives inside <ca>; only the top-level "compress lz4" must be stripped.
        const string ovpn =
            "client\n" +
            "dev tun\n" +
            "remote fw.example.com 443\n" +
            "<ca>\n" +
            "compress\n" +
            "MIIBlevelbase64==\n" +
            "</ca>\n" +
            "compress lz4\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        // Top-level compression directive removed...
        Assert.DoesNotContain("compress lz4", result);
        // ...but the identical-looking line inside the inline block survived verbatim.
        Assert.Contains("<ca>\ncompress\nMIIBlevelbase64==\n</ca>", result);
    }

    [Fact]
    public void Normalize_NormalizesCrlfToLf()
    {
        const string ovpn = "client\r\ndev tun\r\nremote fw 443\r\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.DoesNotContain("\r", result);
        Assert.Contains("client\ndev tun\n", result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   \n  \n")]
    public void Normalize_ThrowsOnEmpty(string ovpn)
    {
        Assert.Throws<InvalidOperationException>(() => StormshieldProfileNormalizer.Normalize(ovpn));
    }
}
