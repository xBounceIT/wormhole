using System;
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
    public void Normalize_StripsCompressionDirectives(string compressionLine)
    {
        // Stormshield itself recommends disabling compression (VORACLE), so any compression directive
        // is removed regardless of which variant the firewall emitted.
        var ovpn = $"client\ndev tun\nremote fw.example.com 443\n{compressionLine}\n";

        var result = StormshieldProfileNormalizer.Normalize(ovpn);

        Assert.DoesNotContain(compressionLine, result);
        Assert.Contains("remote fw.example.com 443", result);
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
