using System;
using Wormhole.Models;
using Wormhole.Services.Tunneling.Watchguard;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class WatchguardProfileBuilderTests
{
    private static WatchguardSettings ValidSample() => new()
    {
        Server = "firebox.example.com",
        Port = 443,
        Username = "alice",
        Password = "s3cret",
        CaPem = "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----",
        ClientCertPem = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----",
        ClientKeyPem = "-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----",
    };

    [Fact]
    public void Build_EmitsCoreOpenVpnDirectives()
    {
        var profile = WatchguardProfileBuilder.Build(ValidSample());

        Assert.Contains("client\n", profile);
        Assert.Contains("dev tun\n", profile);
        Assert.Contains("proto tcp-client\n", profile);
        Assert.Contains("remote firebox.example.com 443\n", profile);
        Assert.Contains("remote-cert-tls server\n", profile);
        Assert.Contains("auth-user-pass\n", profile);
    }

    [Fact]
    public void Build_InlinesCaCertAndKeyBlocks()
    {
        var profile = WatchguardProfileBuilder.Build(ValidSample());

        Assert.Contains("<ca>\n-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n</ca>", profile);
        Assert.Contains("<cert>\n-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n</cert>", profile);
        Assert.Contains("<key>\n-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----\n</key>", profile);
    }

    [Fact]
    public void Build_PinsX509SubjectByDefault()
    {
        var profile = WatchguardProfileBuilder.Build(ValidSample());

        Assert.Contains("verify-x509-name", profile);
        Assert.Contains("Fireware_SSLVPN_Server", profile);
    }

    [Fact]
    public void Build_SkipsX509PinWhenTrustServerCertIsOn()
    {
        var settings = ValidSample();
        settings.TrustServerCertificate = true;

        var profile = WatchguardProfileBuilder.Build(settings);

        Assert.DoesNotContain("verify-x509-name", profile);
    }

    [Fact]
    public void Build_NormalizesCrlfInPemBlocks()
    {
        var settings = ValidSample();
        settings.CaPem = "-----BEGIN CERTIFICATE-----\r\nFAKECA\r\n-----END CERTIFICATE-----\r\n";

        var profile = WatchguardProfileBuilder.Build(settings);

        // No raw \r in the synthesized profile — keeps OpenVPN parsers happy on Windows pastes.
        Assert.DoesNotContain("\r", profile);
        Assert.Contains("-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----", profile);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public void Build_RejectsOutOfRangePort(int port)
    {
        var settings = ValidSample();
        settings.Port = port;

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }

    [Fact]
    public void Build_RejectsMissingServer()
    {
        var settings = ValidSample();
        settings.Server = "";

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }

    [Fact]
    public void Build_RejectsMissingCa()
    {
        var settings = ValidSample();
        settings.CaPem = "";

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }

    [Theory]
    [InlineData("evil\nremote attacker.com 443")]
    [InlineData("firebox\twith-tab")]
    [InlineData("firebox\rwith-cr")]
    [InlineData("firebox\"with-quote")]
    public void Build_RejectsServerWithControlCharsOrQuotes(string server)
    {
        // Regression: prior to the fix, `Server` was concatenated into the `remote …` directive
        // verbatim. A newline-bearing value lets the user (or an imported .wgssl) inject extra
        // OpenVPN directives like `up /path/to/script` which the sidecar would execute.
        var settings = ValidSample();
        settings.Server = server;

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }

    [Theory]
    [InlineData("foo\" subject\nscript-security 2\nup /tmp/pwn.sh\nverify-x509-name \"bar")]
    [InlineData("OU=Fireware\nremote evil 443")]
    [InlineData("subject\"")]
    public void Build_RejectsVerifyX509NameWithControlCharsOrQuotes(string verifyName)
    {
        // Same class of injection as Server: VerifyX509Name was inlined between double quotes.
        var settings = ValidSample();
        settings.VerifyX509Name = verifyName;

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }

    [Fact]
    public void Build_RejectsPemContainingInlineTagClose()
    {
        // A PEM whose body literally contains "</ca>" breaks out of the inline <ca>…</ca>
        // block and lets the next line be parsed as a top-level directive. Stock PEM never
        // contains this — it's always a sign of malformation or injection.
        var settings = ValidSample();
        settings.CaPem = "-----BEGIN CERTIFICATE-----\nFAKE\n</ca>\nscript-security 2\nup /tmp/pwn\n<ca>\n-----END CERTIFICATE-----";

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }

    [Fact]
    public void Build_RejectsClientCertContainingInlineTagClose()
    {
        var settings = ValidSample();
        settings.ClientCertPem = "-----BEGIN CERTIFICATE-----\nFAKE\n</CERT>\n-----END CERTIFICATE-----";

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }

    [Theory]
    [InlineData("</ca >")]      // whitespace inside close tag
    [InlineData("< /ca>")]      // leading space
    [InlineData("</ca\t>")]      // tab inside close tag
    [InlineData("<script>")]    // any angle bracket at all — PEM never contains these
    public void Build_RejectsPemWithAnyAngleBrackets(string injectedTag)
    {
        // Previously the guard only matched the exact `</ca>` / `</cert>` / `</key>` form.
        // Whitespace-tolerant OpenVPN parser variants would still terminate the block on the
        // variants above. The tightened guard rejects any '<' or '>' in PEM bodies because
        // legitimate PEM never contains them (RFC 7468 base64 alphabet + armor lines only).
        var settings = ValidSample();
        settings.CaPem = $"-----BEGIN CERTIFICATE-----\nFAKE\n{injectedTag}\n-----END CERTIFICATE-----";

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }

    [Theory]
    [InlineData("firebox\0nul")]   // NUL byte
    [InlineData("firebox\u0007bel")] // BEL control
    [InlineData("firebox\u0085nel")] // Unicode NEL
    [InlineData("firebox'quote")]   // single quote
    public void Build_RejectsServerWithBroaderControlCharsOrQuotes(string server)
    {
        // Tightened guard: char.IsControl covers NUL/BEL/NEL/FF/VT/etc., not just \r\n\t.
        // Single-quote covers the case where the OpenVPN parser ever supports single-quoted
        // strings (some forks do).
        var settings = ValidSample();
        settings.Server = server;

        Assert.Throws<InvalidOperationException>(() => WatchguardProfileBuilder.Build(settings));
    }
}
