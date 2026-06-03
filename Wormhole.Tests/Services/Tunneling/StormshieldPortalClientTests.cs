using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Wormhole.Services.Tunneling.Stormshield;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class StormshieldPortalClientTests
{
    // ----- LooksLikeOpenVpnProfile -----

    [Fact]
    public void LooksLikeOpenVpnProfile_TrueForRealProfile()
    {
        const string ovpn = "client\ndev tun\nremote fw.example.com 443 tcp\n<ca>\n...\n</ca>\n";
        Assert.True(StormshieldPortalClient.LooksLikeOpenVpnProfile(ovpn));
    }

    [Theory]
    [InlineData("")]
    [InlineData("<html><body>403 Forbidden</body></html>")]
    [InlineData("remote only without a device or ca block")]
    public void LooksLikeOpenVpnProfile_FalseForNonProfile(string text)
    {
        Assert.False(StormshieldPortalClient.LooksLikeOpenVpnProfile(text));
    }

    // ----- BuildBaseUri host validation -----

    [Theory]
    [InlineData("attacker.com@victim.com")]
    [InlineData("evil.com/path")]
    [InlineData("evil.com?")]
    [InlineData("evil.com#frag")]
    [InlineData("evil com")]
    public void BuildBaseUri_RejectsHostStringsThatSmuggleUriComponents(string server)
    {
        Assert.Throws<InvalidOperationException>(() => StormshieldPortalClient.BuildBaseUri(server, 443));
    }

    [Theory]
    [InlineData("rpv.example.com", 443)]
    [InlineData("192.0.2.1", 8443)]
    public void BuildBaseUri_AcceptsValidHosts(string server, int port)
    {
        var uri = StormshieldPortalClient.BuildBaseUri(server, port);
        Assert.Equal("https", uri.Scheme);
        Assert.Equal(port, uri.Port);
        Assert.Equal("/", uri.AbsolutePath);
    }

    [Fact]
    public void BuildBaseUri_RejectsOutOfRangePort()
    {
        Assert.Throws<InvalidOperationException>(() => StormshieldPortalClient.BuildBaseUri("fw", 0));
        Assert.Throws<InvalidOperationException>(() => StormshieldPortalClient.BuildBaseUri("fw", 70000));
    }

    // ----- TLS ctor behavior (mirrors WatchguardPreAuthClient) -----

    [Fact]
    public void Ctor_ThrowsOnMalformedCaPem()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new StormshieldPortalClient("fw.example.com", 443, trustServerCertificate: false, caPem: "not a valid PEM"));
    }

    [Fact]
    public void Ctor_TrustServerCertificateBypassesCaPemValidation()
    {
        using var client = new StormshieldPortalClient("fw.example.com", 443, trustServerCertificate: true, caPem: "garbage");
        Assert.NotNull(client);
    }

    [Fact]
    public void Ctor_TestSeam_ThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => new StormshieldPortalClient(null!, new Uri("https://fw/")));
        using var http = new HttpClient(new CapturingHandler("<auth msg=\"AUTH_SUCCESS\"/>"));
        Assert.Throws<ArgumentNullException>(() => new StormshieldPortalClient(http, null!));
    }

    // ----- DownloadProfileV5Async: native v5 SN SSL VPN Client flow -----
    //
    // Regression-locks the wire format reverse-engineered from the v5 client's
    // SSLVPNService.SNS.SnsVpnConfiguration.DownloadConfig: POST auth/config.html?version=1&type=openvpn,
    // form user=<user> pass=<password[+otp]>, 200 application/zip bundle (.ovpn + separate CA/cert/key
    // PEMs) or 200 text/xml <ret> error.

    private const string V5Ca = "-----BEGIN CERTIFICATE-----\nMIICA_TEST_CA\n-----END CERTIFICATE-----";
    private const string V5Cert = "-----BEGIN CERTIFICATE-----\nMIICB_TEST_CERT\n-----END CERTIFICATE-----";
    private const string V5Key = "-----BEGIN PRIVATE KEY-----\nMIIE_TEST_KEY\n-----END PRIVATE KEY-----";

    private const string V5Ovpn =
        "client\ndev tun\ncipher AES-256-CBC\ndata-ciphers AES-256-CBC\nremote 151.84.99.155 1194 udp\n"
        + "remote 151.84.99.155 443 tcp\nca \"CA.cert.pem\"\ncert \"openvpnclient.cert.pem\"\nkey \"openvpnclient.pkey.pem\"\n"
        + "auth-user-pass\n";

    private static byte[] V5Bundle() => BuildBundleZip(
        ("openvpn_client.ovpn", V5Ovpn),
        ("CA.cert.pem", V5Ca),
        ("openvpnclient.cert.pem", V5Cert),
        ("openvpnclient.pkey.pem", V5Key));

    [Fact]
    public async Task DownloadProfileV5Async_PostsCredentialsToConfigHtml_AndInlinesBundle()
    {
        var handler = new BinaryCapturingHandler(V5Bundle(), "application/zip");
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        var profile = await client.DownloadProfileV5Async("daniel.dangeli", "p4ss", otp: "123456", CancellationToken.None);

        Assert.Equal("/auth/config.html", handler.LastPath);
        Assert.Contains("version=1", handler.LastQuery);
        Assert.Contains("type=openvpn", handler.LastQuery);
        Assert.Equal("daniel.dangeli", handler.LastForm["user"]);
        // OTP is concatenated directly onto the password (no separator) for the download.
        Assert.Equal("p4ss123456", handler.LastForm["pass"]);

        // The separate PEM files are inlined into the profile; no file references remain.
        Assert.Contains("<ca>", profile);
        Assert.Contains("MIICA_TEST_CA", profile);
        Assert.Contains("<cert>", profile);
        Assert.Contains("MIICB_TEST_CERT", profile);
        Assert.Contains("<key>", profile);
        Assert.Contains("MIIE_TEST_KEY", profile);
        Assert.DoesNotContain("CA.cert.pem", profile);
        Assert.Contains("remote 151.84.99.155 1194 udp", profile);
    }

    [Fact]
    public async Task DownloadProfileV5Async_NoOtp_SendsPasswordAlone()
    {
        var handler = new BinaryCapturingHandler(V5Bundle(), "application/zip");
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        await client.DownloadProfileV5Async("daniel.dangeli", "p4ss", otp: null, CancellationToken.None);

        Assert.Equal("p4ss", handler.LastForm["pass"]);
    }

    [Fact]
    public async Task DownloadProfileV5Async_XmlError_SurfacesFirewallMessageAndCode()
    {
        // A bad login/OTP is delivered as 200 + text/xml with the REAL <nws> envelope (XmlRoot "nws",
        // <ret code/msg>, FirewallErrorCode BadLoginOrPassword=8). The firewall's own message + code
        // must surface rather than a generic failure.
        var handler = new RoutingHandler(_ => (HttpStatusCode.OK,
            "<nws version=\"1\"><config user=\"daniel.dangeli\" type=\"openvpn\"/><ret code=\"8\" msg=\"Bad login or password\"/></nws>", "text/xml"));
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.DownloadProfileV5Async("u", "p", otp: null, CancellationToken.None));
        Assert.Contains("Bad login or password", ex.Message);
        Assert.Contains("(code 8)", ex.Message);
    }

    [Fact]
    public async Task DownloadProfileV5Async_Non200_ThrowsWithStatus()
    {
        var handler = new RoutingHandler(_ => (HttpStatusCode.Forbidden, "<html>403</html>", "text/html"));
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.DownloadProfileV5Async("u", "p", otp: null, CancellationToken.None));
        Assert.Contains("403", ex.Message);
    }

    [Fact]
    public async Task DownloadProfileV5Async_200ButNotZip_ThrowsUnexpectedContentTypeWithImportHint()
    {
        // A captive-portal / WAF redirect or pre-v5 firmware can answer 200 with HTML; surface an
        // actionable "unexpected content type" + Import hint, NOT a misleading zip-parse error.
        var handler = new RoutingHandler(_ => (HttpStatusCode.OK, "<html><body>login</body></html>", "text/html"));
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.DownloadProfileV5Async("u", "p", otp: null, CancellationToken.None));
        Assert.Contains("unexpected content type", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Import", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DownloadProfileV5Async_OversizedBundle_TripsSafetyCap()
    {
        // The compressed-size cap trips before any zip parsing, so the bytes need not be a valid zip.
        var oversized = new byte[1 * 1024 * 1024 + 1];
        var handler = new BinaryCapturingHandler(oversized, "application/zip");
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.DownloadProfileV5Async("u", "p", otp: null, CancellationToken.None));
        Assert.Contains("safety cap", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DownloadProfileV5Async_XmlErrorWithDtd_DoesNotExpandEntities()
    {
        // The firewall's text/xml error is parsed by the hardened XML reader (DtdProcessing.Prohibit +
        // no resolver). A malicious DOCTYPE/ENTITY must NOT be expanded (XXE / billion-laughs defence).
        // This pins that hardening on the surviving v5 error path (DescribeV5Error -> LoadHardenedXml).
        const string xxe = "<!DOCTYPE r [<!ENTITY x \"XXE_EXPANDED_SECRET\">]>"
            + "<nws version=\"1\"><config user=\"u\" type=\"openvpn\"/><ret code=\"8\" msg=\"&x;\"/></nws>";
        var handler = new RoutingHandler(_ => (HttpStatusCode.OK, xxe, "text/xml"));
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.DownloadProfileV5Async("u", "p", otp: null, CancellationToken.None));
        // The DTD is rejected, so the entity is never expanded into the surfaced message.
        Assert.DoesNotContain("XXE_EXPANDED_SECRET", ex.Message);
    }

    [Fact]
    public void AssembleProfileFromZip_MissingReferencedPem_ThrowsNamingTheMissingFile()
    {
        // A bundle with the .ovpn (referencing CA.cert.pem) but WITHOUT that file must fail fast and
        // name the missing file — not silently produce a dangling-reference profile that fails deep
        // inside OpenVPN.
        var bundle = BuildBundleZip(
            ("openvpn_client.ovpn", V5Ovpn),
            ("openvpnclient.cert.pem", V5Cert),
            ("openvpnclient.pkey.pem", V5Key)); // CA.cert.pem deliberately omitted
        var ex = Assert.Throws<InvalidOperationException>(() => StormshieldPortalClient.AssembleProfileFromZip(bundle));
        Assert.Contains("CA.cert.pem", ex.Message);
        Assert.Contains("incomplete", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AssembleProfileFromZip_NoOvpnEntry_Throws()
    {
        var bundle = BuildBundleZip(
            ("CA.cert.pem", V5Ca),
            ("openvpnclient.cert.pem", V5Cert),
            ("openvpnclient.pkey.pem", V5Key)); // no .ovpn
        var ex = Assert.Throws<InvalidOperationException>(() => StormshieldPortalClient.AssembleProfileFromZip(bundle));
        Assert.Contains(".ovpn", ex.Message);
    }

    [Fact]
    public void AssembleProfileFromZip_InlinesReferencedPemsIntoSelfContainedProfile()
    {
        var profile = StormshieldPortalClient.AssembleProfileFromZip(V5Bundle());
        Assert.Contains("<key>", profile);
        Assert.Contains("MIIE_TEST_KEY", profile);
        Assert.DoesNotContain("openvpnclient.pkey.pem", profile);
        Assert.True(StormshieldPortalClient.LooksLikeOpenVpnProfile(profile));
    }

    [Fact]
    public void AssembleProfileFromZip_ThrowsOnNonZipBytes()
    {
        Assert.Throws<InvalidOperationException>(() =>
            StormshieldPortalClient.AssembleProfileFromZip(Encoding.UTF8.GetBytes("not a zip")));
    }

    // ----- GetConfigHashAsync: native v5 change-check (GET auth/v1/sslvpn/hash) -----

    [Fact]
    public async Task GetConfigHashAsync_GetsHashEndpoint_ReturnsTrimmedUppercasedToken()
    {
        HttpMethod? method = null;
        string? path = null;
        var hex = new string('a', 64); // SHA-256 hex
        var handler = new RoutingHandler(req =>
        {
            method = req.Method;
            path = req.RequestUri?.AbsolutePath;
            return (HttpStatusCode.OK, "\"" + hex + "\"", "text/plain"); // quoted, as the firewall returns
        });
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        var hash = await client.GetConfigHashAsync(CancellationToken.None);

        Assert.Equal(HttpMethod.Get, method);
        Assert.Equal("/auth/v1/sslvpn/hash", path);
        Assert.Equal(hex.ToUpperInvariant(), hash); // surrounding quotes trimmed, upper-cased for comparison
    }

    [Fact]
    public async Task GetConfigHashAsync_Non200_ReturnsNull()
    {
        // Endpoint unsupported (older firmware) → null so the caller falls back to the cache-presence heuristic.
        var handler = new RoutingHandler(_ => (HttpStatusCode.NotFound, "not found", "text/plain"));
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        Assert.Null(await client.GetConfigHashAsync(CancellationToken.None));
    }

    [Fact]
    public async Task GetConfigHashAsync_NonHashBody_ReturnsNull()
    {
        // A captive portal / WAF answering 200 + HTML must NOT be mistaken for a hash.
        var handler = new RoutingHandler(_ => (HttpStatusCode.OK, "<html><body>login</body></html>", "text/html"));
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        Assert.Null(await client.GetConfigHashAsync(CancellationToken.None));
    }

    [Theory]
    [InlineData(63)]  // one short of SHA-256
    [InlineData(65)]  // one over
    [InlineData(32)]  // a different digest length must NOT be accepted (gates OTP-spending HIT/MISS)
    public async Task GetConfigHashAsync_WrongLengthHex_ReturnsNull(int len)
    {
        var handler = new RoutingHandler(_ => (HttpStatusCode.OK, "\"" + new string('a', len) + "\"", "text/plain"));
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        Assert.Null(await client.GetConfigHashAsync(CancellationToken.None));
    }

    [Fact]
    public async Task GetConfigHashAsync_64NonHexChars_ReturnsNull()
    {
        // Right length, but not hex (e.g. a 64-char error token) → not a hash.
        var handler = new RoutingHandler(_ => (HttpStatusCode.OK, new string('z', 64), "text/plain"));
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://rpv.example.com/"));

        Assert.Null(await client.GetConfigHashAsync(CancellationToken.None));
    }

    private static byte[] BuildBundleZip(params (string Name, string Content)[] files)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in files)
            {
                var entry = zip.CreateEntry(name);
                using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                writer.Write(content);
            }
        }
        return ms.ToArray();
    }

    /// <summary>Test-only handler that returns a chosen (status, body, content-type) computed from the
    /// request — used to drive the v5 download error branches and the config-hash change-check.</summary>
    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, (HttpStatusCode, string, string)> _route;
        public RoutingHandler(Func<HttpRequestMessage, (HttpStatusCode, string, string)> route) { _route = route; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var (status, body, mediaType) = _route(request);
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, mediaType),
            });
        }
    }

    /// <summary>
    /// Test-only handler that returns a canned body and records the last request's path + form
    /// fields. Mirrors WatchguardPreAuthClientTests.CapturingHandler — avoids HttpListener URLACL
    /// requirements on Windows.
    /// </summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly string _canned;
        private readonly string _mediaType;
        public System.Collections.Specialized.NameValueCollection LastForm { get; private set; } = new();
        public string? LastPath { get; private set; }

        public CapturingHandler(string canned, string mediaType = "application/xml")
        {
            _canned = canned;
            _mediaType = mediaType;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastPath = request.RequestUri?.AbsolutePath;
            if (request.Content is not null)
            {
                var body = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                LastForm = HttpUtility.ParseQueryString(body);
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_canned, Encoding.UTF8, _mediaType),
            };
        }
    }

    /// <summary>
    /// Test-only handler that returns a canned BINARY body (e.g. the v5 application/zip bundle) with a
    /// chosen content type, and records the last request's path, query and form fields.
    /// </summary>
    private sealed class BinaryCapturingHandler : HttpMessageHandler
    {
        private readonly byte[] _body;
        private readonly string _mediaType;
        public string? LastPath { get; private set; }
        public string LastQuery { get; private set; } = string.Empty;
        public System.Collections.Specialized.NameValueCollection LastForm { get; private set; } = new();

        public BinaryCapturingHandler(byte[] body, string mediaType)
        {
            _body = body;
            _mediaType = mediaType;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastPath = request.RequestUri?.AbsolutePath;
            LastQuery = request.RequestUri?.Query ?? string.Empty;
            if (request.Content is not null)
            {
                var body = await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                LastForm = HttpUtility.ParseQueryString(body);
            }
            var content = new ByteArrayContent(_body);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(_mediaType);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        }
    }
}
