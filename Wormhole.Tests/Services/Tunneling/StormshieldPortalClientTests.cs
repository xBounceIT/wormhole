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
    private static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    // ----- AuthenticateAsync wire format -----
    //
    // Regression-locks the request shape against Stormshield's own python-SNS-API client:
    // POST /auth/admin.html with base64(uid)/base64(pswd)/app[/base64(totp)].

    [Fact]
    public async Task AuthenticateAsync_PostsBase64CredentialsToAdminHtml()
    {
        var captured = new CapturingHandler(canned: "<auth msg=\"AUTH_SUCCESS\"/>");
        using var http = new HttpClient(captured);
        using var client = new StormshieldPortalClient(http, new Uri("https://fw.example.com/"));

        await client.AuthenticateAsync("alice", "p4ss", otp: null, app: "sslclient", CancellationToken.None);

        Assert.Equal("/auth/admin.html", captured.LastPath);
        var form = captured.LastForm;
        Assert.Equal(B64("alice"), form["uid"]);
        Assert.Equal(B64("p4ss"), form["pswd"]);
        Assert.Equal("sslclient", form["app"]);
        // No OTP supplied → no totp field at all.
        Assert.DoesNotContain("totp", form.AllKeys);
    }

    [Fact]
    public async Task AuthenticateAsync_IncludesBase64Totp_WhenOtpSupplied()
    {
        var captured = new CapturingHandler(canned: "<auth msg=\"AUTH_SUCCESS\"/>");
        using var http = new HttpClient(captured);
        using var client = new StormshieldPortalClient(http, new Uri("https://fw.example.com/"));

        await client.AuthenticateAsync("alice", "p4ss", otp: "123456", app: "sslclient", CancellationToken.None);

        Assert.Equal(B64("123456"), captured.LastForm["totp"]);
    }

    [Fact]
    public async Task AuthenticateAsync_NonXmlContent_FailsNamingContentTypeNotMalformedXml()
    {
        // A captive portal / WAF / wrong host answering 200 OK + HTML must produce a "non-XML
        // content" failure that names the type — NOT a misleading "malformed XML" parse error.
        var handler = new CapturingHandler(canned: "<html><body>login</body></html>", mediaType: "text/html");
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://fw.example.com/"));

        var outcome = await client.AuthenticateAsync("alice", "p4ss", otp: null, app: "sslclient", CancellationToken.None);

        var failure = Assert.IsType<StormshieldAuthOutcome.Failure>(outcome);
        Assert.Contains("non-XML", failure.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("text/html", failure.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("malformed", failure.Reason, StringComparison.OrdinalIgnoreCase);
    }

    // ----- ParseAuthResponse status mapping -----

    [Fact]
    public void ParseAuthResponse_AuthSuccess_MapsToOk()
    {
        var outcome = StormshieldPortalClient.ParseAuthResponse("<auth msg=\"AUTH_SUCCESS\"/>");
        Assert.IsType<StormshieldAuthOutcome.Ok>(outcome);
    }

    [Fact]
    public void ParseAuthResponse_NeedTotp_MapsToNeedOtp()
    {
        var outcome = StormshieldPortalClient.ParseAuthResponse("<auth msg=\"NEED_TOTP_AUTH\"/>");
        Assert.IsType<StormshieldAuthOutcome.NeedOtp>(outcome);
    }

    [Fact]
    public void ParseAuthResponse_Bruteforce_CarriesDelay()
    {
        var outcome = StormshieldPortalClient.ParseAuthResponse("<auth msg=\"ERR_BRUTEFORCE\" delay=\"30\"/>");
        var bf = Assert.IsType<StormshieldAuthOutcome.Bruteforce>(outcome);
        Assert.Equal(30, bf.DelaySeconds);
    }

    [Fact]
    public void ParseAuthResponse_AuthFailed_MapsToFailure()
    {
        var outcome = StormshieldPortalClient.ParseAuthResponse("<auth msg=\"AUTH_FAILED\"/>");
        Assert.IsType<StormshieldAuthOutcome.Failure>(outcome);
    }

    [Fact]
    public void ParseAuthResponse_AccessDenied_MapsToActionableImportGuidance()
    {
        // ACCESS_DENIED is an authorization refusal (credentials accepted, but the account is not entitled to
        // the Automatic-mode admin/serverd surface), distinct from AUTH_FAILED. It must get a dedicated,
        // actionable message — NOT fall through to the generic "unexpected authentication status" arm — and
        // steer the user to Import mode.
        var outcome = StormshieldPortalClient.ParseAuthResponse("<auth msg=\"ACCESS_DENIED\"/>");
        var failure = Assert.IsType<StormshieldAuthOutcome.Failure>(outcome);
        Assert.DoesNotContain("unexpected authentication status", failure.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Import", failure.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("<auth msg=\"SOMETHING_NEW\"/>")] // unknown status
    [InlineData("<auth status=\"ok\"/>")]          // no msg attribute at all
    [InlineData("<auth msg=\"AUTH_SUCCESS\"")]     // malformed XML
    public void ParseAuthResponse_BadOrUnknown_MapsToFailure(string xml)
    {
        Assert.IsType<StormshieldAuthOutcome.Failure>(StormshieldPortalClient.ParseAuthResponse(xml));
    }

    [Fact]
    public void ParseAuthResponse_RejectsXmlWithDtd()
    {
        // Billion-laughs / entity-expansion DoS protection (DtdProcessing.Prohibit).
        const string xml = "<!DOCTYPE r [<!ENTITY x \"y\">]><auth msg=\"AUTH_SUCCESS\"/>";
        Assert.IsType<StormshieldAuthOutcome.Failure>(StormshieldPortalClient.ParseAuthResponse(xml));
    }

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

    // ----- DownloadProfileAsync: the profile is returned by the command response (Format raw) -----

    [Fact]
    public async Task DownloadProfileAsync_ReadsProfileFromCommandResponse_WithoutTmpFile()
    {
        // CONFIG OPENVPN DOWNLOAD returns the .ovpn inline — the profile must come from the command
        // response, and tmp.file must not be required.
        const string ovpn = "client\ndev tun\nremote rpv.example.com 443 tcp\n<ca>\nMIIB\n</ca>\n";
        var tmpFileHit = false;
        var handler = new RoutingHandler(req =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path.EndsWith("/api/auth/login", StringComparison.Ordinal)) return (HttpStatusCode.OK, "<nws code=\"100\"><sessionid>abc123</sessionid></nws>", "application/xml");
            if (path.EndsWith("/api/command", StringComparison.Ordinal)) return (HttpStatusCode.OK, ovpn, "text/plain");
            if (path.EndsWith("/api/download/tmp.file", StringComparison.Ordinal)) { tmpFileHit = true; return (HttpStatusCode.NotFound, "missing", "text/plain"); }
            return (HttpStatusCode.OK, string.Empty, "text/plain");
        });
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://fw.example.com/"));

        var profile = await client.DownloadProfileAsync("sslclient", CancellationToken.None);

        Assert.Contains("remote rpv.example.com 443 tcp", profile);
        Assert.False(tmpFileHit, "tmp.file must not be needed when the command returns the profile inline");
    }

    [Fact]
    public async Task DownloadProfileAsync_ExtractsProfileFromXmlEnvelope()
    {
        // When the raw output is wrapped in the serverd XML envelope, the profile is recovered from
        // the data node and the envelope markup is stripped.
        const string ovpn = "client\ndev tun\nremote rpv.example.com 443 tcp\n";
        var enveloped = "<nws code=\"100\"><data format=\"raw\"><![CDATA[" + ovpn + "]]></data></nws>";
        var handler = new RoutingHandler(req =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path.EndsWith("/api/auth/login", StringComparison.Ordinal)) return (HttpStatusCode.OK, "<nws><sessionid>s1</sessionid></nws>", "application/xml");
            if (path.EndsWith("/api/command", StringComparison.Ordinal)) return (HttpStatusCode.OK, enveloped, "application/xml");
            return (HttpStatusCode.OK, "irrelevant", "text/plain");
        });
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://fw.example.com/"));

        var profile = await client.DownloadProfileAsync("sslclient", CancellationToken.None);

        Assert.Contains("remote rpv.example.com 443 tcp", profile);
        Assert.DoesNotContain("nws", profile, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DownloadProfileAsync_NoProfileAnywhere_ThrowsActionableImportHint()
    {
        // No inline profile and no staged file (e.g. the account lacks API privilege) → an actionable
        // error pointing at Import mode, not a silent failure.
        var handler = new RoutingHandler(req =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path.EndsWith("/api/auth/login", StringComparison.Ordinal)) return (HttpStatusCode.OK, "<nws><sessionid>s1</sessionid></nws>", "application/xml");
            if (path.EndsWith("/api/command", StringComparison.Ordinal)) return (HttpStatusCode.OK, "<html>403 Forbidden</html>", "text/html");
            if (path.EndsWith("/api/download/tmp.file", StringComparison.Ordinal)) return (HttpStatusCode.NotFound, "nope", "text/plain");
            return (HttpStatusCode.OK, string.Empty, "text/plain");
        });
        using var http = new HttpClient(handler);
        using var client = new StormshieldPortalClient(http, new Uri("https://fw.example.com/"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.DownloadProfileAsync("sslclient", CancellationToken.None));
        Assert.Contains("Import", ex.Message, StringComparison.OrdinalIgnoreCase);
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

    /// <summary>Test-only handler that routes responses by request (path), used to script the
    /// multi-request DownloadProfileAsync flow.</summary>
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
