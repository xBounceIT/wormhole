using System;
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
}
