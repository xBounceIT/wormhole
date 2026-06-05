using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Wormhole.Services.Tunneling.Watchguard;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class WatchguardPreAuthClientTests
{
    [Fact]
    public async Task LogonAsync_PostsExpectedFormFields()
    {
        // Regression-locks the wire format of the initial logon leg against tazjin/watchblob's
        // urls.go templateChallengeTriggerUri. The `style` + `fw_logon_type=logon` fields are
        // required by some Fireware revs to route into the challenge-aware code path; their
        // absence silently lands in a legacy path that never issues 2FA challenges.
        var captured = new CapturingHandler(canned: "<resp><logon_status>1</logon_status></resp>");
        using var http = new HttpClient(captured);
        using var client = new WatchguardPreAuthClient(http);

        await client.LogonAsync(
            server: "firebox.example.com", port: 443,
            username: "alice", password: "p4ss", domain: "Firebox-DB",
            cancellationToken: CancellationToken.None);

        var form = captured.LastForm;
        Assert.Equal("sslvpn_logon", form["action"]);
        Assert.Equal("fw_logon_progress.xsl", form["style"]);
        Assert.Equal("logon", form["fw_logon_type"]);
        Assert.Equal("Firebox-DB", form["fw_domain"]);
        Assert.Equal("alice", form["fw_username"]);
        Assert.Equal("p4ss", form["fw_password"]);

        var query = captured.LastQuery;
        Assert.Equal("sslvpn_logon", query["action"]);
        Assert.Equal("fw_logon_progress.xsl", query["style"]);
        Assert.Equal("logon", query["fw_logon_type"]);
        Assert.Equal("Firebox-DB", query["fw_domain"]);
        Assert.Equal("alice", query["fw_username"]);
        Assert.Equal("p4ss", query["fw_password"]);
    }

    [Fact]
    public async Task RespondToChallengeAsync_PostsResponseFieldNotFwPassword()
    {
        // Regression-locks the wire format of the challenge-response leg against
        // tazjin/watchblob's urls.go templateResponseUri. The OTP must go in `response`
        // with `fw_logon_type=response`, NOT in `fw_password` — MFA-enabled gateways reject
        // the second step otherwise.
        var captured = new CapturingHandler(canned: "<resp><logon_status>1</logon_status></resp>");
        using var http = new HttpClient(captured);
        using var client = new WatchguardPreAuthClient(http);

        await client.RespondToChallengeAsync(
            server: "firebox.example.com", port: 443,
            logonId: "session-abc-123", otpCode: "654321",
            cancellationToken: CancellationToken.None);

        var form = captured.LastForm;
        Assert.Equal("sslvpn_logon", form["action"]);
        Assert.Equal("fw_logon_progress.xsl", form["style"]);
        Assert.Equal("response", form["fw_logon_type"]);
        Assert.Equal("session-abc-123", form["fw_logon_id"]);
        Assert.Equal("654321", form["response"]);
        // The OTP must NOT be sent in fw_password on the response leg — that was the bug.
        Assert.False(form.AllKeys.Contains("fw_password"),
            "challenge response must not include fw_password (it expects `response` instead).");

        var query = captured.LastQuery;
        Assert.Equal("sslvpn_logon", query["action"]);
        Assert.Equal("fw_logon_progress.xsl", query["style"]);
        Assert.Equal("response", query["fw_logon_type"]);
        Assert.Equal("session-abc-123", query["fw_logon_id"]);
        Assert.Equal("654321", query["response"]);
    }

    [Fact]
    public async Task RespondToMfaChoiceAsync_PostsNativePushChoiceShape()
    {
        var captured = new CapturingHandler(canned: "<resp><logon_status>1</logon_status></resp>");
        using var http = new HttpClient(captured);
        using var client = new WatchguardPreAuthClient(http);

        await client.RespondToMfaChoiceAsync(
            server: "firebox.example.com", port: 443,
            logonId: "session-abc-123", choice: "p",
            cancellationToken: CancellationToken.None);

        var form = captured.LastForm;
        Assert.Equal("sslvpn_logon", form["action"]);
        Assert.Equal("fw_logon_progress.xsl", form["style"]);
        Assert.Equal("mfa_response", form["fw_logon_type"]);
        Assert.Equal("session-abc-123", form["fw_logon_id"]);
        Assert.Equal("p", form["mfa_choice"]);
        Assert.False(form.AllKeys.Contains("response"));
        Assert.False(form.AllKeys.Contains("fw_password"));

        var query = captured.LastQuery;
        Assert.Equal("sslvpn_logon", query["action"]);
        Assert.Equal("fw_logon_progress.xsl", query["style"]);
        Assert.Equal("mfa_response", query["fw_logon_type"]);
        Assert.Equal("session-abc-123", query["fw_logon_id"]);
        Assert.Equal("p", query["mfa_choice"]);
    }

    [Fact]
    public async Task ConfigClientLogonAsync_PostsToSslvpnLogonQueryRoute()
    {
        // Production uses WatchguardConfigClient, not WatchguardPreAuthClient. This locks the
        // real tunnel path to the Firebox route shape; otherwise some gateways answer with the
        // HTML portal page and the user sees "non-XML content (text/html)" before OpenVPN starts.
        var captured = new CapturingHandler(canned: "<resp><logon_status>1</logon_status></resp>");
        using var http = new HttpClient(captured);
        using var client = new WatchguardConfigClient(http);

        await client.LogonAsync(
            server: "firebox.example.com", port: 6443,
            username: "alice", password: "p4ss", domain: "Firebox-DB",
            cancellationToken: CancellationToken.None);

        var uri = Assert.IsAssignableFrom<Uri>(captured.LastRequestUri);
        Assert.Equal("https", uri.Scheme);
        Assert.Equal("firebox.example.com", uri.Host);
        Assert.Equal(6443, uri.Port);
        Assert.Equal("/", uri.AbsolutePath);

        var query = captured.LastQuery;
        Assert.Equal("sslvpn_logon", query["action"]);
        Assert.Equal("fw_logon_progress.xsl", query["style"]);
        Assert.Equal("logon", query["fw_logon_type"]);
        Assert.Equal("Firebox-DB", query["fw_domain"]);
        Assert.Equal("alice", query["fw_username"]);
        Assert.Equal("p4ss", query["fw_password"]);
    }

    /// <summary>
    /// Test-only HttpMessageHandler that returns a canned XML body and records the request's
    /// form fields for assertion. Mirrors what a stub Firebox listener would provide without
    /// the ceremony (and HttpListener URLACL requirements on Windows).
    /// </summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly string _canned;
        public System.Collections.Specialized.NameValueCollection LastForm { get; private set; } = new();
        public Uri? LastRequestUri { get; private set; }
        public System.Collections.Specialized.NameValueCollection LastQuery =>
            LastRequestUri is null ? new() : HttpUtility.ParseQueryString(LastRequestUri.Query);

        public CapturingHandler(string canned) { _canned = canned; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri;
            var body = await request.Content!.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            LastForm = HttpUtility.ParseQueryString(body);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_canned, Encoding.UTF8, "application/xml"),
            };
        }
    }


    [Theory]
    [InlineData("attacker.com@victim.com")]
    [InlineData("evil.com/path")]
    [InlineData("evil.com?")]
    [InlineData("evil.com#frag")]
    [InlineData("evil.com:8080")]   // colon would be parsed as inline port, smuggling
    [InlineData("evil com")]         // space
    public void BuildLogonUri_RejectsHostStringsThatSmuggleUriComponents(string server)
    {
        // Regression: previously `new Uri($"https://{server}:{port}/")` would silently accept
        // these and POST credentials to whatever Uri parsed out. UriBuilder + CheckHostName
        // closes that gap.
        Assert.Throws<InvalidOperationException>(() => WatchguardPreAuthClient.BuildLogonUri(server, 443));
    }

    [Theory]
    [InlineData("firebox.example.com", 443)]
    [InlineData("192.0.2.1", 443)]
    [InlineData("[2001:db8::1]", 443)]
    [InlineData("2001:db8::1", 443)]    // bare IPv6 — what users typically paste
    public void BuildLogonUri_AcceptsValidHosts(string server, int port)
    {
        var uri = WatchguardPreAuthClient.BuildLogonUri(server, port);
        Assert.Equal("https", uri.Scheme);
        Assert.Equal(port, uri.Port);
        Assert.Equal("/", uri.AbsolutePath);
        var query = HttpUtility.ParseQueryString(uri.Query);
        Assert.Equal("sslvpn_logon", query["action"]);
        Assert.Equal("fw_logon_progress.xsl", query["style"]);
        Assert.Equal("logon", query["fw_logon_type"]);
    }

    [Fact]
    public void Ctor_ThrowsOnMalformedCaPem()
    {
        // Previously a malformed CaPem silently fell through to OS-trust-store validation;
        // the operator saw a downstream "chain error" with no hint that the CA blob itself
        // was the cause. Now construction throws a clear InvalidOperationException so the
        // dialog can surface "Watchguard CA certificate (PEM) failed to parse…".
        Assert.Throws<InvalidOperationException>(() =>
            new WatchguardPreAuthClient(trustServerCertificate: false, caPem: "not a valid PEM at all"));
    }

    [Fact]
    public void Ctor_ThrowsOnEmptyCaPemAfterTrim()
    {
        // A PEM with armor lines but no body should also fail loudly rather than silently.
        // ImportFromPem yields zero certs and we throw "contained no certificates."
        Assert.Throws<InvalidOperationException>(() =>
            new WatchguardPreAuthClient(trustServerCertificate: false,
                caPem: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"));
    }

    [Fact]
    public void Ctor_TrustServerCertificateBypassesCaPemValidation()
    {
        // When TrustServerCertificate is true, CaPem is ignored entirely. A malformed CaPem
        // should not block the ctor in that mode.
        using var client = new WatchguardPreAuthClient(trustServerCertificate: true, caPem: "garbage");
        Assert.NotNull(client);
    }

    [Fact]
    public void Ctor_HttpClientSeam_ThrowsOnNull()
    {
        // Test-seam ctor should reject null cleanly instead of NREing later in PostAsync.
        Assert.Throws<ArgumentNullException>(() => new WatchguardPreAuthClient((System.Net.Http.HttpClient)null!));
    }

    [Fact]
    public void BuildLogonUri_RejectsOutOfRangePort()
    {
        Assert.Throws<InvalidOperationException>(() => WatchguardPreAuthClient.BuildLogonUri("firebox", 0));
        Assert.Throws<InvalidOperationException>(() => WatchguardPreAuthClient.BuildLogonUri("firebox", 70000));
    }

    [Fact]
    public void ParseLogonResponse_RejectsXmlWithDtd()
    {
        // Billion-laughs / DTD entity-expansion DoS protection. With DtdProcessing.Prohibit
        // the parser should refuse the document and we treat that as a Failure outcome.
        const string xml = "<!DOCTYPE r [<!ENTITY x \"y\">]><r><logon_status>1</logon_status></r>";
        var outcome = WatchguardPreAuthClient.ParseLogonResponse(xml);

        Assert.IsType<PreAuthOutcome.Failure>(outcome);
    }

    [Fact]
    public void ParseLogonResponse_RejectsWhitespaceOnlyLogonId()
    {
        // logon_id was IsNullOrEmpty-checked which let whitespace-only IDs slip through; the
        // user would type an OTP and the challenge response POST would fail with a generic
        // "Firebox rejected credentials" instead of an early "missing logon_id" error.
        const string xml = "<resp><logon_status>4</logon_status><logon_id>   </logon_id></resp>";
        var outcome = WatchguardPreAuthClient.ParseLogonResponse(xml);

        Assert.IsType<PreAuthOutcome.Failure>(outcome);
    }

    [Fact]
    public void ParseLogonResponse_MapsStatus1ToOk()
    {
        const string xml = "<resp><logon_status>1</logon_status></resp>";
        var outcome = WatchguardPreAuthClient.ParseLogonResponse(xml);

        Assert.IsType<PreAuthOutcome.Ok>(outcome);
    }

    [Fact]
    public void ParseLogonResponse_MapsStatus4WithLogonIdToChallenge()
    {
        const string xml = """
            <resp>
                <logon_status>4</logon_status>
                <logon_id>session-abc-123</logon_id>
                <chaStr>Enter your authenticator code</chaStr>
            </resp>
            """;
        var outcome = WatchguardPreAuthClient.ParseLogonResponse(xml);

        var ch = Assert.IsType<PreAuthOutcome.Challenge>(outcome);
        Assert.Equal("session-abc-123", ch.LogonId);
        Assert.Equal("Enter your authenticator code", ch.ChallengeText);
    }

    [Fact]
    public void ParseLogonResponse_MapsStatus4WithoutLogonIdToFailure()
    {
        const string xml = "<resp><logon_status>4</logon_status></resp>";
        var outcome = WatchguardPreAuthClient.ParseLogonResponse(xml);

        Assert.IsType<PreAuthOutcome.Failure>(outcome);
    }

    [Fact]
    public void ParseLogonResponse_MapsUnknownStatusToFailure()
    {
        const string xml = "<resp><logon_status>2</logon_status><message>Bad creds</message></resp>";
        var outcome = WatchguardPreAuthClient.ParseLogonResponse(xml);

        var failure = Assert.IsType<PreAuthOutcome.Failure>(outcome);
        Assert.Equal("Bad creds", failure.Reason);
    }

    [Fact]
    public void ParseLogonResponse_UsesErrStrForFailureReason()
    {
        const string xml = "<resp><logon_status>8</logon_status><errStr>Wrong authentication domain</errStr></resp>";
        var outcome = WatchguardPreAuthClient.ParseLogonResponse(xml);

        var failure = Assert.IsType<PreAuthOutcome.Failure>(outcome);
        Assert.Equal("Wrong authentication domain", failure.Reason);
    }

    [Fact]
    public void ParseLogonResponse_HandlesMalformedXml()
    {
        const string xml = "<resp><logon_status>1";
        var outcome = WatchguardPreAuthClient.ParseLogonResponse(xml);

        Assert.IsType<PreAuthOutcome.Failure>(outcome);
    }

    [Fact]
    public void ParseLogonResponse_HandlesEmptyBody()
    {
        var outcome = WatchguardPreAuthClient.ParseLogonResponse("");

        Assert.IsType<PreAuthOutcome.Failure>(outcome);
    }

    [Fact]
    public void ParseStatusResponse_MapsSamlAndDomains()
    {
        const string xml = """
            <resp>
                <saml_enabled>1</saml_enabled>
                <saml_idp_name>Entra ID</saml_idp_name>
                <auth-domain>Firebox-DB</auth-domain>
                <auth-domain>FMS_EntraID_SAML</auth-domain>
            </resp>
            """;

        var status = WatchguardConfigClient.ParseStatusResponse(xml);

        Assert.True(status.SamlEnabled);
        Assert.Equal("Entra ID", status.SamlIdentityProviderName);
        Assert.Contains("Firebox-DB", status.AuthDomains);
        Assert.Contains("FMS_EntraID_SAML", status.AuthDomains);
    }

    [Fact]
    public void ParseStatusResponse_MapsNestedAuthDomainName()
    {
        const string xml = """
            <resp>
              <action>sslvpn_logon</action>
              <logon_status>2</logon_status>
              <auth-domain-list>
                <auth-domain>
                  <name>AuthPoint</name>
                  <type>radius</type>
                </auth-domain>
              </auth-domain-list>
            </resp>
            """;

        var status = WatchguardConfigClient.ParseStatusResponse(xml);

        Assert.False(status.SamlEnabled);
        Assert.Equal("AuthPoint", Assert.Single(status.AuthDomains));
    }

    [Theory]
    [InlineData("https://firebox.example.com/auth/saml/login?from=sslvpn_client", true)]
    [InlineData("https://firebox.example.com:443/saml/login?from=sslvpn_client", true)]
    [InlineData("https://login.microsoftonline.com/common/oauth2/v2.0/authorize", false)]
    [InlineData("https://firebox.example.com:4443/auth/saml/login", false)]
    [InlineData("http://firebox.example.com/auth/saml/login", false)]
    [InlineData("not a uri", false)]
    public void IsConfiguredFireboxHttpsUri_OnlyMatchesConfiguredGateway(string requestUri, bool expected)
    {
        var fireboxUri = WatchguardConfigClient.BuildUri("firebox.example.com", 443, "/");

        Assert.Equal(expected, WatchguardConfigClient.IsConfiguredFireboxHttpsUri(fireboxUri, requestUri));
    }

    [Fact]
    public void BuildSamlLoginUris_TriesDocumentedFireboxEntryPointFirst()
    {
        var uris = WatchguardConfigClient.BuildSamlLoginUris("firebox.example.com", 443);

        Assert.Equal("/auth/saml", uris[0].AbsolutePath);
        Assert.Equal("from=sslvpn_client", uris[0].Query.TrimStart('?'));
        Assert.Equal("/auth/saml/login", uris[1].AbsolutePath);
        Assert.Equal("/saml/login", uris[2].AbsolutePath);
    }
}
