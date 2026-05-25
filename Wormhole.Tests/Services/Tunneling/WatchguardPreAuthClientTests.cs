using System;
using Wormhole.Services.Tunneling.Watchguard;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class WatchguardPreAuthClientTests
{
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
}
