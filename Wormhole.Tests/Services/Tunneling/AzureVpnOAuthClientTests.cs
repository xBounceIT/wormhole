using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Tunneling.AzureVpn;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class AzureVpnOAuthClientTests
{
    private static AzureVpnSettings Settings() => new()
    {
        Servers = new List<string> { "gw.vpn.azure.com" },
        TenantId = "11111111-2222-3333-4444-555555555555",
        Audience = "c632b3df-fb67-4d84-bdcf-b95ad541b5c8",
    };

    [Fact]
    public void BuildScope_IsAudienceDefaultPlusOfflineAccess()
    {
        // The exact shape the official Azure VPN clients request; offline_access is what grants
        // the refresh token that keeps reconnects silent.
        Assert.Equal(
            "c632b3df-fb67-4d84-bdcf-b95ad541b5c8/.default offline_access",
            AzureVpnOAuthClient.BuildScope(Settings()));
    }

    [Fact]
    public void BuildAuthorizeUri_CarriesAllRequiredParameters()
    {
        var uri = AzureVpnOAuthClient.BuildAuthorizeUri(Settings(), "challenge123", "state456");

        Assert.StartsWith(
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize?", uri);
        // No <applicationid> → audience doubles as the public client id.
        Assert.Contains("client_id=c632b3df-fb67-4d84-bdcf-b95ad541b5c8", uri);
        Assert.Contains("response_type=code", uri);
        Assert.Contains("redirect_uri=" + Uri.EscapeDataString("http://localhost:2023"), uri);
        Assert.Contains("code_challenge=challenge123", uri);
        Assert.Contains("code_challenge_method=S256", uri);
        Assert.Contains("state=state456", uri);
        Assert.Contains("prompt=select_account", uri);
        Assert.Contains(Uri.EscapeDataString("c632b3df-fb67-4d84-bdcf-b95ad541b5c8/.default offline_access"), uri);
    }

    [Fact]
    public void BuildAuthorizeUri_ApplicationIdOverride_WinsOverAudience()
    {
        var settings = Settings();
        settings.ApplicationId = "custom-app";
        var uri = AzureVpnOAuthClient.BuildAuthorizeUri(settings, "c", "s");
        Assert.Contains("client_id=custom-app", uri);
        // The scope still targets the gateway audience, not the client app.
        Assert.Contains(Uri.EscapeDataString("c632b3df-fb67-4d84-bdcf-b95ad541b5c8/.default"), uri);
    }

    [Fact]
    public void CreatePkcePair_ChallengeIsS256OfVerifier()
    {
        var (verifier, challenge) = AzureVpnOAuthClient.CreatePkcePair();

        var expected = AzureVpnOAuthClient.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        Assert.Equal(expected, challenge);
        // 32 random bytes → 43 base64url chars, the RFC 7636 minimum verifier length.
        Assert.Equal(43, verifier.Length);
        Assert.DoesNotContain('+', verifier);
        Assert.DoesNotContain('/', verifier);
        Assert.DoesNotContain('=', verifier);
    }

    [Fact]
    public async Task RefreshAsync_Success_ReturnsTokens()
    {
        var handler = new StubHandler(HttpStatusCode.OK,
            """{"access_token":"at-1","refresh_token":"rt-2","expires_in":3599}""");
        using var client = new AzureVpnOAuthClient(
            NullLogger<AzureVpnOAuthClient>.Instance, new HttpClient(handler));

        var result = await client.RefreshAsync(Settings(), "rt-1", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("at-1", result!.AccessToken);
        Assert.Equal("rt-2", result.RefreshToken);
        Assert.Equal(
            "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token",
            handler.LastUri?.ToString());
        Assert.Contains("grant_type=refresh_token", handler.LastBody);
        Assert.Contains("refresh_token=rt-1", handler.LastBody);
    }

    [Fact]
    public async Task RefreshAsync_InvalidGrant_ReturnsNull()
    {
        // Entra rejecting the grant (expired/revoked) is the signal to fall back to the popup —
        // not an exception.
        var handler = new StubHandler(HttpStatusCode.BadRequest,
            """{"error":"invalid_grant","error_description":"AADSTS70008: The refresh token has expired."}""");
        using var client = new AzureVpnOAuthClient(
            NullLogger<AzureVpnOAuthClient>.Instance, new HttpClient(handler));

        var result = await client.RefreshAsync(Settings(), "rt-stale", CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task ExchangeCodeAsync_Rejection_ThrowsWithEntraDescription()
    {
        // Right after an interactive sign-in a rejection is configuration feedback the user must
        // see (consent missing, bad client id), not something to swallow.
        var handler = new StubHandler(HttpStatusCode.BadRequest,
            """{"error":"invalid_client","error_description":"AADSTS650053: scope misconfigured."}""");
        using var client = new AzureVpnOAuthClient(
            NullLogger<AzureVpnOAuthClient>.Instance, new HttpClient(handler));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            client.ExchangeCodeAsync(Settings(), "code-1", "verifier-1", CancellationToken.None));
        Assert.Contains("invalid_client", ex.Message);
        Assert.Contains("AADSTS650053", ex.Message);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;

        public Uri? LastUri { get; private set; }
        public string LastBody { get; private set; } = string.Empty;

        public StubHandler(HttpStatusCode status, string body)
        {
            _status = status;
            _body = body;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastUri = request.RequestUri;
            LastBody = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(_status)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json"),
            };
        }
    }
}
