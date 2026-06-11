using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Microsoft Entra ID OAuth2 plumbing for Azure VPN tunnels. Wire parameters mirror what the
/// official Azure VPN clients use:
/// <list type="bullet">
///   <item>v2.0 endpoints under <c>https://login.microsoftonline.com/{tenant}/oauth2/v2.0/</c>;</item>
///   <item>scope <c>{audience}/.default offline_access</c>;</item>
///   <item>public client (no secret) with PKCE S256;</item>
///   <item>redirect <see cref="AzureVpnSettings.RedirectUri"/> (<c>http://localhost:2023</c>) —
///   registered by Microsoft for the Azure VPN public app ids; the sign-in WebView intercepts the
///   navigation, so nothing actually listens on the port.</item>
/// </list>
/// The URL/PKCE builders are static and pure for unit testing; only the token-endpoint POSTs do IO.
/// </summary>
public sealed class AzureVpnOAuthClient : IAzureVpnOAuthClient, IDisposable
{
    private const string Authority = "https://login.microsoftonline.com";

    private readonly HttpClient _http;
    private readonly ILogger<AzureVpnOAuthClient> _logger;

    public AzureVpnOAuthClient(ILogger<AzureVpnOAuthClient> logger)
        : this(logger, new HttpClient(new SocketsHttpHandler
        {
            // Token endpoints must never be followed through a redirect — a redirected POST could
            // leak the grant to another host.
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        })
        { Timeout = TimeSpan.FromSeconds(30) })
    {
    }

    internal AzureVpnOAuthClient(ILogger<AzureVpnOAuthClient> logger, HttpClient http)
    {
        _logger = logger;
        _http = http;
    }

    /// <summary>Scope string every leg of the flow uses (auth-code, refresh).</summary>
    internal static string BuildScope(AzureVpnSettings settings) =>
        $"{settings.Audience}/.default offline_access";

    internal static string BuildTokenEndpoint(AzureVpnSettings settings) =>
        $"{Authority}/{Uri.EscapeDataString(settings.TenantId)}/oauth2/v2.0/token";

    /// <summary>
    /// The browser URL for the interactive leg. <c>prompt=select_account</c> mirrors the official
    /// clients — without it Entra silently reuses whatever session the WebView profile already
    /// has, which is confusing for users with several work accounts.
    /// </summary>
    internal static string BuildAuthorizeUri(AzureVpnSettings settings, string codeChallenge, string state)
    {
        var sb = new StringBuilder(512);
        sb.Append(Authority).Append('/').Append(Uri.EscapeDataString(settings.TenantId)).Append("/oauth2/v2.0/authorize");
        sb.Append("?client_id=").Append(Uri.EscapeDataString(settings.ClientId));
        sb.Append("&response_type=code");
        sb.Append("&redirect_uri=").Append(Uri.EscapeDataString(AzureVpnSettings.RedirectUri));
        sb.Append("&response_mode=query");
        sb.Append("&scope=").Append(Uri.EscapeDataString(BuildScope(settings)));
        sb.Append("&state=").Append(Uri.EscapeDataString(state));
        sb.Append("&code_challenge=").Append(Uri.EscapeDataString(codeChallenge));
        sb.Append("&code_challenge_method=S256");
        sb.Append("&prompt=select_account");
        return sb.ToString();
    }

    /// <summary>RFC 7636 PKCE pair: a random verifier and its S256 challenge.</summary>
    internal static (string Verifier, string Challenge) CreatePkcePair()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var verifier = Base64UrlEncode(bytes);
        var challenge = Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    internal static string CreateState() => Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

    internal static string Base64UrlEncode(byte[] bytes) =>
        System.Buffers.Text.Base64Url.EncodeToString(bytes);

    /// <summary>
    /// Redeems the authorization code captured from the popup's redirect. Throws with Entra's
    /// error description on rejection — at this point the user just signed in, so a failure is
    /// actionable configuration feedback (bad client id, missing consent, …), not a silent-retry
    /// situation.
    /// </summary>
    public async Task<AzureVpnTokenResult> ExchangeCodeAsync(
        AzureVpnSettings settings, string code, string codeVerifier, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["client_id"] = settings.ClientId,
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = AzureVpnSettings.RedirectUri,
            ["code_verifier"] = codeVerifier,
            ["scope"] = BuildScope(settings),
        };
        var (result, error) = await PostTokenRequestAsync(settings, form, cancellationToken).ConfigureAwait(false);
        if (result is null)
        {
            throw new InvalidOperationException(
                $"Microsoft Entra ID rejected the sign-in code exchange: {error}");
        }
        return result;
    }

    public async Task<AzureVpnTokenResult?> RefreshAsync(
        AzureVpnSettings settings, string refreshToken, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["client_id"] = settings.ClientId,
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["scope"] = BuildScope(settings),
        };
        var (result, error) = await PostTokenRequestAsync(settings, form, cancellationToken).ConfigureAwait(false);
        if (result is null)
        {
            // Expected on revocation / expiry / conditional-access changes; the caller falls back
            // to the interactive popup. Entra error codes are not secrets.
            _logger.LogInformation("Azure VPN silent token refresh was rejected: {Error}", error);
        }
        return result;
    }

    private async Task<(AzureVpnTokenResult? Result, string? Error)> PostTokenRequestAsync(
        AzureVpnSettings settings, Dictionary<string, string> form, CancellationToken cancellationToken)
    {
        using var content = new FormUrlEncodedContent(form);
        using var response = await _http.PostAsync(BuildTokenEndpoint(settings), content, cancellationToken)
            .ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            return (null, DescribeOAuthError(body, (int)response.StatusCode));

        try
        {
            using var doc = JsonDocument.Parse(body);
            var accessToken = doc.RootElement.TryGetProperty("access_token", out var at) ? at.GetString() : null;
            if (string.IsNullOrEmpty(accessToken))
                return (null, "the token response contained no access_token");
            var refreshToken = doc.RootElement.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null;
            return (new AzureVpnTokenResult(accessToken, refreshToken), null);
        }
        catch (JsonException)
        {
            return (null, "the token response was not valid JSON");
        }
    }

    // Entra error payloads are JSON: { "error": "invalid_grant", "error_description": "AADSTS…" }.
    // Surface both fields; truncate the description (they embed correlation ids + timestamps).
    private static string DescribeOAuthError(string body, int statusCode)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var error = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
            var description = doc.RootElement.TryGetProperty("error_description", out var d) ? d.GetString() : null;
            if (!string.IsNullOrEmpty(description))
            {
                var firstLine = description.Split('\n')[0].Trim();
                if (firstLine.Length > 300) firstLine = firstLine[..300] + "…";
                return string.IsNullOrEmpty(error) ? firstLine : $"{error}: {firstLine}";
            }
            if (!string.IsNullOrEmpty(error)) return error;
        }
        catch (JsonException)
        {
        }
        return $"HTTP {statusCode}";
    }

    public void Dispose() => _http.Dispose();
}
