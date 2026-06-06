using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Extensions.Logging;

namespace Wormhole.Services.Tunneling.Watchguard;

internal interface IWatchguardConfigClient : IWatchguardPreAuth, IDisposable
{
    Task<WatchguardGatewayStatus> GetStatusAsync(string server, int port, CancellationToken cancellationToken);
    Task<byte[]> DownloadConfigAsync(string server, int port, IEnumerable<Cookie>? cookies, CancellationToken cancellationToken);
}

internal sealed record WatchguardGatewayStatus(
    bool SamlEnabled,
    string? SamlIdentityProviderName,
    IReadOnlyList<string> AuthDomains);

internal sealed class WatchguardConfigClient : IWatchguardConfigClient
{
    private const int MaxConfigBytes = 4 * 1024 * 1024;

    /// <summary>
    /// User-Agent of the native WatchGuard Mobile VPN with SSL client (captured from
    /// wgsslvpnc.exe's WinHttpOpen agent string). The Firebox branches its AuthPoint behavior on
    /// this header: identified as the native client, an OTP answered via the <c>response</c> leg is
    /// validated as an OTP; an unrecognized/empty agent ALSO triggers a push notification — the
    /// spurious push users reported when entering a one-time passcode.
    /// </summary>
    internal const string NativeUserAgent = "WatchGuard/wgsslvpnc.exe";

    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);
    // The 2FA response leg is a LONG-POLL: the gateway holds the connection open while AuthPoint
    // validates the entered OTP or waits for the user to approve a push on their phone, and only
    // then replies with the final logon_status. Confirmed live — an answered challenge kept the
    // connection open well past 30s. Both the OTP and the push answer go through this leg, so both
    // get the generous timeout (the default 30s RequestTimeout would cut a valid login off).
    private static readonly TimeSpan AuthenticatingTimeout = TimeSpan.FromSeconds(120);

    private readonly HttpClient _http;
    private readonly CookieContainer? _cookieContainer;
    private readonly bool _ownsHttpClient;
    private readonly X509Certificate2Collection? _pinnedCaCerts;
    private readonly ILogger? _logger;

    public WatchguardConfigClient(bool trustServerCertificate, string? caPem = null, ILogger? logger = null)
    {
        _logger = logger;
        var handler = new HttpClientHandler
        {
            CookieContainer = new CookieContainer(),
            UseCookies = true,
            AllowAutoRedirect = true,
        };
        X509Certificate2Collection? caCerts = null;
        try
        {
            if (trustServerCertificate)
            {
                handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            }
            else if (!string.IsNullOrWhiteSpace(caPem))
            {
                caCerts = new X509Certificate2Collection();
                try
                {
                    caCerts.ImportFromPem(caPem);
                }
                catch (CryptographicException ex)
                {
                    DisposeCerts(caCerts);
                    throw new InvalidOperationException(
                        "Watchguard CA certificate (PEM) failed to parse — check the pasted CA bundle for "
                        + "missing/extra armor lines, truncated base64, or non-PEM content.", ex);
                }
                if (caCerts.Count == 0)
                    throw new InvalidOperationException("Watchguard CA certificate (PEM) contained no certificates.");

                var pinned = caCerts;
                handler.ServerCertificateCustomValidationCallback = (_, serverCert, peerChain, errors) =>
                {
                    if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
                    if (serverCert is null) return false;
                    using var customChain = new X509Chain();
                    customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    customChain.ChainPolicy.CustomTrustStore.AddRange(pinned);
                    if (peerChain is not null)
                    {
                        for (var i = 1; i < peerChain.ChainElements.Count; i++)
                            customChain.ChainPolicy.ExtraStore.Add(peerChain.ChainElements[i].Certificate);
                    }
                    return customChain.Build(serverCert);
                };
            }

            _http = new HttpClient(new RequestDiagnosticsHandler(handler, logger), disposeHandler: true)
            {
                Timeout = System.Threading.Timeout.InfiniteTimeSpan,
                MaxResponseContentBufferSize = MaxConfigBytes,
            };
            ApplyNativeClientHeaders(_http);
            _cookieContainer = handler.CookieContainer;
            _ownsHttpClient = true;
            _pinnedCaCerts = caCerts;
        }
        catch
        {
            DisposeCerts(caCerts);
            handler.Dispose();
            throw;
        }
    }

    public WatchguardConfigClient(HttpClient http)
    {
        ArgumentNullException.ThrowIfNull(http);
        _http = http;
        ApplyNativeClientHeaders(_http);
        _ownsHttpClient = false;
    }

    private static void ApplyNativeClientHeaders(HttpClient http)
    {
        // TryAddWithoutValidation: the value's ".exe" token is not a strictly-valid product/version
        // per RFC 7231, but the Firebox expects this literal string, so bypass header validation.
        if (!http.DefaultRequestHeaders.Contains("User-Agent"))
            http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", NativeUserAgent);
    }

    public async Task<WatchguardGatewayStatus> GetStatusAsync(string server, int port, CancellationToken cancellationToken)
    {
        var uri = BuildUri(server, port, "/?action=sslvpn_logon&style=fw_logon.xsl&fw_logon_type=status");
        using var timeoutCts = CreateTimeoutCancellation(RequestTimeout, cancellationToken);
        using var response = await _http.GetAsync(uri, timeoutCts.Token).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Watchguard status check returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");
        }

        var body = await response.Content.ReadAsStringAsync(timeoutCts.Token).ConfigureAwait(false);
        _logger?.LogInformation("Watchguard status raw response: {Body}", body);
        return ParseStatusResponse(body);
    }

    public async Task<byte[]> DownloadConfigAsync(
        string server, int port, IEnumerable<Cookie>? cookies, CancellationToken cancellationToken)
    {
        var uri = BuildUri(server, port, "/?action=sslvpn_download&filename=client.wgssl");
        if (_cookieContainer is not null && cookies is not null)
        {
            foreach (var cookie in cookies)
            {
                try { _cookieContainer.Add(uri, cookie); } catch (CookieException) { /* ignore malformed browser cookies */ }
            }
        }

        using var timeoutCts = CreateTimeoutCancellation(RequestTimeout, cancellationToken);
        using var response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Watchguard configuration download returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");
        }

        return await ReadCappedBytesAsync(response, MaxConfigBytes, timeoutCts.Token).ConfigureAwait(false);
    }

    public Task<PreAuthOutcome> LogonAsync(
        string server, int port, string username, string password, string domain, CancellationToken cancellationToken)
    {
        // Field order mirrors wgsslvpnc.exe's template exactly:
        // action, fw_username, fw_password, style, fw_logon_type, fw_domain.
        var form = new Dictionary<string, string>
        {
            ["action"] = "sslvpn_logon",
            ["fw_username"] = username,
            ["fw_password"] = password,
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "logon",
            ["fw_domain"] = domain,
        };
        return SendLogonRequestAsync(server, port, form, cancellationToken);
    }

    public Task<PreAuthOutcome> RespondToChallengeAsync(
        string server, int port, string logonId, string otpCode, CancellationToken cancellationToken)
    {
        // Native template: action, style, fw_logon_type=response, response, fw_logon_id.
        var form = new Dictionary<string, string>
        {
            ["action"] = "sslvpn_logon",
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "response",
            ["response"] = otpCode,
            ["fw_logon_id"] = logonId,
        };
        return SendLogonRequestAsync(server, port, form, cancellationToken, AuthenticatingTimeout);
    }

    public Task<PreAuthOutcome> RespondToMfaChoiceAsync(
        string server, int port, string logonId, string choice, CancellationToken cancellationToken)
    {
        // Push uses the DISTINCT mfa_response leg, exactly as wgsslvpnc.exe does:
        // action, style, fw_logon_type=mfa_response, mfa_choice, fw_logon_id. This is a different
        // request from the OTP `response` leg — the firewall only fires a push for this one, which
        // is precisely why an OTP answered via `response` must NOT reuse this shape.
        var form = new Dictionary<string, string>
        {
            ["action"] = "sslvpn_logon",
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "mfa_response",
            ["mfa_choice"] = choice,
            ["fw_logon_id"] = logonId,
        };
        return SendLogonRequestAsync(server, port, form, cancellationToken, AuthenticatingTimeout);
    }

    private async Task<PreAuthOutcome> SendLogonRequestAsync(
        string server,
        int port,
        Dictionary<string, string> form,
        CancellationToken cancellationToken,
        TimeSpan? requestTimeout = null)
    {
        var uri = BuildUri(server, port, "/" + BuildQuery(form));
        using var timeoutCts = CreateTimeoutCancellation(requestTimeout ?? RequestTimeout, cancellationToken);
        using var response = await _http.GetAsync(uri, timeoutCts.Token).ConfigureAwait(false);
        // Diagnostic: log the logon-leg TYPE and the raw RESPONSE body. The response carries no
        // secret (fw_password lives only in the request query, which we deliberately never log);
        // it does carry logon_status / logon_id / message which is exactly what we need to map the
        // AuthPoint progress-poll flow. fw_logon_type tells us which leg (logon / response /
        // mfa_response / poll) produced the body.
        form.TryGetValue("fw_logon_type", out var legType);
        if (!response.IsSuccessStatusCode)
        {
            _logger?.LogInformation(
                "Watchguard logon leg '{Leg}' -> HTTP {Code} {Reason} (no body parsed).",
                legType, (int)response.StatusCode, response.ReasonPhrase);
            return new PreAuthOutcome.Failure($"Firebox returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");
        }

        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (!string.IsNullOrEmpty(mediaType)
            && !mediaType.Equals("application/xml", StringComparison.OrdinalIgnoreCase)
            && !mediaType.Equals("text/xml", StringComparison.OrdinalIgnoreCase))
        {
            return new PreAuthOutcome.Failure(
                $"Firebox endpoint returned non-XML content ({mediaType}). The configured host may not be a WatchGuard SSL VPN endpoint.");
        }

        var body = await response.Content.ReadAsStringAsync(timeoutCts.Token).ConfigureAwait(false);
        _logger?.LogInformation(
            "Watchguard logon leg '{Leg}' raw response: {Body}", legType, body);
        return WatchguardPreAuthClient.ParseLogonResponse(body);
    }

    internal static WatchguardGatewayStatus ParseStatusResponse(string xmlBody)
    {
        if (string.IsNullOrWhiteSpace(xmlBody))
            throw new InvalidOperationException("Firebox returned an empty status response.");

        try
        {
            var doc = LoadHardenedXml(xmlBody);
            var samlEnabledText = SelectText(doc, "saml_enabled");
            var samlEnabled = string.Equals(samlEnabledText, "1", StringComparison.OrdinalIgnoreCase)
                || string.Equals(samlEnabledText, "true", StringComparison.OrdinalIgnoreCase)
                || string.Equals(samlEnabledText, "yes", StringComparison.OrdinalIgnoreCase);
            var domains = doc.GetElementsByTagName("auth-domain")
                .OfType<XmlNode>()
                .Select(SelectAuthDomainName)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s!.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return new WatchguardGatewayStatus(samlEnabled, SelectText(doc, "saml_idp_name"), domains);
        }
        catch (XmlException ex)
        {
            throw new InvalidOperationException($"Firebox returned malformed status XML: {ex.Message}", ex);
        }
    }

    private static string? SelectAuthDomainName(XmlNode authDomain)
    {
        var name = authDomain.SelectSingleNode("name")?.InnerText;
        return string.IsNullOrWhiteSpace(name) ? authDomain.InnerText : name;
    }

    internal static Uri BuildUri(string server, int port, string pathAndQuery)
    {
        if (string.IsNullOrWhiteSpace(server))
            throw new InvalidOperationException("Server is required.");
        if (port is < 1 or > 65535)
            throw new InvalidOperationException("Port must be between 1 and 65535.");
        if (Uri.CheckHostName(server) == UriHostNameType.Unknown)
            throw new InvalidOperationException($"Server '{server}' is not a valid hostname, IPv4, or IPv6 address.");

        var builder = new UriBuilder
        {
            Scheme = Uri.UriSchemeHttps,
            Host = server,
            Port = port,
        };
        var split = pathAndQuery.Split('?', 2);
        builder.Path = split[0].Length == 0 ? "/" : split[0];
        if (split.Length == 2) builder.Query = split[1];
        return builder.Uri;
    }

    private static string BuildQuery(IReadOnlyDictionary<string, string> values)
    {
        var sb = new StringBuilder("?");
        foreach (var (key, value) in values)
        {
            if (sb.Length > 1) sb.Append('&');
            sb.Append(Uri.EscapeDataString(key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(value));
        }
        return sb.ToString();
    }

    internal static bool IsConfiguredFireboxHttpsUri(Uri fireboxBaseUri, string? requestUri)
    {
        ArgumentNullException.ThrowIfNull(fireboxBaseUri);
        if (string.IsNullOrWhiteSpace(requestUri)
            || !Uri.TryCreate(requestUri, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && uri.Port == fireboxBaseUri.Port
            && uri.IdnHost.Equals(fireboxBaseUri.IdnHost, StringComparison.OrdinalIgnoreCase);
    }

    internal static Uri[] BuildSamlLoginUris(string server, int port) =>
    [
        BuildUri(server, port, "/auth/saml?from=sslvpn_client"),
        BuildUri(server, port, "/auth/saml/login?from=sslvpn_client"),
        BuildUri(server, port, "/saml/login?from=sslvpn_client"),
    ];

    private static XmlDocument LoadHardenedXml(string xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        var doc = new XmlDocument { XmlResolver = null };
        using var stringReader = new StringReader(xml);
        using var xmlReader = XmlReader.Create(stringReader, settings);
        doc.Load(xmlReader);
        return doc;
    }

    private static string? SelectText(XmlDocument doc, string nodeName)
    {
        var node = doc.SelectSingleNode($"//{nodeName}");
        return string.IsNullOrWhiteSpace(node?.InnerText) ? null : node.InnerText.Trim();
    }

    private static async Task<byte[]> ReadCappedBytesAsync(HttpResponseMessage response, int capBytes, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        long total = 0;
        while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > capBytes)
                throw new InvalidOperationException($"Watchguard configuration bundle exceeded the {capBytes}-byte safety cap.");
            ms.Write(buffer, 0, read);
        }
        return ms.ToArray();
    }

    private static CancellationTokenSource CreateTimeoutCancellation(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);
        return timeoutCts;
    }

    private static void DisposeCerts(X509Certificate2Collection? certs)
    {
        if (certs is null) return;
        foreach (var c in certs)
        {
            try { c.Dispose(); } catch { /* best effort */ }
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient) _http.Dispose();
        DisposeCerts(_pinnedCaCerts);
    }

    /// <summary>
    /// Diagnostic DelegatingHandler: logs the EXACT request line (query values for secrets
    /// redacted), every request header (incl. the merged User-Agent), the negotiated HTTP version,
    /// and the response's connection-management headers. Used to confirm Wormhole's on-the-wire
    /// request byte-for-byte matches the native wgsslvpnc.exe client when chasing the spurious
    /// AuthPoint push. No secret is logged: fw_password / fw_username / response are redacted.
    /// </summary>
    private sealed class RequestDiagnosticsHandler : DelegatingHandler
    {
        private static readonly HashSet<string> RedactKeys =
            new(StringComparer.OrdinalIgnoreCase) { "fw_password", "fw_username", "response" };

        private readonly ILogger? _logger;

        public RequestDiagnosticsHandler(HttpMessageHandler inner, ILogger? logger) : base(inner) => _logger = logger;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_logger is not null && request.RequestUri is { } uri)
            {
                var headers = string.Join(" | ", request.Headers.Select(h => $"{h.Key}: {string.Join(",", h.Value)}"));
                _logger.LogInformation(
                    "Watchguard REQ {Method} {Path}?{Query} HTTP/{Version} || headers: {Headers}",
                    request.Method.Method, uri.AbsolutePath, RedactQuery(uri.Query), request.Version, headers);
            }

            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (_logger is not null)
            {
                response.Headers.TryGetValues("Set-Cookie", out var setCookie);
                _logger.LogInformation(
                    "Watchguard RESP {Code} HTTP/{Version} Connection=[{Conn}] Set-Cookie={HasCookie} Server=[{Server}]",
                    (int)response.StatusCode, response.Version,
                    string.Join(",", response.Headers.Connection),
                    setCookie is not null,
                    string.Join(",", response.Headers.Server.Select(s => s.ToString())));
            }

            return response;
        }

        private static string RedactQuery(string query)
        {
            var trimmed = query.TrimStart('?');
            if (trimmed.Length == 0) return string.Empty;
            return string.Join('&', trimmed.Split('&').Select(pair =>
            {
                var eq = pair.IndexOf('=');
                if (eq < 0) return pair;
                var key = pair[..eq];
                return RedactKeys.Contains(Uri.UnescapeDataString(key)) ? key + "=***" : pair;
            }));
        }
    }
}
