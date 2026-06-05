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
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PushApprovalTimeout = TimeSpan.FromSeconds(90);

    private readonly HttpClient _http;
    private readonly CookieContainer? _cookieContainer;
    private readonly bool _ownsHttpClient;
    private readonly X509Certificate2Collection? _pinnedCaCerts;

    public WatchguardConfigClient(bool trustServerCertificate, string? caPem = null)
    {
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

            _http = new HttpClient(handler, disposeHandler: true)
            {
                Timeout = System.Threading.Timeout.InfiniteTimeSpan,
                MaxResponseContentBufferSize = MaxConfigBytes,
            };
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
        _ownsHttpClient = false;
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
        var form = new Dictionary<string, string>
        {
            ["action"] = "sslvpn_logon",
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "logon",
            ["fw_domain"] = domain,
            ["fw_username"] = username,
            ["fw_password"] = password,
        };
        return SendLogonRequestAsync(server, port, form, cancellationToken);
    }

    public Task<PreAuthOutcome> RespondToChallengeAsync(
        string server, int port, string logonId, string otpCode, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["action"] = "sslvpn_logon",
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "response",
            ["fw_logon_id"] = logonId,
            ["response"] = otpCode,
        };
        return SendLogonRequestAsync(server, port, form, cancellationToken);
    }

    public Task<PreAuthOutcome> RespondToMfaChoiceAsync(
        string server, int port, string logonId, string choice, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["action"] = "sslvpn_logon",
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "mfa_response",
            ["fw_logon_id"] = logonId,
            ["mfa_choice"] = choice,
        };
        return SendLogonRequestAsync(server, port, form, cancellationToken, PushApprovalTimeout);
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
        if (!response.IsSuccessStatusCode)
            return new PreAuthOutcome.Failure($"Firebox returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");

        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (!string.IsNullOrEmpty(mediaType)
            && !mediaType.Equals("application/xml", StringComparison.OrdinalIgnoreCase)
            && !mediaType.Equals("text/xml", StringComparison.OrdinalIgnoreCase))
        {
            return new PreAuthOutcome.Failure(
                $"Firebox endpoint returned non-XML content ({mediaType}). The configured host may not be a WatchGuard SSL VPN endpoint.");
        }

        var body = await response.Content.ReadAsStringAsync(timeoutCts.Token).ConfigureAwait(false);
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
}
