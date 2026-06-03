using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace Wormhole.Services.Tunneling.Stormshield;

/// <summary>
/// Seam for testing <see cref="StormshieldTunnelProvider.RunAuthLoopAsync"/> without a live SNS
/// firewall. Production callers use the real <see cref="StormshieldPortalClient"/>; tests inject a
/// fake that scripts the auth outcomes and the downloaded profile.
/// </summary>
internal interface IStormshieldPortal : IDisposable
{
    /// <summary>POST username/password (+optional OTP) to the captive-portal auth endpoint.</summary>
    Task<StormshieldAuthOutcome> AuthenticateAsync(
        string username, string password, string? otp, string app, CancellationToken cancellationToken);

    /// <summary>
    /// After a successful auth, download the per-user OpenVPN profile over the authenticated session.
    /// Returns the raw <c>.ovpn</c> text.
    /// </summary>
    Task<string> DownloadProfileAsync(string app, CancellationToken cancellationToken);
}

/// <summary>
/// Talks to the Stormshield SNS firewall captive/authentication portal over HTTPS. The protocol is
/// the one Stormshield publishes in its own open-source client
/// (<c>github.com/stormshield/python-SNS-API</c>, module <c>stormshield.sns.sslclient</c>):
///
/// <list type="bullet">
///   <item><b>Auth</b>: <c>POST /auth/admin.html</c>, form-urlencoded
///   <c>uid=base64(user)</c>, <c>pswd=base64(pass)</c>, <c>app=&lt;app&gt;</c>, and
///   <c>totp=base64(otp)</c> when an OTP is used. The response is XML whose root carries a
///   <c>msg</c> attribute ∈ {<c>AUTH_SUCCESS</c>, <c>AUTH_FAILED</c>, <c>NEED_TOTP_AUTH</c>,
///   <c>ERR_BRUTEFORCE</c> (+ <c>delay</c>)}. The session lives in a cookie carried forward.</item>
///   <item><b>Config download</b>: open a serverd API session
///   (<c>POST /api/auth/login</c> → <c>sessionid</c>), run the documented
///   <c>GET /api/command?sessionid=…&amp;cmd=CONFIG OPENVPN DOWNLOAD</c> command (available since
///   firmware 2.0.0), then stream the produced file from
///   <c>GET /api/download/tmp.file?sessionid=…</c>, and <c>GET /api/auth/logout?sessionid=…</c>.</item>
/// </list>
///
/// <para>
/// CONFIDENCE: the <c>/auth/admin.html</c> auth contract is verified first-hand against the vendor's
/// own source. The serverd download endpoints are likewise from that source, but they require the
/// account to have serverd/API privilege — a low-privilege VPN user normally retrieves the profile
/// from the captive-portal "Personal data" page instead, whose literal href is undocumented and
/// would need a packet capture to pin. The download is therefore centralized in one method so that
/// alternative can be slotted in without touching the provider; users without API privilege should
/// use Import ("OpenVPN") mode in the meantime.
/// </para>
///
/// <para>
/// TLS: SNS factory certificates put the appliance serial number in the certificate CN (no matching
/// SAN), and firmware ≥ 5.0 presents a custom internal CA. So when the user pins a CA we validate
/// the chain against it but tolerate a hostname mismatch (the pinned CA is the real trust anchor) —
/// this mirrors the vendor client's <c>check_hostname=False</c> + manual-CN behavior and is the one
/// deliberate divergence from <c>WatchguardPreAuthClient</c>, which rejects name mismatches.
/// </para>
/// </summary>
internal sealed class StormshieldPortalClient : IStormshieldPortal
{
    private const int MaxProfileBytes = 1 * 1024 * 1024; // a real .ovpn with inline PEMs is ~10 KiB
    // Cap for buffered responses (the auth POST + serverd login/command, which are small XML docs).
    // The profile download streams instead (ResponseHeadersRead + ReadCappedStringAsync), so it is
    // exempt from this buffer cap and keeps its own MaxProfileBytes limit.
    private const int MaxBufferedResponseBytes = 4 * 1024 * 1024;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private readonly HttpClient _http;
    private readonly Uri _baseUri;
    private readonly bool _ownsHttpClient;
    // Held so Dispose can release the native handles the validation-callback closure captured —
    // HttpClientHandler.Dispose does not walk callback-captured certificates.
    private readonly X509Certificate2Collection? _pinnedCaCerts;

    public StormshieldPortalClient(string server, int port, bool trustServerCertificate, string? caPem)
    {
        _baseUri = BuildBaseUri(server, port);

        // CookieContainer so the portal session set by the auth POST is carried into the
        // config-download requests automatically.
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
                // Honors the explicit "trust everything" opt-in. Security note: this disables
                // hostname, chain, and revocation checks for the pre-auth POST, so credentials /
                // OTP would be visible to a MITM on a hostile network.
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
                        "Stormshield CA certificate (PEM) failed to parse — check the pasted CA bundle for "
                        + "missing/extra armor lines, truncated base64, or non-PEM content.", ex);
                }
                if (caCerts.Count == 0)
                {
                    throw new InvalidOperationException("Stormshield CA certificate (PEM) contained no certificates.");
                }
                var pinned = caCerts;
                handler.ServerCertificateCustomValidationCallback = (_, serverCert, peerChain, errors) =>
                {
                    // The pinned CA — not the OS trust store — is the authoritative anchor. Tolerate
                    // a hostname mismatch because SNS factory certs use the appliance serial as the
                    // CN with no matching SAN (the vendor client sets check_hostname=False for the
                    // same reason); the CA pin still prevents a MITM. Reject every OTHER policy bit.
                    const SslPolicyErrors tolerated =
                        SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch;
                    if ((errors & ~tolerated) != SslPolicyErrors.None) return false;
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
            // else: default OS trust-store validation (works only when the firewall presents a
            // publicly-trusted certificate — uncommon, but the recommended setup for OIDC SSO).

            _http = new HttpClient(handler, disposeHandler: true)
            {
                Timeout = RequestTimeout,
                MaxResponseContentBufferSize = MaxBufferedResponseBytes,
            };
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

    // Test seam: inject a fake HttpClient pointed at a loopback listener + the base URI it serves.
    public StormshieldPortalClient(HttpClient http, Uri baseUri)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(baseUri);
        _http = http;
        _baseUri = baseUri;
        _ownsHttpClient = false;
        _pinnedCaCerts = null;
    }

    public async Task<StormshieldAuthOutcome> AuthenticateAsync(
        string username, string password, string? otp, string app, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            // Field names + base64 encoding mirror python-SNS-API's password-auth request verbatim.
            ["uid"] = Base64Utf8(username),
            ["pswd"] = Base64Utf8(password),
            ["app"] = app,
        };
        if (!string.IsNullOrEmpty(otp))
            form["totp"] = Base64Utf8(otp);

        using var content = new FormUrlEncodedContent(form);
        using var response = await _http.PostAsync(new Uri(_baseUri, "auth/admin.html"), content, cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            return new StormshieldAuthOutcome.Failure($"Portal returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");
        if (IsNonXmlContent(response, out var mediaType))
            return new StormshieldAuthOutcome.Failure(
                $"Stormshield portal returned non-XML content ({mediaType}). The configured host may not be a Stormshield SSL VPN portal.");

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ParseAuthResponse(body);
    }

    public async Task<string> DownloadProfileAsync(string app, CancellationToken cancellationToken)
    {
        // Open a serverd API session over the same cookie session established by AuthenticateAsync.
        var sessionId = await OpenServerdSessionAsync(app, cancellationToken).ConfigureAwait(false);
        // The session id comes from the firewall's own XML, but escape it before interpolating into
        // the query string anyway — keeps it consistent with the escaped `cmd` below and removes any
        // chance of a malformed value altering the request shape.
        var sid = Uri.EscapeDataString(sessionId);
        try
        {
            // Documented since firmware 2.0.0: stages the OpenVPN client config as a temp file.
            var cmd = Uri.EscapeDataString("CONFIG OPENVPN DOWNLOAD");
            using (var cmdResponse = await _http
                .GetAsync(new Uri(_baseUri, $"api/command?sessionid={sid}&cmd={cmd}"), cancellationToken)
                .ConfigureAwait(false))
            {
                if (!cmdResponse.IsSuccessStatusCode)
                    throw new InvalidOperationException(
                        $"Stormshield 'CONFIG OPENVPN DOWNLOAD' returned HTTP {(int)cmdResponse.StatusCode}.");
            }

            using var dlResponse = await _http
                .GetAsync(new Uri(_baseUri, $"api/download/tmp.file?sessionid={sid}"),
                    HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            if (!dlResponse.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Stormshield profile download returned HTTP {(int)dlResponse.StatusCode}.");

            var profile = await ReadCappedStringAsync(dlResponse, MaxProfileBytes, cancellationToken).ConfigureAwait(false);
            if (!LooksLikeOpenVpnProfile(profile))
            {
                // Most likely cause: the account lacks serverd/API privilege, so the firewall served
                // an error/HTML page instead of the .ovpn. Point the user at the working fallback.
                throw new InvalidOperationException(
                    "Stormshield did not return an OpenVPN profile from the firewall. The account may lack "
                    + "configuration-API privilege for automatic retrieval — download the .ovpn from the "
                    + "firewall's /auth \"Personal data\" page and use Import (OpenVPN) mode instead.");
            }
            return profile;
        }
        finally
        {
            // Best-effort logout — never mask the primary outcome.
            try
            {
                using var ct = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                ct.CancelAfter(TimeSpan.FromSeconds(5));
                using var _ = await _http
                    .GetAsync(new Uri(_baseUri, $"api/auth/logout?sessionid={sid}"), ct.Token)
                    .ConfigureAwait(false);
            }
            catch { /* best effort */ }
        }
    }

    private async Task<string> OpenServerdSessionAsync(string app, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string> { ["app"] = app, ["id"] = "0" };
        using var content = new FormUrlEncodedContent(form);
        using var response = await _http.PostAsync(new Uri(_baseUri, "api/auth/login"), content, cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Stormshield serverd login returned HTTP {(int)response.StatusCode}.");
        if (IsNonXmlContent(response, out var mediaType))
            throw new InvalidOperationException(
                $"Stormshield serverd login returned non-XML content ({mediaType}) — the host may not be a Stormshield SSL VPN portal.");

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var sessionId = SelectText(body, "sessionid");
        if (string.IsNullOrWhiteSpace(sessionId))
            throw new InvalidOperationException(
                "Stormshield serverd login did not return a session id (the account may lack API privilege).");
        return sessionId!;
    }

    /// <summary>
    /// Builds the portal base URI safely: validates <paramref name="server"/> as a bare host
    /// (rejecting inputs that would smuggle userinfo / path / query into the parser) and assigns
    /// scheme/host/port positionally rather than via string interpolation.
    /// </summary>
    internal static Uri BuildBaseUri(string server, int port)
    {
        if (string.IsNullOrWhiteSpace(server))
            throw new InvalidOperationException("Server is required.");
        if (port is < 1 or > 65535)
            throw new InvalidOperationException("Port must be between 1 and 65535.");
        if (Uri.CheckHostName(server) == UriHostNameType.Unknown)
            throw new InvalidOperationException($"Server '{server}' is not a valid hostname, IPv4, or IPv6 address.");

        // Trailing slash so relative Uris ("auth/admin.html") resolve under the host root.
        return new UriBuilder { Scheme = Uri.UriSchemeHttps, Host = server, Port = port, Path = "/" }.Uri;
    }

    internal static StormshieldAuthOutcome ParseAuthResponse(string xmlBody)
    {
        if (string.IsNullOrWhiteSpace(xmlBody))
            return new StormshieldAuthOutcome.Failure("Portal returned an empty response body.");

        string? msg;
        string? delay;
        try
        {
            var doc = LoadHardenedXml(xmlBody);
            // The status lives on whichever element carries a `msg` attribute (the response root in
            // practice); search by attribute so we don't depend on the exact element name.
            var node = doc.SelectSingleNode("//*[@msg]");
            msg = node?.Attributes?["msg"]?.Value;
            delay = node?.Attributes?["delay"]?.Value;
        }
        catch (XmlException ex)
        {
            return new StormshieldAuthOutcome.Failure($"Portal returned malformed XML: {ex.Message}");
        }

        return msg switch
        {
            "AUTH_SUCCESS" => new StormshieldAuthOutcome.Ok(),
            "NEED_TOTP_AUTH" => new StormshieldAuthOutcome.NeedOtp(),
            "ERR_BRUTEFORCE" => new StormshieldAuthOutcome.Bruteforce(int.TryParse(delay, out var d) ? d : 0),
            "AUTH_FAILED" => new StormshieldAuthOutcome.Failure("Authentication failed — check the username and password."),
            null => new StormshieldAuthOutcome.Failure("Portal response did not contain an authentication status."),
            _ => new StormshieldAuthOutcome.Failure($"Portal returned an unexpected authentication status '{msg}'."),
        };
    }

    internal static bool LooksLikeOpenVpnProfile(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        // A self-contained Stormshield profile always carries a remote and a tun/tap device or the
        // inline CA block. Two independent markers keeps an error page that happens to mention one
        // keyword from passing.
        var hasRemote = text.Contains("remote ", StringComparison.OrdinalIgnoreCase);
        var hasDeviceOrCa = text.Contains("dev tun", StringComparison.OrdinalIgnoreCase)
            || text.Contains("dev tap", StringComparison.OrdinalIgnoreCase)
            || text.Contains("<ca>", StringComparison.OrdinalIgnoreCase);
        return hasRemote && hasDeviceOrCa;
    }

    /// <summary>
    /// True when the response declares a Content-Type that is present and is neither application/xml
    /// nor text/xml. A captive portal / WAF / wrong host can answer 200 OK with HTML, which would
    /// otherwise slip past the status check and surface later as a misleading "malformed XML" error;
    /// surfacing the media type tells the operator the host isn't a Stormshield portal. Mirrors the
    /// guard in WatchguardPreAuthClient.PostFormAsync.
    /// </summary>
    private static bool IsNonXmlContent(HttpResponseMessage response, out string? mediaType)
    {
        mediaType = response.Content.Headers.ContentType?.MediaType;
        return !string.IsNullOrEmpty(mediaType)
            && !mediaType.Equals("application/xml", StringComparison.OrdinalIgnoreCase)
            && !mediaType.Equals("text/xml", StringComparison.OrdinalIgnoreCase);
    }

    private static XmlDocument LoadHardenedXml(string xml)
    {
        // DTD prohibited + no resolver: defends against XXE and entity-expansion DoS from a hostile
        // or proxied response. Same hardening as WatchguardPreAuthClient.
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        var doc = new XmlDocument { XmlResolver = null };
        using var stringReader = new StringReader(xml);
        using var xmlReader = XmlReader.Create(stringReader, settings);
        doc.Load(xmlReader);
        return doc;
    }

    private static string? SelectText(string xmlBody, string nodeName)
    {
        try
        {
            var doc = LoadHardenedXml(xmlBody);
            return doc.SelectSingleNode($"//{nodeName}")?.InnerText;
        }
        catch (XmlException)
        {
            return null;
        }
    }

    private static async Task<string> ReadCappedStringAsync(HttpResponseMessage response, int capBytes, CancellationToken ct)
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
                throw new InvalidOperationException(
                    $"Stormshield profile download exceeded the {capBytes}-byte safety cap.");
            ms.Write(buffer, 0, read);
        }
        return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }

    private static string Base64Utf8(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

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

/// <summary>Outcome of a Stormshield portal authentication POST. Discriminated via type test.</summary>
internal abstract record StormshieldAuthOutcome
{
    public sealed record Ok : StormshieldAuthOutcome;
    public sealed record NeedOtp : StormshieldAuthOutcome;
    public sealed record Bruteforce(int DelaySeconds) : StormshieldAuthOutcome;
    public sealed record Failure(string Reason) : StormshieldAuthOutcome;
}
