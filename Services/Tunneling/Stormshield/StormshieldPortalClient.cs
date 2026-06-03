using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
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
    // Zip-bomb defence for the v5 application/zip bundle: a real bundle is ~5 small files. Cap the
    // entry count and each entry's DECOMPRESSED size (the compressed download is already capped at
    // MaxProfileBytes, which does not bound inflation). Mirrors WatchguardWgsslImporter.
    private const int MaxZipEntryBytes = 1 * 1024 * 1024;
    private const int MaxZipEntryCount = 32;
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
            // CONFIG OPENVPN DOWNLOAD is a "Format raw" serverd command (per the command reference),
            // so the OpenVPN profile is returned in the command RESPONSE itself — either as raw text
            // or wrapped in the serverd XML envelope — NOT staged for a separate download. Read the
            // response and extract the profile from it.
            var cmd = Uri.EscapeDataString("CONFIG OPENVPN DOWNLOAD");
            string commandBody;
            using (var cmdResponse = await _http
                .GetAsync(new Uri(_baseUri, $"api/command?sessionid={sid}&cmd={cmd}"), cancellationToken)
                .ConfigureAwait(false))
            {
                if (!cmdResponse.IsSuccessStatusCode)
                    throw new InvalidOperationException(
                        $"Stormshield 'CONFIG OPENVPN DOWNLOAD' returned HTTP {(int)cmdResponse.StatusCode}.");
                // Capped by HttpClient.MaxResponseContentBufferSize on the production client.
                commandBody = await cmdResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            }

            var profile = ExtractProfile(commandBody);
            if (profile is not null) return profile;

            // Fallback: should the firmware instead stage the file for a separate download, try the
            // staged-file endpoint before giving up. (The inline command response above is the
            // documented path; this just keeps an older/edge firmware working.)
            using (var dlResponse = await _http
                .GetAsync(new Uri(_baseUri, $"api/download/tmp.file?sessionid={sid}"),
                    HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false))
            {
                if (dlResponse.IsSuccessStatusCode)
                {
                    var staged = await ReadCappedStringAsync(dlResponse, MaxProfileBytes, cancellationToken).ConfigureAwait(false);
                    var stagedProfile = ExtractProfile(staged);
                    if (stagedProfile is not null) return stagedProfile;
                }
            }

            // Most likely cause: the account lacks serverd/API privilege, so the firewall served an
            // error/HTML page instead of the .ovpn. Point the user at the working fallback.
            throw new InvalidOperationException(
                "Stormshield did not return an OpenVPN profile from the firewall. The account may lack "
                + "configuration-API privilege for automatic retrieval — download the .ovpn from the "
                + "firewall's /auth \"Personal data\" page and use Import (OpenVPN) mode instead.");
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

    /// <summary>
    /// Downloads the per-user OpenVPN bundle using the native <b>v5</b> "SN SSL VPN Client" flow,
    /// reverse-engineered from the client's <c>SSLVPNService.SNS.SnsVpnConfiguration.DownloadConfig</c>:
    /// <c>POST auth/config.html?version=1&amp;type=openvpn</c>, form-urlencoded <c>user</c> / <c>pass</c>.
    ///
    /// <para>Unlike the legacy <c>/auth/admin.html</c> serverd path, this is the low-privilege,
    /// user-facing surface — no administration/serverd privilege, no <c>app</c> token, no SSO. The
    /// single-use OTP, when used, is <b>concatenated directly onto the password</b> (no separator) and
    /// spent here, on the HTTPS config download; the OpenVPN <c>auth-user-pass</c> still uses the real
    /// password. A <c>200 application/zip</c> carries the bundle (<c>.ovpn</c> + CA/cert/key PEMs,
    /// referenced by filename); a <c>200 text/xml</c> carries a <c>&lt;ret code/msg&gt;</c> firewall
    /// error. The bundle's file references are inlined into a self-contained profile for the sidecar.</para>
    /// </summary>
    public async Task<string> DownloadProfileV5Async(
        string username, string password, string? otp, CancellationToken cancellationToken)
    {
        var pass = string.IsNullOrEmpty(otp) ? password : password + otp;
        var form = new Dictionary<string, string> { ["user"] = username, ["pass"] = pass };
        using var content = new FormUrlEncodedContent(form);

        using var response = await _http
            .PostAsync(new Uri(_baseUri, "auth/config.html?version=1&type=openvpn"), content, cancellationToken)
            .ConfigureAwait(false);

        var mediaType = response.Content.Headers.ContentType?.MediaType;

        // The firewall delivers an authentication/authorization error as 200 + text/xml — surface its
        // message before the status check (the native client parses this envelope on 200 too).
        if (IsXmlMediaType(mediaType))
        {
            var xml = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException(DescribeV5Error(xml));
        }
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Stormshield configuration download returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}"
                + (string.IsNullOrEmpty(mediaType) ? "." : $" ({mediaType})."));
        if (!string.Equals(mediaType, "application/zip", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"Stormshield configuration download returned unexpected content type '{mediaType ?? "none"}' "
                + "(expected an application/zip OpenVPN bundle). The configured host may not be a Stormshield SSL VPN portal, "
                + "or this firmware may predate the v5 SSL VPN API — in that case use Import (OpenVPN) mode.");

        var zipBytes = await ReadCappedBytesAsync(response, MaxProfileBytes, cancellationToken).ConfigureAwait(false);
        return AssembleProfileFromZip(zipBytes);
    }

    /// <summary>
    /// Turns the v5 <c>openvpn_client.zip</c> bundle into a single self-contained <c>.ovpn</c> by
    /// inlining its separate CA/cert/key PEM files (referenced by name from the profile) as inline
    /// blocks. The OpenVPN sidecar receives one profile, no loose files.
    /// </summary>
    internal static string AssembleProfileFromZip(byte[] zipBytes)
    {
        using var ms = new MemoryStream(zipBytes, writable: false);
        ZipArchive archive;
        try
        {
            archive = new ZipArchive(ms, ZipArchiveMode.Read);
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidOperationException("Stormshield returned a configuration bundle that is not a valid zip archive.", ex);
        }
        using (archive)
        {
            if (archive.Entries.Count > MaxZipEntryCount)
                throw new InvalidOperationException(
                    $"Stormshield configuration bundle has too many entries ({archive.Entries.Count} > {MaxZipEntryCount}).");

            ZipArchiveEntry? ovpnEntry = null;
            var byName = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in archive.Entries)
            {
                byName[entry.Name] = entry;
                if (ovpnEntry is null && entry.Name.EndsWith(".ovpn", StringComparison.OrdinalIgnoreCase))
                    ovpnEntry = entry;
            }
            if (ovpnEntry is null)
                throw new InvalidOperationException("Stormshield configuration bundle did not contain an OpenVPN (.ovpn) profile.");

            var ovpn = ReadZipEntryText(ovpnEntry);
            var assembled = StormshieldProfileNormalizer.InlineFileReferences(
                ovpn,
                name => byName.TryGetValue(name, out var entry) ? ReadZipEntryText(entry) : null,
                out var unresolved);

            // A truncated/renamed bundle (a ca/cert/key file referenced but not present) would otherwise
            // pass through as a dangling reference and fail deep inside OpenVPN with an opaque "cannot
            // load certificate". Fail fast with an actionable, named error instead.
            if (unresolved.Count > 0)
                throw new InvalidOperationException(
                    "Stormshield configuration bundle was missing referenced key material: "
                    + string.Join(", ", unresolved)
                    + ". The downloaded bundle is incomplete — retry, or download the .ovpn from the firewall's "
                    + "/auth \"Personal data\" page and use Import (OpenVPN) mode.");
            if (!LooksLikeOpenVpnProfile(assembled))
                throw new InvalidOperationException("Stormshield configuration bundle did not yield a usable OpenVPN profile.");
            return assembled;
        }
    }

    // Reads a zip entry as UTF-8 text with a decompressed-size cap (zip-bomb defence — do NOT trust
    // entry.Length, which is attacker-controlled metadata; the streamed total is authoritative).
    private static string ReadZipEntryText(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var ms = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        long total = 0;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            total += read;
            if (total > MaxZipEntryBytes)
                throw new InvalidOperationException(
                    $"Stormshield configuration bundle entry '{entry.Name}' exceeded the {MaxZipEntryBytes}-byte safety cap.");
            ms.Write(buffer, 0, read);
        }
        return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
    }

    private static bool IsXmlMediaType(string? mediaType) =>
        string.Equals(mediaType, "text/xml", StringComparison.OrdinalIgnoreCase)
        || string.Equals(mediaType, "application/xml", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Renders the firewall's <c>text/xml</c> config-download error into an actionable message. The
    /// envelope shape is read defensively (any <c>code</c>/<c>msg</c> attribute or element) so a
    /// firmware-specific layout still yields the human-readable reason the firewall provided.
    /// </summary>
    internal static string DescribeV5Error(string xmlBody)
    {
        string? code = null;
        string? msg = null;
        try
        {
            var doc = LoadHardenedXml(xmlBody);
            msg = doc.SelectSingleNode("//*[@msg]")?.Attributes?["msg"]?.Value
                ?? doc.SelectSingleNode("//ret")?.InnerText
                ?? doc.SelectSingleNode("//msg")?.InnerText;
            code = doc.SelectSingleNode("//*[@code]")?.Attributes?["code"]?.Value
                ?? doc.SelectSingleNode("//code")?.InnerText;
        }
        catch (XmlException) { /* fall through to the no-detail message */ }

        msg = string.IsNullOrWhiteSpace(msg) ? null : msg!.Trim();
        code = string.IsNullOrWhiteSpace(code) ? null : code!.Trim();

        // Only assert a definitive "rejected" when the firewall gave a human-readable reason; a
        // code-only or empty envelope (e.g. an internal/file error, native FirewallErrorCode Internal=7
        // / FileNotFound=11) is reported neutrally, and the credential hint is attached only when there
        // is something to act on rather than blamed on every error.
        var reason = (code, msg) switch
        {
            (not null, not null) => $"the firewall rejected the configuration request (code {code}): {msg}",
            (null, not null) => $"the firewall rejected the configuration request: {msg}",
            (not null, null) => $"the firewall returned an unexpected response while downloading the configuration (code {code}).",
            _ => "the firewall returned an unexpected response while downloading the configuration.",
        };
        var hint = (code is not null || msg is not null)
            ? " If this is an authentication problem, check the username and password and use a fresh one-time code (a single-use OTP cannot be reused)."
            : string.Empty;
        return "Stormshield configuration download failed: " + reason + hint;
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
                throw new InvalidOperationException(
                    $"Stormshield configuration bundle exceeded the {capBytes}-byte safety cap.");
            ms.Write(buffer, 0, read);
        }
        return ms.ToArray();
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
            // ACCESS_DENIED is an AUTHORIZATION refusal, not a credential failure: the firewall accepted the
            // username/password/OTP (a wrong password is AUTH_FAILED) but would not let this account through.
            // The usual trigger is that Automatic mode authenticates against the firewall's management/serverd
            // configuration API (auth/admin.html, app "sslclient" — the surface python-SNS-API uses), which a
            // normal SSL VPN user is not entitled to open; the documented working path for such a user is the
            // captive-portal .ovpn + Import mode. ACCESS_DENIED is not in python-SNS-API's status set, so it
            // formerly fell to the "_" arm and surfaced as an opaque "unexpected authentication status".
            "ACCESS_DENIED" => new StormshieldAuthOutcome.Failure(
                "the firewall accepted the username, password and OTP but denied this account access. Automatic mode "
                + "signs in to the firewall's configuration API (auth/admin.html), which standard SSL VPN users are "
                + "usually not authorized to use. Download the .ovpn from the firewall portal's \"Personal data\" page "
                + "(open the firewall's /auth page in a browser and sign in), then switch this tunnel to Import (OpenVPN) "
                + "mode and paste it — that path needs only SSL VPN access, no administrator rights. To keep using "
                + "Automatic mode, the firewall administrator must grant this account firewall-administration/serverd privilege."),
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
    /// Pulls the OpenVPN profile out of a serverd <c>CONFIG OPENVPN DOWNLOAD</c> response. As a
    /// "Format raw" command it may return the profile as the raw body or wrapped in the serverd XML
    /// envelope. Returns the profile text, or <c>null</c> when the body doesn't contain one (e.g. an
    /// error / HTML page). For the XML case the tightest element whose text content looks like a
    /// profile is chosen, so envelope metadata isn't spliced into the result — the profile's own
    /// inline <c>&lt;ca&gt;</c>/<c>&lt;cert&gt;</c>/<c>&lt;key&gt;</c> tags survive because they
    /// arrive entity-encoded or inside CDATA and are recovered by InnerText.
    /// </summary>
    private static string? ExtractProfile(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        // Try the XML envelope FIRST: a raw .ovpn is not well-formed XML (leading text plus several
        // root-level <ca>/<cert>/<key> blocks), so it throws and falls through to the raw branch.
        // An enveloped profile, by contrast, parses — and a raw-first check would wrongly return the
        // whole envelope because the profile's markers appear as substrings inside it.
        try
        {
            var doc = LoadHardenedXml(body);
            var nodes = doc.SelectNodes("//*");
            string? best = null;
            if (nodes is not null)
            {
                foreach (XmlNode node in nodes)
                {
                    var text = node.InnerText?.Trim();
                    // Pick the tightest (shortest) element whose text looks like a profile — that's
                    // the data leaf, not the envelope whose text also carries metadata.
                    if (!string.IsNullOrEmpty(text)
                        && LooksLikeOpenVpnProfile(text)
                        && (best is null || text!.Length < best.Length))
                    {
                        best = text;
                    }
                }
            }
            return best;
        }
        catch (XmlException)
        {
            // Not XML — treat the body as a raw profile.
            var raw = body.Trim();
            return LooksLikeOpenVpnProfile(raw) ? raw : null;
        }
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
