using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
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

namespace Wormhole.Services.Tunneling.Stormshield;

/// <summary>
/// Seam for testing <see cref="StormshieldTunnelProvider.ResolveAutomaticCoreAsync"/> without a live SNS
/// firewall. Production callers use the real <see cref="StormshieldPortalClient"/>; tests inject a fake
/// that scripts the config-change hash and the downloaded profile.
/// </summary>
internal interface IStormshieldPortal : IDisposable
{
    /// <summary>
    /// Native v5 download: <c>POST auth/config.html?version=1&amp;type=openvpn</c>, returning the assembled,
    /// self-contained <c>.ovpn</c>. The single-use OTP, when supplied, is concatenated onto the password.
    /// </summary>
    Task<string> DownloadProfileV5Async(string username, string password, string? otp, CancellationToken cancellationToken);

    /// <summary>
    /// Native v5 change-check: <c>GET auth/v1/sslvpn/hash</c>, returning the firewall's current SSL VPN
    /// config hash (an opaque token) or <c>null</c> when the firewall doesn't support the endpoint / it
    /// is unreachable. Used to decide whether a cached profile is still current.
    /// </summary>
    Task<string?> GetConfigHashAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Talks to the Stormshield SNS firewall's native <b>v5</b> "SN SSL VPN Client" surface over HTTPS,
/// reverse-engineered from the vendor's shipping client (<c>SSLVPNService.SNS.SnsVpnConfiguration</c>):
///
/// <list type="bullet">
///   <item><b>Config download</b>: <c>POST auth/config.html?version=1&amp;type=openvpn</c>, form-urlencoded
///   <c>user</c> / <c>pass</c> (the single-use OTP, when used, is concatenated onto the password). A
///   <c>200 application/zip</c> carries the per-user OpenVPN bundle (<c>.ovpn</c> + CA/cert/key PEMs);
///   a <c>200 text/xml</c> carries a <c>&lt;ret code/msg&gt;</c> firewall error. This is the low-privilege,
///   user-facing surface — no administration/serverd privilege required (see <see cref="DownloadProfileV5Async"/>).</item>
///   <item><b>Change check</b>: <c>GET auth/v1/sslvpn/hash</c> (unauthenticated) returns the firewall's
///   current SSL VPN config hash, used to decide whether a cached profile is still current
///   (see <see cref="GetConfigHashAsync"/>).</item>
/// </list>
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
    // Cap for buffered responses (the config-change hash GET + a text/xml download error, both small).
    // The zip bundle download streams instead (ReadCappedBytesAsync) under its own MaxProfileBytes limit.
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

    /// <summary>
    /// Downloads the per-user OpenVPN bundle using the native <b>v5</b> "SN SSL VPN Client" flow,
    /// reverse-engineered from the client's <c>SSLVPNService.SNS.SnsVpnConfiguration.DownloadConfig</c>:
    /// <c>POST auth/config.html?version=1&amp;type=openvpn</c>, form-urlencoded <c>user</c> / <c>pass</c>.
    ///
    /// <para>Unlike the legacy <c>/auth/admin.html</c> serverd path, this is the low-privilege,
    /// user-facing surface — no administration/serverd privilege, no <c>app</c> token, no SSO. The
    /// single-use OTP, when used, is <b>concatenated directly onto the password</b> (no separator) and
    /// spent here, on the HTTPS config download. If that happens, the caller deliberately stops and asks
    /// the user to reconnect with a fresh OTP for the OpenVPN tunnel authentication. A <c>200
    /// application/zip</c> carries the bundle (<c>.ovpn</c> + CA/cert/key PEMs, referenced by filename);
    /// a <c>200 text/xml</c> carries a <c>&lt;ret code/msg&gt;</c> firewall error. The bundle's file
    /// references are inlined into a self-contained profile for the sidecar.</para>
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
    /// Fetches the firewall's current SSL VPN configuration hash via the native v5 change-check endpoint
    /// (<c>GET auth/v1/sslvpn/hash</c>), mirroring <c>SnsVpnConfiguration.GetSnsConfigHash</c>. The endpoint
    /// is unauthenticated (the pinned server certificate is the only trust check) and returns a quoted
    /// SHA-256; this strips the quotes and upper-cases the value for a stable, case-insensitive comparison.
    ///
    /// <para>Returns <c>null</c> — never throws (except on genuine caller cancellation) — when the firewall
    /// doesn't expose the endpoint, is unreachable, times out, or answers with something that isn't a hash
    /// (e.g. an HTML error page). The caller treats a null as "change-check unavailable" and falls back to
    /// the cache-presence heuristic, so a missing endpoint degrades gracefully rather than failing the connect.</para>
    /// </summary>
    public async Task<string?> GetConfigHashAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_baseUri, "auth/v1/sslvpn/hash"));
            // Mirror the native client's Accept headers (it asks for text/html, text/plain).
            request.Headers.Accept.ParseAdd("text/html");
            request.Headers.Accept.ParseAdd("text/plain");
            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return null;

            var hash = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim().Trim('"');
            // The native client returns a 66-char quoted SHA-256, i.e. exactly 64 hex chars once the quotes
            // are stripped. Require exactly that: anything else (an HTML page, an XML envelope, a truncated
            // body) is "not a hash" → null → the caller degrades gracefully (cache-presence heuristic). Being
            // strict here matters because this value gates HIT vs MISS — and a MISS spends the OTP.
            if (hash.Length != 64 || !hash.All(char.IsAsciiHexDigit)) return null;
            return hash.ToUpperInvariant();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // HttpRequestException, a non-cancellation TaskCanceledException (timeout), etc. → unavailable.
            return null;
        }
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

        // Trailing slash so relative Uris ("auth/config.html") resolve under the host root.
        return new UriBuilder { Scheme = Uri.UriSchemeHttps, Host = server, Port = port, Path = "/" }.Uri;
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
