using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace Wormhole.Services.Tunneling.Watchguard;

/// <summary>
/// Seam for testing <see cref="WatchguardTunnelProvider.RunPreAuthLoopAsync"/> without
/// spinning up a real Firebox or HTTP listener. Production callers use the real
/// <see cref="WatchguardPreAuthClient"/>; tests inject a fake that scripts the outcome sequence.
/// </summary>
internal interface IWatchguardPreAuth
{
    Task<PreAuthOutcome> LogonAsync(string server, int port, string username, string password, string domain, CancellationToken cancellationToken);
    Task<PreAuthOutcome> RespondToChallengeAsync(string server, int port, string logonId, string otpCode, CancellationToken cancellationToken);
    Task<PreAuthOutcome> RespondToMfaChoiceAsync(string server, int port, string logonId, string choice, CancellationToken cancellationToken);
}

/// <summary>
/// Thin HttpClient wrapper over the Firebox `/?action=sslvpn_logon` endpoint. The official
/// WatchGuard client sends the logon fields in the query string, parses the XML response,
/// and either proceeds with the original password (no 2FA) or prompts the user for an OTP
/// (challenge) which then becomes the OpenVPN auth-user-pass password.
///
/// Outcome encoding follows the reverse-engineered logon_status values:
///   1 = Ok (credentials accepted, proceed)
///   4 = Challenge (classic Firebox-DB — server wants a one-time code via the response leg)
///   8 = Challenge (AuthPoint/RADIUS MFA — same response-leg shape; the gateway returns a
///       logon_id + chaStr "Type 'p' to receive a push notification or type your one-time
///       password". Confirmed against a live AuthPoint Firebox.)
///   anything else = Failure (treat as bad credentials / server error)
///
/// References:
///   - https://tazj.in/blog/reversing-watchguard-vpn
///   - https://github.com/tazjin/watchblob (archived but accurate)
/// </summary>
internal sealed class WatchguardPreAuthClient : IWatchguardPreAuth, IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    // Pinned CA chain certs captured by the validation callback closure. We hold a direct
    // reference so Dispose() can release the native SafeCertContextHandle each cert owns —
    // HttpClientHandler.Dispose() does NOT walk callback-captured certificates.
    private readonly X509Certificate2Collection? _pinnedCaCerts;

    public WatchguardPreAuthClient(bool trustServerCertificate, string? caPem = null)
    {
        // Build the handler inside a try/catch so a partial-construction failure (e.g.
        // ImportFromPem partway, or a future runtime that throws from HttpClient) doesn't
        // orphan the unmanaged handle held by HttpClientHandler. On failure: dispose any
        // partially-loaded certs AND the handler before rethrowing.
        var handler = new HttpClientHandler();
        X509Certificate2Collection? caCerts = null;
        try
        {
            if (trustServerCertificate)
            {
                // Honors the user's explicit "trust everything" opt-in (the dialog checkbox is
                // labeled to spell out that this skips ALL TLS checks, not just the OpenVPN
                // verify-x509-name subject pin). Mirrors the official client's "Always trust
                // this server" toggle and the FortinetSettings.TrustServerCertificate path.
                //
                // Security note: this disables hostname, chain, and revocation checks for the
                // pre-auth request. Username / password / OTP would be visible to a MITM on a
                // hostile network. The downstream OpenVPN sidecar still validates the tunnel
                // with the inline <ca> block, but that's not a substitute for pre-auth TLS —
                // credentials leave the client before the sidecar starts.
                handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            }
            else if (!string.IsNullOrWhiteSpace(caPem))
            {
                // For self-signed Firebox deployments the user supplies the CA via the dialog.
                // Without this hook the pre-auth request would always fail TLS chain validation
                // against the OS trust store even though OpenVPN's downstream <ca> block accepts
                // it — surfacing as a confusing "RemoteCertificateChainErrors" before the sidecar
                // ever launches. Load the PEM (one or more concatenated certs) and validate the
                // chain against it. Failure to parse is LOUD (throws) rather than a silent
                // fall-back so the operator sees the actual cause (typo, truncated paste, wrong
                // armor) instead of a downstream chain-error mystery.
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
                {
                    throw new InvalidOperationException(
                        "Watchguard CA certificate (PEM) contained no certificates.");
                }
                var pinned = caCerts;
                handler.ServerCertificateCustomValidationCallback = (_, serverCert, peerChain, errors) =>
                {
                    // When the user pinned a CA, the user-supplied CA — NOT the OS trust store —
                    // is the authoritative trust anchor. Returning true on SslPolicyErrors.None
                    // would silently accept any cert the OS already trusts (e.g. a WebPKI cert
                    // for the same hostname), diverging from the OpenVPN sidecar's <ca> bundle:
                    // pre-auth would succeed while the sidecar later rejects the same cert.
                    // Always validate against the pinned CA.
                    //
                    // Hostname / missing-cert errors still fail outright — the custom chain only
                    // overrides root trust, not the other policy bits.
                    if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
                    if (serverCert is null) return false;
                    using var customChain = new X509Chain();
                    customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    customChain.ChainPolicy.CustomTrustStore.AddRange(pinned);
                    // Copy the intermediates the server sent (the leaf is at ChainElements[0];
                    // anything above it is an intermediate) into ExtraStore so a Firebox that
                    // presents a "leaf → intermediate" chain rooted at the pinned CA validates
                    // even when the intermediate isn't in the local machine trust store. Without
                    // this, partial-chain deployments fail TLS even though the server's chain
                    // is correct against the pinned root.
                    if (peerChain is not null)
                    {
                        for (var i = 1; i < peerChain.ChainElements.Count; i++)
                        {
                            customChain.ChainPolicy.ExtraStore.Add(peerChain.ChainElements[i].Certificate);
                        }
                    }
                    return customChain.Build(serverCert);
                };
            }
            _http = new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(20),
            };
            ApplyNativeClientHeaders(_http);
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

    private static void ApplyNativeClientHeaders(HttpClient http)
    {
        // Identify as the native WatchGuard client so the Firebox doesn't fire a push for an OTP
        // answered via the `response` leg. See WatchguardConfigClient.NativeUserAgent.
        if (!http.DefaultRequestHeaders.Contains("User-Agent"))
            http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", WatchguardConfigClient.NativeUserAgent);
    }

    // Test seam: inject a fake HttpClient pointed at a loopback HttpListener.
    public WatchguardPreAuthClient(HttpClient http)
    {
        ArgumentNullException.ThrowIfNull(http);
        _http = http;
        ApplyNativeClientHeaders(_http);
        _ownsHttpClient = false;
        _pinnedCaCerts = null;
    }

    private static void DisposeCerts(X509Certificate2Collection? certs)
    {
        if (certs is null) return;
        foreach (var c in certs)
        {
            try { c.Dispose(); } catch { /* best effort */ }
        }
    }

    public async Task<PreAuthOutcome> LogonAsync(
        string server, int port, string username, string password, string domain, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            // Field names AND ORDER mirror wgsslvpnc.exe's template exactly:
            //   /?action=sslvpn_logon&fw_username=%1&fw_password=%2&style=fw_logon_progress.xsl&fw_logon_type=logon&fw_domain=%3
            ["action"] = "sslvpn_logon",
            ["fw_username"] = username,
            ["fw_password"] = password,
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "logon",
            ["fw_domain"] = domain,
        };
        var uri = BuildLogonUri(server, port, form);
        return await SendLogonRequestAsync(uri, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PreAuthOutcome> RespondToChallengeAsync(
        string server, int port, string logonId, string otpCode, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            // The OTP answer goes in `response` with fw_logon_type=response. Native template:
            //   /?action=sslvpn_logon&style=fw_logon_progress.xsl&fw_logon_type=response&response=%1&fw_logon_id=%2
            // After a successful response leg the same OTP also becomes the OpenVPN auth-user-pass
            // password (the gateway records the (user, OTP) one-shot accept) — handled by the caller.
            ["action"] = "sslvpn_logon",
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "response",
            ["response"] = otpCode,
            ["fw_logon_id"] = logonId,
        };
        var uri = BuildLogonUri(server, port, form);
        return await SendLogonRequestAsync(uri, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PreAuthOutcome> RespondToMfaChoiceAsync(
        string server, int port, string logonId, string choice, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            // Push uses the DISTINCT mfa_response leg, exactly as wgsslvpnc.exe does:
            //   /?action=sslvpn_logon&style=fw_logon_progress.xsl&fw_logon_type=mfa_response&mfa_choice=%1&fw_logon_id=%2
            // Only this request makes the firewall fire a push — an OTP answered via the `response`
            // leg must therefore NOT reuse this shape.
            ["action"] = "sslvpn_logon",
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "mfa_response",
            ["mfa_choice"] = choice,
            ["fw_logon_id"] = logonId,
        };
        var uri = BuildLogonUri(server, port, form);
        return await SendLogonRequestAsync(uri, cancellationToken).ConfigureAwait(false);
    }

    private async Task<PreAuthOutcome> SendLogonRequestAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var response = await _http.GetAsync(uri, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return new PreAuthOutcome.Failure($"Firebox returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");
        }
        // Sniff Content-Type: a captive portal, WAF, or non-WatchGuard endpoint on the same
        // host:port can return 200 OK with HTML, which would slip past the success-code check
        // and surface as a misleading "malformed XML" message later. Surfacing the mismatch
        // explicitly tells the operator "this endpoint isn't a Firebox" instead.
        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (!string.IsNullOrEmpty(mediaType)
            && !mediaType.Equals("application/xml", StringComparison.OrdinalIgnoreCase)
            && !mediaType.Equals("text/xml", StringComparison.OrdinalIgnoreCase))
        {
            return new PreAuthOutcome.Failure(
                $"Firebox endpoint returned non-XML content ({mediaType}). The configured host may not be a WatchGuard SSL VPN endpoint.");
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return ParseLogonResponse(body);
    }

    /// <summary>
    /// Builds the logon URI safely: validates <paramref name="server"/> as a bare host (rejecting
    /// inputs that would smuggle a userinfo / path / query into the Uri parser via `@`, `/`, `?`,
    /// `#`, etc.) and uses UriBuilder so the scheme/host/port/path are assigned positionally
    /// rather than through string interpolation.
    /// </summary>
    internal static Uri BuildLogonUri(string server, int port) =>
        BuildLogonUri(server, port, new Dictionary<string, string>
        {
            ["action"] = "sslvpn_logon",
            ["style"] = "fw_logon_progress.xsl",
            ["fw_logon_type"] = "logon",
        });

    internal static Uri BuildLogonUri(string server, int port, IReadOnlyDictionary<string, string> query)
    {
        if (string.IsNullOrWhiteSpace(server))
            throw new InvalidOperationException("Server is required.");
        if (port is < 1 or > 65535)
            throw new InvalidOperationException("Port must be between 1 and 65535.");
        ArgumentNullException.ThrowIfNull(query);

        // CheckHostName accepts DNS names, IPv4, IPv6 — and rejects strings containing reserved
        // URI characters (`@`, `/`, `?`, `#`, control chars, spaces). This is the same parser
        // Uri uses internally, so we get exact-spelling coverage of what would smuggle through.
        var kind = Uri.CheckHostName(server);
        if (kind == UriHostNameType.Unknown)
            throw new InvalidOperationException(
                $"Server '{server}' is not a valid hostname, IPv4, or IPv6 address.");

        var builder = new UriBuilder
        {
            Scheme = Uri.UriSchemeHttps,
            // UriBuilder wraps an IPv6 literal in brackets on Build; we just hand it the raw form.
            Host = server,
            Port = port,
            Path = "/",
            Query = BuildQuery(query),
        };
        return builder.Uri;
    }

    private static string BuildQuery(IReadOnlyDictionary<string, string> values)
    {
        var sb = new StringBuilder();
        foreach (var (key, value) in values)
        {
            if (sb.Length > 0) sb.Append('&');
            sb.Append(Uri.EscapeDataString(key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(value));
        }
        return sb.ToString();
    }

    internal static PreAuthOutcome ParseLogonResponse(string xmlBody)
    {
        if (string.IsNullOrWhiteSpace(xmlBody))
            return new PreAuthOutcome.Failure("Firebox returned an empty response body.");

        int? status = null;
        string? logonId = null;
        string? chaStr = null;
        string? errorMessage = null;

        try
        {
            // Build an XmlReader with DTD processing explicitly prohibited and no XmlResolver.
            // Modern .NET sets XmlResolver=null by default on XmlDocument (mitigating classic
            // XXE), but billion-laughs DoS via internal entity expansion is still possible
            // under the default settings. The explicit settings are belt-and-suspenders against
            // both a hostile server and future runtime default changes.
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
            };
            var doc = new XmlDocument();
            using var stringReader = new StringReader(xmlBody);
            using var xmlReader = XmlReader.Create(stringReader, settings);
            doc.Load(xmlReader);
            status = TryParseInt(SelectText(doc, "logon_status"));
            logonId = SelectText(doc, "logon_id");
            chaStr = SelectText(doc, "chaStr");
            errorMessage = SelectText(doc, "message") ?? SelectText(doc, "errStr");
        }
        catch (XmlException ex)
        {
            return new PreAuthOutcome.Failure($"Firebox returned malformed XML: {ex.Message}");
        }

        return status switch
        {
            1 => new PreAuthOutcome.Ok(),
            // Both status 4 (classic Firebox-DB challenge) AND status 8 (AuthPoint/RADIUS MFA) are
            // challenges when the gateway returns a logon_id + chaStr. Confirmed from a live
            // AuthPoint Firebox capture: a bare-password logon answers
            //   <logon_status>8</logon_status><logon_id>1810</logon_id>
            //   <chaStr>Type "p" to receive a push notification or type your one-time password</chaStr>
            // i.e. the OTP (or "p") must come back via the `response` leg
            // (fw_logon_type=response&fw_logon_id=…&response=…), NOT appended to the password in a
            // fresh logon — doing the latter makes the gateway answer <errStr>501</errStr>.
            // IsNullOrWhiteSpace (not IsNullOrEmpty): a `<logon_id>   </logon_id>` from a
            // non-conforming firmware would otherwise look like a valid challenge.
            4 or 8 when !string.IsNullOrWhiteSpace(logonId) => new PreAuthOutcome.Challenge(logonId!, chaStr ?? string.Empty),
            4 => new PreAuthOutcome.Failure("Firebox requested a 2FA challenge but did not return a logon_id."),
            _ => new PreAuthOutcome.Failure(
                string.IsNullOrWhiteSpace(errorMessage)
                    ? $"Firebox rejected credentials (logon_status={status?.ToString() ?? "?"})."
                    : errorMessage!),
        };
    }

    private static string? SelectText(XmlDocument doc, string nodeName)
    {
        // Firebox responses are flat: <resp><logon_status>1</logon_status>...</resp>. Use a
        // descendant search so we don't have to assume a particular root element name across
        // firmware versions.
        var node = doc.SelectSingleNode($"//{nodeName}");
        return node?.InnerText;
    }

    private static int? TryParseInt(string? s) => int.TryParse(s, out var n) ? n : null;

    public void Dispose()
    {
        if (_ownsHttpClient) _http.Dispose();
        DisposeCerts(_pinnedCaCerts);
    }
}

/// <summary>Outcome of a Firebox logon request. Discriminated via type test.</summary>
internal abstract record PreAuthOutcome
{
    public sealed record Ok : PreAuthOutcome;
    public sealed record Challenge(string LogonId, string ChallengeText) : PreAuthOutcome;
    public sealed record Failure(string Reason) : PreAuthOutcome;
}
