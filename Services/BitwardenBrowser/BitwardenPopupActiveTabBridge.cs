using System.Text.Json;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Services.BitwardenBrowser;

/// <summary>
/// Makes a separately-hosted extension popup observe the HTTPS WebView that opened it as the active
/// browser tab. WebView2 otherwise treats the popup control itself as the active tab, so extensions
/// receive their own chrome-extension URL from chrome.tabs.query.
/// </summary>
internal static class BitwardenPopupActiveTabBridge
{
    private const string PageMarkerAttribute = "data-wormhole-bitwarden-active-tab";

    internal static BitwardenActiveTabContext? CreateContext(
        HttpConnectionTarget target,
        string? currentSource)
    {
        ArgumentNullException.ThrowIfNull(target);

        var physicalUri = TryGetWebUri(currentSource)
            ?? (IsWebUri(target.NavigateUri) ? target.NavigateUri : null);
        if (physicalUri is null) return null;

        var logicalUri = physicalUri;
        if (target.OriginalUri is { } originalUri
            && IsWebUri(originalUri)
            && IsSameOrigin(physicalUri, target.NavigateUri))
        {
            logicalUri = ReplaceAuthority(physicalUri, originalUri);
        }

        return new BitwardenActiveTabContext(physicalUri.AbsoluteUri, logicalUri.AbsoluteUri);
    }

    internal static string BuildPageMarkerScript(string marker)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(marker);
        var attributePayload = JsonSerializer.Serialize(PageMarkerAttribute);
        var markerPayload = JsonSerializer.Serialize(marker);

        return $$"""
            document.documentElement?.setAttribute({{attributePayload}}, {{markerPayload}});
            """;
    }

    internal static string BuildScript(BitwardenActiveTabContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var payload = JsonSerializer.Serialize(context);
        var pageMarkerAttributePayload = JsonSerializer.Serialize(PageMarkerAttribute);

        // Bitwarden asks for { active: true, currentWindow: true } when it pre-fills a new login.
        // The popup lives in a second WebView2, so query all profile tabs to recover the real page,
        // keep its genuine tab id, and expose only the logical URL to the extension. Every other tabs
        // query remains native. The callback path is the one used by Bitwarden today; the Promise path
        // keeps the bridge compatible with WebExtension callers that use the MV3 overload.
        return $$"""
            (() => {
                const context = {{payload}};
                if (location.protocol !== "chrome-extension:" || !globalThis.chrome?.tabs?.query) {
                    return;
                }

                const tabsApi = chrome.tabs;
                const nativeQuery = tabsApi.query.bind(tabsApi);
                const normalizeUrl = (value) => {
                    try { return new URL(value).href; }
                    catch { return value; }
                };
                const physicalUrl = normalizeUrl(context.PhysicalUrl);
                const findSourceTab = async (allTabs) => {
                    const candidates = Array.isArray(allTabs)
                        ? allTabs.filter(
                            (tab) => tab?.url && normalizeUrl(tab.url) === physicalUrl)
                        : [];
                    if (candidates.length <= 1) {
                        return candidates[0] ?? null;
                    }

                    if (context.PageMarker && globalThis.chrome?.scripting?.executeScript) {
                        for (const tab of candidates) {
                            if (!Number.isInteger(tab.id)) {
                                continue;
                            }

                            try {
                                const results = await chrome.scripting.executeScript({
                                    target: { tabId: tab.id },
                                    func: (attribute, marker) => {
                                        const root = document.documentElement;
                                        if (root?.getAttribute(attribute) !== marker) {
                                            return false;
                                        }

                                        root.removeAttribute(attribute);
                                        return true;
                                    },
                                    args: [{{pageMarkerAttributePayload}}, context.PageMarker],
                                });
                                if (results.some((result) => result?.result === true)) {
                                    return tab;
                                }
                            } catch {
                                // Fall back to the browser's recency signal below.
                            }
                        }
                    }

                    return candidates.reduce((latest, tab) =>
                        !latest || (tab.lastAccessed ?? 0) > (latest.lastAccessed ?? 0)
                            ? tab
                            : latest,
                    null);
                };
                const projectActiveTab = async (allTabs) => {
                    const sourceTab = await findSourceTab(allTabs);
                    return sourceTab
                        ? [{ ...sourceTab, active: true, url: context.LogicalUrl }]
                        : null;
                };
                const isActiveCurrentWindowQuery = (queryInfo) =>
                    queryInfo?.active === true && queryInfo?.currentWindow === true;

                const bridgedQuery = (queryInfo, callback) => {
                    if (!isActiveCurrentWindowQuery(queryInfo)) {
                        return typeof callback === "function"
                            ? nativeQuery(queryInfo, callback)
                            : nativeQuery(queryInfo);
                    }

                    if (typeof callback === "function") {
                        return nativeQuery({}, async (allTabs) => {
                            const projected = await projectActiveTab(allTabs);
                            if (projected) {
                                callback(projected);
                            } else {
                                nativeQuery(queryInfo, callback);
                            }
                        });
                    }

                    return nativeQuery({}).then(async (allTabs) =>
                        await projectActiveTab(allTabs) ?? nativeQuery(queryInfo));
                };

                try {
                    Object.defineProperty(tabsApi, "query", {
                        configurable: true,
                        writable: true,
                        value: bridgedQuery,
                    });
                } catch {
                    tabsApi.query = bridgedQuery;
                }
            })();
            """;
    }

    private static Uri? TryGetWebUri(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && IsWebUri(uri) ? uri : null;

    private static bool IsWebUri(Uri uri) =>
        uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
        || uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static bool IsSameOrigin(Uri left, Uri right) =>
        left.Scheme.Equals(right.Scheme, StringComparison.OrdinalIgnoreCase)
        && left.IdnHost.Equals(right.IdnHost, StringComparison.OrdinalIgnoreCase)
        && left.Port == right.Port;

    private static Uri ReplaceAuthority(Uri source, Uri authority)
    {
        var builder = new UriBuilder(source)
        {
            Scheme = authority.Scheme,
            Host = authority.Host,
            Port = authority.Port,
        };
        return builder.Uri;
    }
}

internal sealed record BitwardenActiveTabContext(
    string PhysicalUrl,
    string LogicalUrl,
    string? PageMarker = null);
