namespace Wormhole.Helpers;

internal static class AppPaths
{
    private static readonly string AppDataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Wormhole");

    private static readonly string DatabaseFilePath = Path.Combine(AppDataDirectory, "wormhole.db");
    private static readonly string SettingsFilePath = Path.Combine(AppDataDirectory, "settings.json");
    private static readonly string AppAuthenticationFilePath = Path.Combine(AppDataDirectory, "app-auth.dpapi");
    private static readonly string LogsDirectory = Path.Combine(AppDataDirectory, "logs");
    private static readonly string CrashDumpsDirectory = Path.Combine(AppDataDirectory, "crashdumps");
    private static readonly string KeysDirectory = Path.Combine(AppDataDirectory, "keys");
    private static readonly string TunnelConfigsDirectory = Path.Combine(AppDataDirectory, "tunnels");
    private static readonly string StormshieldCacheDirectory = Path.Combine(AppDataDirectory, "stormshield-cache");
    private static readonly string WatchguardCacheDirectory = Path.Combine(AppDataDirectory, "watchguard-cache");
    private static readonly string AzureVpnCacheDirectory = Path.Combine(AppDataDirectory, "azurevpn-cache");
    private static readonly string UpdateCacheDirectory = Path.Combine(AppDataDirectory, "cache", "updates");
    // Every fixed-path WebView2 surface places its actual environment in an argument-fingerprinted
    // subfolder of its root (see WebViewBrowserArguments.KeyedSharedFolderName): WebView2 fails
    // environment creation with ERROR_INVALID_STATE when a browser process is already running on the
    // same user-data folder with different arguments, and nothing stops an older installed build from
    // running next to this one. Keying the folder by the arguments makes such builds use disjoint
    // folders. Side effect when the argument set changes between builds: surfaces with persistent
    // state (e.g. the Azure VPN popup's Entra session cookies) start from a fresh profile once.
    private static readonly string WebView2UserDataDirectory = Path.Combine(AppDataDirectory, "webview2");
    private static readonly string WatchguardSamlWebView2UserDataDirectory = Path.Combine(AppDataDirectory, "watchguard-saml-webview2");
    private static readonly string AzureVpnWebView2UserDataDirectory = Path.Combine(AppDataDirectory, "azurevpn-webview2");
    private static readonly string UpdateChangelogWebView2UserDataDirectory = Path.Combine(AppDataDirectory, "update-changelog-webview2");
    // Separate user-data root for the HTTP/HTTPS browser session surface, so its (possibly
    // proxy-configured) WebView2 environments never collide with the SSH terminal's shared env.
    // Isolated tabs get a unique sub-folder; this root is wiped at startup (App.ClearWebBrowserUserData).
    private static readonly string WebBrowserUserDataDirectory = Path.Combine(AppDataDirectory, "webview2-web");
    private static readonly string BitwardenCliDirectory = Path.Combine(AppDataDirectory, "tools", "bitwarden-cli");
    private static readonly string BitwardenCliDownloadDirectory = Path.Combine(AppDataDirectory, "cache", "bitwarden-cli");
    private static readonly string BitwardenBrowserExtensionDirectory = Path.Combine(AppDataDirectory, "extensions", "bitwarden");
    private static readonly string BitwardenBrowserExtensionDownloadDirectory = Path.Combine(AppDataDirectory, "cache", "bitwarden-browser-extension");
    private static readonly string BitwardenBrowserExtensionWebView2UserDataDirectory = Path.Combine(AppDataDirectory, "bitwarden-browser-webview2");
    private static readonly string WebAssetsDirectory = Path.Combine(AppContext.BaseDirectory, "Assets", "web");
    private static readonly string WgProxyExecutablePath = Path.Combine(AppContext.BaseDirectory, "wormhole-wgproxy.exe");
    private static readonly string FortiProxyExecutablePath = Path.Combine(AppContext.BaseDirectory, "wormhole-fortiproxy.exe");
    private static readonly string OvpnProxyExecutablePath = Path.Combine(AppContext.BaseDirectory, "wormhole-ovpnproxy.exe");
    private static readonly string CiscoProxyExecutablePath = Path.Combine(AppContext.BaseDirectory, "wormhole-ciscoproxy.exe");

    public static string GetAppDataDirectory() => AppDataDirectory;

    public static string GetDatabaseFilePath() => DatabaseFilePath;

    public static string GetSettingsFilePath() => SettingsFilePath;

    public static string GetAppAuthenticationFilePath() => AppAuthenticationFilePath;

    public static string GetLogsDirectory() => LogsDirectory;

    public static string GetCrashDumpsDirectory() => CrashDumpsDirectory;

    public static string GetKeysDirectory() => KeysDirectory;

    public static string GetTunnelConfigsDirectory() => TunnelConfigsDirectory;

    // Per-tunnel DPAPI-encrypted cache of downloaded Stormshield Automatic-mode OpenVPN profiles, so a
    // reconnect can reuse the profile instead of re-downloading it (which would spend the single-use
    // OTP on the HTTPS step rather than the OpenVPN data-plane password). See StormshieldConfigCache.
    public static string GetStormshieldCacheDirectory() => StormshieldCacheDirectory;

    // Per-tunnel DPAPI-encrypted cache of downloaded WatchGuard OpenVPN profiles, so a reconnect can
    // skip the web sslvpn_logon (which spends the single 2FA factor on the portal and leaves the
    // OpenVPN CRV1 layer demanding a second) and route the one factor to the OpenVPN data channel.
    // See WatchguardProfileCache.
    public static string GetWatchguardCacheDirectory() => WatchguardCacheDirectory;

    // Per-tunnel DPAPI-encrypted cache of Microsoft Entra ID refresh tokens for Azure VPN tunnels,
    // so a reconnect can mint a fresh access token silently instead of re-opening the Microsoft
    // sign-in popup. See AzureVpnTokenCache.
    public static string GetAzureVpnCacheDirectory() => AzureVpnCacheDirectory;

    public static string GetUpdateCacheDirectory() => UpdateCacheDirectory;

    // WebView2's default user-data folder is `{exe_dir}\{exe_name}.WebView2\`,
    // which the app cannot create when installed under Program Files without
    // elevation. Pin it under %LOCALAPPDATA%\Wormhole\ to match sibling state.
    // Root accessors exist so callers can sweep stale keyed siblings
    // (WebViewBrowserArguments.SweepStaleKeyedFolders) before creating the environment.
    public static string GetWebView2UserDataRoot() => WebView2UserDataDirectory;

    public static string GetWebView2UserDataDirectory() =>
        Path.Combine(WebView2UserDataDirectory, WebViewBrowserArguments.KeyedSharedFolderName);

    public static string GetWatchguardSamlWebView2UserDataRoot() => WatchguardSamlWebView2UserDataDirectory;

    public static string GetWatchguardSamlWebView2UserDataDirectory() =>
        Path.Combine(WatchguardSamlWebView2UserDataDirectory, WebViewBrowserArguments.KeyedSharedFolderName);

    // Persistent profile for the Azure VPN Microsoft sign-in popup, so Entra session cookies
    // survive across connects and an interactive re-auth is usually a single account click.
    public static string GetAzureVpnWebView2UserDataRoot() => AzureVpnWebView2UserDataDirectory;

    public static string GetAzureVpnWebView2UserDataDirectory() =>
        Path.Combine(AzureVpnWebView2UserDataDirectory, WebViewBrowserArguments.KeyedSharedFolderName);

    public static string GetUpdateChangelogWebView2UserDataRoot() => UpdateChangelogWebView2UserDataDirectory;

    public static string GetUpdateChangelogWebView2UserDataDirectory() =>
        Path.Combine(UpdateChangelogWebView2UserDataDirectory, WebViewBrowserArguments.KeyedSharedFolderName);

    // Root for ALL web-tab environments — wiped at startup by App.ClearWebBrowserUserData, and the
    // parent of both the keyed shared folder and the per-tab isolated env-<id> folders.
    public static string GetWebBrowserUserDataDirectory() => WebBrowserUserDataDirectory;

    // Shared environment folder for plain web tabs — those that neither proxy through SOCKS nor ignore
    // certificate errors, so they can safely share one browser process / cert-decision cache. No sweep
    // needed here: the startup wipe of the root already removes stale keyed folders.
    public static string GetWebBrowserSharedUserDataDirectory() =>
        Path.Combine(WebBrowserUserDataDirectory, WebViewBrowserArguments.KeyedSharedFolderName);

    // Unique per-tab folder for a web tab that needs an ISOLATED environment: a SOCKS5 proxy (Chromium
    // proxy args are fixed at env creation) or ignore-cert (WebView2 caches AlwaysAllow per environment,
    // which must not leak to a sibling tab that didn't opt in). Each such session gets its own dir.
    public static string GetWebBrowserIsolatedUserDataDirectory(string id) =>
        Path.Combine(WebBrowserUserDataDirectory, "env-" + id);

    public static string GetBitwardenCliRootDirectory() => BitwardenCliDirectory;

    public static string GetBitwardenCliDownloadDirectory() => BitwardenCliDownloadDirectory;

    public static string GetBitwardenBrowserExtensionRootDirectory() => BitwardenBrowserExtensionDirectory;

    public static string GetBitwardenBrowserExtensionDownloadDirectory() => BitwardenBrowserExtensionDownloadDirectory;

    public static string GetBitwardenBrowserExtensionInstallDirectory(string version) =>
        Path.Combine(BitwardenBrowserExtensionDirectory, version);

    public static string GetBitwardenBrowserExtensionWebView2UserDataRoot() => BitwardenBrowserExtensionWebView2UserDataDirectory;

    public static string GetBitwardenBrowserExtensionWebView2UserDataDirectory(string contextFolderName) =>
        Path.Combine(BitwardenBrowserExtensionWebView2UserDataDirectory, contextFolderName);

    public static string GetWebAssetsDirectory() => WebAssetsDirectory;

    public static string GetWgProxyExecutablePath() => WgProxyExecutablePath;

    public static string GetFortiProxyExecutablePath() => FortiProxyExecutablePath;

    public static string GetOvpnProxyExecutablePath() => OvpnProxyExecutablePath;

    public static string GetCiscoProxyExecutablePath() => CiscoProxyExecutablePath;
}
