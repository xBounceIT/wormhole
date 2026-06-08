namespace Wormhole.Helpers;

internal static class AppPaths
{
    private static readonly string AppDataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Wormhole");

    private static readonly string DatabaseFilePath = Path.Combine(AppDataDirectory, "wormhole.db");
    private static readonly string SettingsFilePath = Path.Combine(AppDataDirectory, "settings.json");
    private static readonly string LogsDirectory = Path.Combine(AppDataDirectory, "logs");
    private static readonly string KeysDirectory = Path.Combine(AppDataDirectory, "keys");
    private static readonly string TunnelConfigsDirectory = Path.Combine(AppDataDirectory, "tunnels");
    private static readonly string StormshieldCacheDirectory = Path.Combine(AppDataDirectory, "stormshield-cache");
    private static readonly string WatchguardCacheDirectory = Path.Combine(AppDataDirectory, "watchguard-cache");
    private static readonly string UpdateCacheDirectory = Path.Combine(AppDataDirectory, "cache", "updates");
    private static readonly string WebView2UserDataDirectory = Path.Combine(AppDataDirectory, "webview2");
    private static readonly string WatchguardSamlWebView2UserDataDirectory = Path.Combine(AppDataDirectory, "watchguard-saml-webview2");
    // Separate user-data root for the HTTP/HTTPS browser session surface, so its (possibly
    // proxy-configured) WebView2 environments never collide with the SSH terminal's shared env, which
    // must keep default options to share one browser process. Proxied tabs get a unique sub-folder.
    private static readonly string WebBrowserUserDataDirectory = Path.Combine(AppDataDirectory, "webview2-web");
    private static readonly string WebAssetsDirectory = Path.Combine(AppContext.BaseDirectory, "Assets", "web");
    private static readonly string WgProxyExecutablePath = Path.Combine(AppContext.BaseDirectory, "wormhole-wgproxy.exe");
    private static readonly string FortiProxyExecutablePath = Path.Combine(AppContext.BaseDirectory, "wormhole-fortiproxy.exe");
    private static readonly string OvpnProxyExecutablePath = Path.Combine(AppContext.BaseDirectory, "wormhole-ovpnproxy.exe");

    public static string GetAppDataDirectory() => AppDataDirectory;

    public static string GetDatabaseFilePath() => DatabaseFilePath;

    public static string GetSettingsFilePath() => SettingsFilePath;

    public static string GetLogsDirectory() => LogsDirectory;

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

    public static string GetUpdateCacheDirectory() => UpdateCacheDirectory;

    // WebView2's default user-data folder is `{exe_dir}\{exe_name}.WebView2\`,
    // which the app cannot create when installed under Program Files without
    // elevation. Pin it under %LOCALAPPDATA%\Wormhole\ to match sibling state.
    public static string GetWebView2UserDataDirectory() => WebView2UserDataDirectory;

    public static string GetWatchguardSamlWebView2UserDataDirectory() => WatchguardSamlWebView2UserDataDirectory;

    // Shared environment folder for plain web tabs — those that neither proxy through SOCKS nor ignore
    // certificate errors, so they can safely share one browser process / cert-decision cache.
    public static string GetWebBrowserUserDataDirectory() => WebBrowserUserDataDirectory;

    // Unique per-tab folder for a web tab that needs an ISOLATED environment: a SOCKS5 proxy (Chromium
    // proxy args are fixed at env creation) or ignore-cert (WebView2 caches AlwaysAllow per environment,
    // which must not leak to a sibling tab that didn't opt in). Each such session gets its own dir.
    public static string GetWebBrowserIsolatedUserDataDirectory(string id) =>
        Path.Combine(WebBrowserUserDataDirectory, "env-" + id);

    public static string GetWebAssetsDirectory() => WebAssetsDirectory;

    public static string GetWgProxyExecutablePath() => WgProxyExecutablePath;

    public static string GetFortiProxyExecutablePath() => FortiProxyExecutablePath;

    public static string GetOvpnProxyExecutablePath() => OvpnProxyExecutablePath;
}
