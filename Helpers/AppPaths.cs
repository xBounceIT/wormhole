namespace Wormhole.Helpers;

internal static class AppPaths
{
    public static string GetAppDataDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Wormhole");
    }

    public static string GetDatabaseFilePath()
    {
        return Path.Combine(GetAppDataDirectory(), "wormhole.db");
    }

    public static string GetSettingsFilePath()
    {
        return Path.Combine(GetAppDataDirectory(), "settings.json");
    }

    public static string GetLogsDirectory()
    {
        return Path.Combine(GetAppDataDirectory(), "logs");
    }

    public static string GetKeysDirectory()
    {
        return Path.Combine(GetAppDataDirectory(), "keys");
    }

    public static string GetTunnelConfigsDirectory()
    {
        return Path.Combine(GetAppDataDirectory(), "tunnels");
    }

    public static string GetUpdateCacheDirectory()
    {
        return Path.Combine(GetAppDataDirectory(), "cache", "updates");
    }

    // WebView2's default user-data folder is `{exe_dir}\{exe_name}.WebView2\`,
    // which the app cannot create when installed under Program Files without
    // elevation. Pin it under %LOCALAPPDATA%\Wormhole\ to match sibling state.
    public static string GetWebView2UserDataDirectory()
    {
        return Path.Combine(GetAppDataDirectory(), "webview2");
    }

    public static string GetWebAssetsDirectory()
    {
        return Path.Combine(AppContext.BaseDirectory, "Assets", "web");
    }

    public static string GetWgProxyExecutablePath()
    {
        return Path.Combine(AppContext.BaseDirectory, "wormhole-wgproxy.exe");
    }

    public static string GetFortiProxyExecutablePath()
    {
        return Path.Combine(AppContext.BaseDirectory, "wormhole-fortiproxy.exe");
    }

    public static string GetOvpnProxyExecutablePath()
    {
        return Path.Combine(AppContext.BaseDirectory, "wormhole-ovpnproxy.exe");
    }
}
