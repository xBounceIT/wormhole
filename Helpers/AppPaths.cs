using System;
using System.IO;

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
}
