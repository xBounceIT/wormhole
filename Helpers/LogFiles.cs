using System.Globalization;

namespace Wormhole.Helpers;

internal static class LogFiles
{
    public const int DefaultRetentionDays = 14;
    public const int MinimumRetentionDays = 1;
    public const int MaximumRetentionDays = 365;

    public static string GetDailySinkPath() =>
        Path.Combine(AppPaths.GetLogsDirectory(), "wormhole-.log");

    public static string GetCurrentDayLogFilePath() =>
        GetLogFilePath(DateTime.Today);

    public static string GetLogFilePath(DateTime localDate) =>
        Path.Combine(
            AppPaths.GetLogsDirectory(),
            "wormhole-" + localDate.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".log");

    public static int NormalizeRetentionDays(int days) =>
        days is >= MinimumRetentionDays and <= MaximumRetentionDays
            ? days
            : DefaultRetentionDays;
}
