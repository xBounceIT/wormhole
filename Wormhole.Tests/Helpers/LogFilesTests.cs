using Wormhole.Helpers;
using Xunit;

namespace Wormhole.Tests.Helpers;

public class LogFilesTests
{
    [Fact]
    public void CurrentDayLogFilePath_Resolves_Under_Logs_Directory()
    {
        var path = LogFiles.GetCurrentDayLogFilePath();

        Assert.Equal(AppPaths.GetLogsDirectory(), Path.GetDirectoryName(path));
    }

    [Fact]
    public void LogFilePath_Uses_Daily_Serilog_File_Name()
    {
        var path = LogFiles.GetLogFilePath(new DateTime(2026, 6, 16));

        Assert.Equal("wormhole-20260616.log", Path.GetFileName(path));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(14, 14)]
    [InlineData(365, 365)]
    [InlineData(0, 14)]
    [InlineData(366, 14)]
    [InlineData(-1, 14)]
    public void NormalizeRetentionDays_Accepts_Range_And_Defaults_Invalid_Values(int input, int expected)
    {
        Assert.Equal(expected, LogFiles.NormalizeRetentionDays(input));
    }
}
