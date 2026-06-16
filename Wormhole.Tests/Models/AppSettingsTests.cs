using System.Text.Json;
using Wormhole.Models;
using Xunit;

namespace Wormhole.Tests.Models;

public class AppSettingsTests
{
    [Fact]
    public void Deserialize_Missing_LogRetentionDays_Uses_Default()
    {
        var settings = JsonSerializer.Deserialize<AppSettings>("{}");

        Assert.NotNull(settings);
        Assert.Equal(14, settings!.LogRetentionDays);
    }
}
