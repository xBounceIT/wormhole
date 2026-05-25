using Wormhole.Helpers;
using Xunit;

namespace Wormhole.Tests.Helpers;

public class AppPathsTests
{
    [Fact]
    public void WebView2UserDataDirectory_Is_Lowercase_Sibling_Of_LocalAppData_Wormhole()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var expected = Path.Combine(localAppData, "Wormhole", "webview2");

        Assert.Equal(expected, AppPaths.GetWebView2UserDataDirectory());
    }
}
