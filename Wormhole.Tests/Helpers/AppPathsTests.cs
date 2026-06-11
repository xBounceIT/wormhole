using Wormhole.Helpers;
using Xunit;

namespace Wormhole.Tests.Helpers;

public class AppPathsTests
{
    [Fact]
    public void WebView2UserDataRoot_Is_Lowercase_Sibling_Of_LocalAppData_Wormhole()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var expected = Path.Combine(localAppData, "Wormhole", "webview2");

        Assert.Equal(expected, AppPaths.GetWebView2UserDataRoot());
    }

    [Fact]
    public void WebView2UserDataDirectory_Is_The_ArgsKeyed_Subfolder_Of_The_Root()
    {
        // The actual environment folder is keyed by the browser arguments (see
        // WebViewBrowserArguments.KeyedSharedFolderName) so builds with different arguments use
        // disjoint folders instead of failing WebView2 environment creation on a mismatch.
        var expected = Path.Combine(AppPaths.GetWebView2UserDataRoot(), WebViewBrowserArguments.KeyedSharedFolderName);

        Assert.Equal(expected, AppPaths.GetWebView2UserDataDirectory());
    }
}
