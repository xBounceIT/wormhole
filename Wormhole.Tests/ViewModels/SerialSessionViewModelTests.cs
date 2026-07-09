using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class SerialSessionViewModelTests
{
    [Fact]
    public void DetachView_PreservedTerminal_KeepsSameWebViewNotFresh()
    {
        var vm = CreateViewModel();
        var webView = new object();
        vm.RegisterAttachedWebView(webView);

        vm.DetachView();

        Assert.False(vm.RegisterAttachedWebView(webView));
    }

    [Fact]
    public void DetachView_ReplacedTerminal_MakesSameWebViewFresh()
    {
        var vm = CreateViewModel();
        var webView = new object();
        vm.RegisterAttachedWebView(webView);

        vm.DetachView(preserveTerminalContents: false);

        Assert.True(vm.RegisterAttachedWebView(webView));
    }

    private static SerialSessionViewModel CreateViewModel() =>
        new(null!, null!, null!, NullLoggerFactory.Instance);
}
