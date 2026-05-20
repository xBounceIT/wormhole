using System;
using System.Diagnostics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Sessions;

public sealed partial class SshTerminalView : UserControl
{
    private SshSessionViewModel? _viewModel;
    private bool _initialized;

    public SshTerminalView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_initialized) return;
        _initialized = true;

        _viewModel = DataContext as SshSessionViewModel;
        if (_viewModel is null) return;

        try
        {
            await TerminalView.EnsureCoreWebView2Async();

            TerminalView.CoreWebView2.SetVirtualHostNameToFolderMapping(
                "terminal.wormhole",
                AppPaths.GetWebAssetsDirectory(),
                CoreWebView2HostResourceAccessKind.Allow);

            TerminalView.CoreWebView2.Settings.AreDevToolsEnabled = Debugger.IsAttached;
            TerminalView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = Debugger.IsAttached;

            TerminalView.CoreWebView2.WebMessageReceived += OnReadyMessage;
            TerminalView.CoreWebView2.Navigate("https://terminal.wormhole/terminal.html");
        }
        catch (Exception ex)
        {
            _viewModel.ReportFailure("Failed to initialize WebView2: " + ex.Message);
        }
    }

    private async void OnReadyMessage(CoreWebView2 sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        var msg = args.TryGetWebMessageAsString();
        if (msg != "ready") return;

        TerminalView.CoreWebView2.WebMessageReceived -= OnReadyMessage;

        var vm = _viewModel;
        if (vm is null) return;
        try
        {
            await vm.AttachAsync(TerminalView.CoreWebView2, XamlRoot);
        }
        catch (Exception ex)
        {
            vm.ReportFailure(ex.Message);
        }
    }

    // Unloaded fires on every tab content swap, not just close. Tear-down belongs to the
    // explicit close (SessionsPage.TabCloseRequested calls DetachAsync) and Disconnect
    // commands; here we only unhook the WebView2 event so the handler can't fire after
    // the control leaves the visual tree.
    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (TerminalView.CoreWebView2 is not null)
        {
            TerminalView.CoreWebView2.WebMessageReceived -= OnReadyMessage;
        }
    }
}
