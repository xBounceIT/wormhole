using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Sessions;

public sealed partial class SshTerminalView : UserControl
{
    private SshSessionViewModel? _viewModel;
    private bool _webViewReady;

    public SshTerminalView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        var newVm = DataContext as SshSessionViewModel;
        if (newVm is null) return;

        if (!ReferenceEquals(newVm, _viewModel))
        {
            if (_viewModel is not null) _viewModel.InitializationRetryRequested -= OnInitializationRetryRequested;
            _viewModel = newVm;
            _viewModel.InitializationRetryRequested += OnInitializationRetryRequested;
        }

        if (_webViewReady) return;
        await InitializeWebViewAsync().ConfigureAwait(true);
    }

    // The VM outlives the view (it lives in ShellViewModel.Tabs across navigations),
    // so we must unsubscribe here or every navigation accumulates a stale handler
    // that keeps the old SshTerminalView alive and double-runs init on retry.
    // Also unhook the one-shot WebView2 ready handler — if the user closes the tab
    // before "ready" arrives, an in-flight WebMessageReceived would otherwise fire
    // on a torn-down view and call AttachAsync against a disposed control.
    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_viewModel is not null)
        {
            _viewModel.InitializationRetryRequested -= OnInitializationRetryRequested;
        }
        if (TerminalView.CoreWebView2 is not null)
        {
            TerminalView.CoreWebView2.WebMessageReceived -= OnReadyMessage;
        }
    }

    private async Task InitializeWebViewAsync()
    {
        var vm = _viewModel;
        if (vm is null) return;
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
            _webViewReady = true;
        }
        catch (Exception ex)
        {
            // Leave _webViewReady false so a Retry click can re-attempt init.
            vm.ReportFailure("Failed to initialize WebView2: " + ex.Message);
        }
    }

    private async void OnInitializationRetryRequested()
    {
        if (_webViewReady) return;
        await InitializeWebViewAsync().ConfigureAwait(true);
    }

    private async void OnReadyMessage(CoreWebView2 sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        var msg = args.TryGetWebMessageAsString();
        if (msg is null || !msg.StartsWith("ready", StringComparison.Ordinal)) return;

        // Self-unsubscribe so a second navigation doesn't double-attach.
        TerminalView.CoreWebView2.WebMessageReceived -= OnReadyMessage;

        // The handshake carries the initial xterm.js geometry as "ready:COLSxROWS" so the
        // SSH shell can be allocated at the correct size. If parsing fails, fall back to
        // the protocol default — better than 80x24 stuck forever.
        var size = TerminalSize.Default;
        if (msg.Length > 6 && msg[5] == ':')
        {
            var parts = msg.Substring(6).Split('x');
            if (parts.Length == 2 &&
                uint.TryParse(parts[0], out var cols) &&
                uint.TryParse(parts[1], out var rows) &&
                cols > 0 && rows > 0)
            {
                size = new TerminalSize(cols, rows);
            }
        }

        var vm = _viewModel;
        if (vm is null) return;
        try
        {
            await vm.AttachAsync(TerminalView.CoreWebView2, size);
        }
        catch (Exception ex)
        {
            vm.ReportFailure(ex.Message);
        }
    }
}
