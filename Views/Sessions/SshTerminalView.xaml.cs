using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Sessions;

public sealed partial class SshTerminalView : UserControl
{
    // How long to wait for the JS "ready" handshake after navigation completes before
    // surfacing a failure. Missing/corrupt xterm assets, JS errors in bridge.js, or
    // a stuck WebView all show up as "no handshake."
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);

    private SshSessionViewModel? _viewModel;
    private bool _handshakeReceived;
    private bool _terminalInitializationFailed;
    private int _handshakeGeneration;
    private int _initInProgress;
    private TerminalSize _lastSize = TerminalSize.Default;

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
            _handshakeReceived = false;
            _terminalInitializationFailed = false;
            _lastSize = TerminalSize.Default;
            _handshakeGeneration++;
        }
        // Always (re)subscribe — OnUnloaded unsubscribes on every unload, so a same-VM
        // reload would otherwise leave the event with no listener and RetryAsync (the
        // _webView == null branch) would be a no-op.
        _viewModel.InitializationRetryRequested -= OnInitializationRetryRequested;
        _viewModel.InitializationRetryRequested += OnInitializationRetryRequested;

        // Same instance is being reloaded (e.g. NavigationView swap, tab content
        // recycle): the WebView2 and its in-page xterm.js are still alive but
        // OnUnloaded disposed the bridge. Rebind without re-navigating, otherwise
        // the terminal would appear dead — _handshakeReceived gates re-init so
        // a normal flow would short-circuit here and never call AttachAsync.
        if (_handshakeReceived)
        {
            if (TerminalView.CoreWebView2 is not null)
            {
                try { await _viewModel.AttachAsync(TerminalView.CoreWebView2, _lastSize).ConfigureAwait(true); }
                catch (Exception ex) { _viewModel.ReportFailure(ex.Message); }
                return;
            }

            _handshakeReceived = false;
        }
        await InitializeWebViewAsync().ConfigureAwait(true);
    }

    private async Task InitializeWebViewAsync()
    {
        // Re-entrancy guard: OnLoaded racing with InitializationRetryRequested could
        // otherwise double-fire Navigate.
        if (System.Threading.Interlocked.CompareExchange(ref _initInProgress, 1, 0) != 0) return;

        var vm = _viewModel;
        if (vm is null) { _initInProgress = 0; return; }
        try
        {
            await TerminalView.EnsureCoreWebView2Async();

            TerminalView.CoreWebView2.SetVirtualHostNameToFolderMapping(
                "terminal.wormhole",
                AppPaths.GetWebAssetsDirectory(),
                CoreWebView2HostResourceAccessKind.Allow);

            TerminalView.CoreWebView2.Settings.AreDevToolsEnabled = Debugger.IsAttached;
            TerminalView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = Debugger.IsAttached;

            // -= then += so a Retry doesn't accumulate handlers.
            _handshakeReceived = false;
            _terminalInitializationFailed = false;
            var handshakeGeneration = ++_handshakeGeneration;
            TerminalView.CoreWebView2.WebMessageReceived -= OnTerminalInitializationMessage;
            TerminalView.CoreWebView2.WebMessageReceived += OnTerminalInitializationMessage;
            TerminalView.CoreWebView2.Navigate("https://terminal.wormhole/terminal.html");

            _ = ScheduleHandshakeTimeoutAsync(vm, handshakeGeneration);
        }
        catch (Exception ex)
        {
            _terminalInitializationFailed = true;
            LogWebViewInitializationFailure(ex);
            // _handshakeReceived stays false so a Retry click re-runs init.
            vm.ReportFailure("Failed to initialize WebView2: " + ex.Message);
        }
        finally
        {
            _initInProgress = 0;
        }
    }

    private async Task ScheduleHandshakeTimeoutAsync(SshSessionViewModel vm, int handshakeGeneration)
    {
        await Task.Delay(HandshakeTimeout).ConfigureAwait(true);
        if (handshakeGeneration != _handshakeGeneration) return;
        if (_handshakeReceived) return;
        if (_terminalInitializationFailed) return;
        if (!ReferenceEquals(vm, _viewModel)) return;
        vm.ReportFailure("Terminal page did not finish loading (no 'ready' handshake). " +
                         "The xterm.js assets may be missing or corrupted.");
    }

    private async void OnInitializationRetryRequested()
    {
        if (_handshakeReceived) return;
        await InitializeWebViewAsync().ConfigureAwait(true);
    }

    private async void OnTerminalInitializationMessage(CoreWebView2 sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        var msg = args.TryGetWebMessageAsString();
        if (msg is null) return;

        if (msg.StartsWith("error:", StringComparison.Ordinal))
        {
            sender.WebMessageReceived -= OnTerminalInitializationMessage;
            _terminalInitializationFailed = true;

            var detail = msg.Substring("error:".Length);
            LogTerminalInitializationFailure(detail);
            var errorVm = _viewModel;
            errorVm?.ReportFailure("Terminal page failed to initialize: " + detail);
            return;
        }

        if (!msg.StartsWith("ready", StringComparison.Ordinal)) return;

        // Self-unsubscribe and mark handshake done so future navigations / retries don't
        // double-attach.
        sender.WebMessageReceived -= OnTerminalInitializationMessage;
        _handshakeReceived = true;

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
        _lastSize = size;
        LogTerminalReady(size);

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

    private static void LogTerminalReady(TerminalSize size)
    {
        var logger = App.Current.Services.GetService<ILogger<SshTerminalView>>();
        logger?.LogInformation("Terminal page ready with geometry {Columns}x{Rows}.", size.Columns, size.Rows);
    }

    private static void LogTerminalInitializationFailure(string detail)
    {
        var logger = App.Current.Services.GetService<ILogger<SshTerminalView>>();
        logger?.LogError("Terminal page reported initialization failure: {Detail}", detail);
    }

    private static void LogWebViewInitializationFailure(Exception ex)
    {
        var logger = App.Current.Services.GetService<ILogger<SshTerminalView>>();
        if (logger is null) return;

        var baseDirectory = AppContext.BaseDirectory;
        var loaderPath = Path.Combine(baseDirectory, "WebView2Loader.dll");
        logger.LogError(
            ex,
            "Failed to initialize WebView2. BaseDirectory={BaseDirectory}; ExceptionType={ExceptionType}; HResult=0x{HResult:X8}; WebView2LoaderPath={WebView2LoaderPath}; WebView2LoaderExists={WebView2LoaderExists}",
            baseDirectory,
            ex.GetType().FullName,
            ex.HResult,
            loaderPath,
            File.Exists(loaderPath));
    }

    // The VM outlives the view (it lives in ShellViewModel.Tabs across navigations),
    // so we must unsubscribe here or every navigation accumulates a stale handler
    // that keeps the old SshTerminalView alive and double-runs init on retry.
    // Also tell the VM to drop the bridge — otherwise background SSH output keeps
    // posting to a disposed WebView2 until reconnect or tab close.
    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _handshakeGeneration++;
        if (_viewModel is not null)
        {
            _viewModel.InitializationRetryRequested -= OnInitializationRetryRequested;
            _viewModel.DetachView();
        }
        if (TerminalView.CoreWebView2 is not null)
        {
            TerminalView.CoreWebView2.WebMessageReceived -= OnTerminalInitializationMessage;
        }
    }
}
