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

    // EnsureCoreWebView2Async throws if the WebView2 control is re-bound to a different
    // CoreWebView2Environment instance — so Retry (and multi-tab opens) must reuse the
    // same one. Cache it process-wide on first successful creation; concurrent first
    // callers race via CompareExchange and the loser drops its instance.
    private static CoreWebView2Environment? s_sharedEnvironment;

    private ITerminalSessionViewModel? _viewModel;
    private bool _handshakeReceived;
    private bool _terminalInitializationFailed;
    private int _handshakeGeneration;
    private int _viewBindingGeneration;
    private int _activeHandshakeBindingGeneration = -1;
    private int _initInProgress;
    private TerminalSize _lastSize = TerminalSize.Default;

    public SshTerminalView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        DataContextChanged += OnDataContextChanged;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await AttachCurrentViewModelAsync().ConfigureAwait(true);
    }

    private async void OnDataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)
    {
        // TabView may recycle the selected content container by changing DataContext without an
        // Unloaded/Loaded pair. That is the close-by-middle-click race: without this callback the
        // visible terminal keeps its bridge pointed at the VM that has just been closed.
        if (!IsLoaded) return;
        await AttachCurrentViewModelAsync().ConfigureAwait(true);
    }

    private async Task AttachCurrentViewModelAsync()
    {
        var newVm = DataContext as ITerminalSessionViewModel;
        var bindingChanged = !ReferenceEquals(newVm, _viewModel);

        // A recycled container still holds the previous session's xterm page. Keep that surface
        // hidden until the new binding's ready handshake; status overlays remain visible above it.
        // A same-VM reload can safely restore the existing page immediately.
        TerminalView.Visibility = !bindingChanged && newVm is not null
            ? Visibility.Visible
            : Visibility.Collapsed;

        if (bindingChanged)
        {
            if (_viewModel is not null)
            {
                _viewModel.InitializationRetryRequested -= OnInitializationRetryRequested;
                // DataContext recycling can happen while the control remains loaded, so OnUnloaded
                // has not detached the previous bridge. Do it here before the WebView is cleared and
                // rebound to the new session.
                _viewModel.DetachView(preserveTerminalContents: false);
            }
            if (TerminalView.CoreWebView2 is not null)
            {
                TerminalView.CoreWebView2.WebMessageReceived -= OnTerminalInitializationMessage;
            }
            _viewModel = newVm;
            _handshakeReceived = false;
            _terminalInitializationFailed = false;
            _lastSize = TerminalSize.Default;
            _handshakeGeneration++;
            _viewBindingGeneration++;
        }
        if (newVm is null) return;

        // Always (re)subscribe — OnUnloaded unsubscribes on every unload, so a same-VM
        // reload would otherwise leave the event with no listener and RetryAsync (the
        // _webView == null branch) would be a no-op.
        newVm.InitializationRetryRequested -= OnInitializationRetryRequested;
        newVm.InitializationRetryRequested += OnInitializationRetryRequested;

        // Same instance is being reloaded (e.g. NavigationView swap, tab content
        // recycle): the WebView2 and its in-page xterm.js are still alive but
        // OnUnloaded disposed the bridge. Rebind without re-navigating, otherwise
        // the terminal would appear dead — _handshakeReceived gates re-init so
        // a normal flow would short-circuit here and never call AttachAsync.
        if (_handshakeReceived)
        {
            if (TerminalView.CoreWebView2 is not null)
            {
                try { await newVm.AttachAsync(TerminalView.CoreWebView2, _lastSize).ConfigureAwait(true); }
                catch (Exception ex) { newVm.ReportFailure(ex.Message); }
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
        var bindingGeneration = _viewBindingGeneration;

        // Make the (re)init window legible. A tab that was unloaded mid-init (the user opened
        // a second connection back-to-back before this tab's "ready" handshake fired) sits in
        // Disconnected until it is brought forward and this re-init drives the deferred first
        // connect. Flip to the Connecting spinner now that we're past the re-entrancy guard
        // and committed to navigating;
        // MarkConnecting no-ops unless the tab is an idle, never-connected Disconnected, so a live
        // session's rebind and a Failed tab's Retry overlay are untouched.
        vm.MarkConnecting();
        // Pin WebView2's user-data folder under %LOCALAPPDATA%. The default location
        // is `{exe_dir}\{exe_name}.WebView2\`, which is unwritable when the app is
        // installed under Program Files — initialization then silently leaves
        // CoreWebView2 null and the next access throws NullReferenceException.
        var userDataFolder = AppPaths.GetWebView2UserDataDirectory();
        try
        {
            var environment = await GetOrCreateSharedEnvironmentAsync(userDataFolder);
            if (!IsCurrentBinding(vm, bindingGeneration)) return;
            await TerminalView.EnsureCoreWebView2Async(environment);
            if (!IsCurrentBinding(vm, bindingGeneration)) return;

            if (TerminalView.CoreWebView2 is null)
            {
                throw new InvalidOperationException(
                    "WebView2 initialization completed without a CoreWebView2 instance. " +
                    "UserDataFolder=" + userDataFolder);
            }

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
            _activeHandshakeBindingGeneration = bindingGeneration;
            TerminalView.CoreWebView2.WebMessageReceived -= OnTerminalInitializationMessage;
            TerminalView.CoreWebView2.WebMessageReceived += OnTerminalInitializationMessage;
            TerminalView.CoreWebView2.Navigate("https://terminal.wormhole/terminal.html");

            _ = ScheduleHandshakeTimeoutAsync(vm, handshakeGeneration);
        }
        catch (Exception ex)
        {
            // A recycled container queues initialization for its new VM. Do not report an old
            // WebView attempt against the session that no longer owns this view.
            if (!IsCurrentBinding(vm, bindingGeneration)) return;

            _terminalInitializationFailed = true;
            LogWebViewInitializationFailure(ex, userDataFolder);
            // _handshakeReceived stays false so a Retry click re-runs init.
            vm.ReportFailure("Failed to initialize WebView2: " + ex.Message);
        }
        finally
        {
            _initInProgress = 0;
            // A DataContext change may have arrived while the old initialization held the guard.
            // Its request intentionally returned above; replay it now for the current binding.
            if (bindingGeneration != _viewBindingGeneration && IsLoaded && _viewModel is not null)
            {
                await InitializeWebViewAsync().ConfigureAwait(true);
            }
        }
    }

    private bool IsCurrentBinding(ITerminalSessionViewModel vm, int bindingGeneration) =>
        bindingGeneration == _viewBindingGeneration && ReferenceEquals(vm, _viewModel) && IsLoaded;

    private static async Task<CoreWebView2Environment> GetOrCreateSharedEnvironmentAsync(string userDataFolder)
    {
        var existing = Volatile.Read(ref s_sharedEnvironment);
        if (existing is not null) return existing;

        // The terminal renders only local xterm.js assets via a virtual host, so none of Chromium's
        // background services are needed — harden the environment like the web tabs do. The folder is
        // argument-keyed (see WebViewBrowserArguments.KeyedSharedFolderName), so a build with different
        // arguments running concurrently uses a disjoint folder instead of failing creation; sweep
        // siblings left by older argument sets since this root has no startup wipe.
        WebViewBrowserArguments.SweepStaleKeyedFolders(AppPaths.GetWebView2UserDataRoot());
        Directory.CreateDirectory(userDataFolder);
        // null browserExecutableFolder = use the installed Evergreen Runtime (the documented
        // sentinel). string.Empty works in this SDK but is not the contract.
        var created = await CoreWebView2Environment.CreateWithOptionsAsync(
            null,
            userDataFolder,
            new CoreWebView2EnvironmentOptions
            {
                AdditionalBrowserArguments = WebViewBrowserArguments.Build(socks5Proxy: null),
            });

        // First writer wins. A concurrent call (e.g. two tabs opening at once) may have
        // created an env in parallel; per WebView2 docs, options-equivalent envs share the
        // same browser host process, so the loser can be dropped harmlessly.
        var winner = Interlocked.CompareExchange(ref s_sharedEnvironment, created, null);
        return winner ?? created;
    }

    private async Task ScheduleHandshakeTimeoutAsync(ITerminalSessionViewModel vm, int handshakeGeneration)
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
        if (_activeHandshakeBindingGeneration != _viewBindingGeneration) return;

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
        TerminalView.Visibility = Visibility.Visible;

        // The handshake carries the initial xterm.js geometry as "ready:COLSxROWS" so the
        // SSH shell can be allocated at the correct size. If parsing fails, fall back to
        // the protocol default — better than 80x24 stuck forever.
        var size = TerminalSize.Default;
        if (msg.Length > 6 && msg[5] == ':')
        {
            var dimensions = msg.AsSpan(6);
            var separator = dimensions.IndexOf('x');
            if (separator > 0 &&
                separator < dimensions.Length - 1 &&
                uint.TryParse(dimensions[..separator], out var cols) &&
                uint.TryParse(dimensions[(separator + 1)..], out var rows) &&
                cols > 0 && rows > 0)
            {
                size = new TerminalSize(cols, rows);
            }
        }
        _lastSize = size;
        LogTerminalReady(size);

        var vm = _viewModel;
        if (vm is null) return;
        // Push WinUI keyboard focus into the WebView2 before AttachAsync fires
        // its JS-side term.focus(). Without this, a freshly-opened tab leaves
        // focus on the connection tree and the first keystrokes are dropped
        // until the user clicks inside the terminal.
        //
        // Wrapped in its own try/catch (separate from the AttachAsync try below)
        // for two reasons: (1) a Focus exception during a WebView2 teardown race
        // must not escape this async void handler and crash the process; (2) a
        // focus failure must not bubble up to vm.ReportFailure and mark a healthy
        // SSH session as Failed. IsLoaded gates the call so we don't focus a
        // control whose Unloaded raced ahead of this dispatcher run.
        if (IsLoaded)
        {
            try
            {
                TerminalView.Focus(FocusState.Programmatic);
            }
            catch (Exception ex)
            {
                // App.Current can be null during process shutdown — accessed via ?. so an
                // NRE inside this catch can't escape and crash the async void handler.
                var logger = App.Current?.Services?.GetService<ILogger<SshTerminalView>>();
                logger?.LogDebug(ex, "SshTerminalView focus push suppressed (likely teardown race).");
            }
        }
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

    private static void LogWebViewInitializationFailure(Exception ex, string userDataFolder)
    {
        var logger = App.Current.Services.GetService<ILogger<SshTerminalView>>();
        if (logger is null) return;

        var baseDirectory = AppContext.BaseDirectory;
        var loaderPath = Path.Combine(baseDirectory, "WebView2Loader.dll");
        logger.LogError(
            ex,
            "Failed to initialize WebView2. BaseDirectory={BaseDirectory}; ExceptionType={ExceptionType}; HResult=0x{HResult:X8}; WebView2LoaderPath={WebView2LoaderPath}; WebView2LoaderExists={WebView2LoaderExists}; UserDataFolder={UserDataFolder}; UserDataFolderExists={UserDataFolderExists}",
            baseDirectory,
            ex.GetType().FullName,
            ex.HResult,
            loaderPath,
            File.Exists(loaderPath),
            userDataFolder,
            Directory.Exists(userDataFolder));
    }

    // The VM outlives the view (it lives in ShellViewModel.Tabs across navigations),
    // so we must unsubscribe here or every navigation accumulates a stale handler
    // that keeps the old SshTerminalView alive and double-runs init on retry.
    // Also tell the VM to drop the bridge — otherwise background SSH output keeps
    // posting to a disposed WebView2 until reconnect or tab close.
    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        // Collapse the WebView2 BEFORE detaching: WinUI 3's TabView leaving parent visibility
        // to its child doesn't reliably suspend WebView2's composition surface, so a
        // background tab still painting (heavy SSH output, or an xterm.js re-render fired
        // by text selection) can bleed pixels into the selected tab. Setting Visibility on
        // the WebView2 element itself propagates to its render surface.
        // (RdpSurfaceHost solves the equivalent airspace problem differently — it reparents
        // the ActiveX HWND via DetachView — so the mechanism is unique to this file.)
        TerminalView.Visibility = Visibility.Collapsed;

        _viewBindingGeneration++;
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
