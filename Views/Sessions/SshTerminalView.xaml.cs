using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;
using Wormhole.Interop.Terminal;
using Wormhole.Services;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Sessions;

public sealed partial class SshTerminalView : UserControl, ISessionSurfaceActivation
{
    // How long to wait for the JS "ready" handshake after navigation completes before
    // surfacing a failure. Missing/corrupt xterm assets, JS errors in bridge.js, or
    // a stuck WebView all show up as "no handshake."
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);
    private const long RendererUnresponsiveGraceMilliseconds = 15_000;

    private enum RendererRecoveryResult
    {
        Busy,
        Stale,
        Handled,
    }

    // EnsureCoreWebView2Async throws if the WebView2 control is re-bound to a different
    // CoreWebView2Environment instance — so Retry (and multi-tab opens) must reuse the
    // same one. Cache it process-wide on first successful creation; concurrent first
    // callers race via CompareExchange and the loser drops its instance.
    private static CoreWebView2Environment? s_sharedEnvironment;

    private readonly ILogger<SshTerminalView> _logger;
    private readonly TerminalInitializationRecoveryGate _initializationRecoveryGate = new();

    private ITerminalSessionViewModel? _viewModel;
    private bool _handshakeReceived;
    private bool _terminalInitializationFailed;
    private int _handshakeGeneration;
    private int _viewBindingGeneration;
    private int _activeHandshakeBindingGeneration = -1;
    private int _activeHandshakeGeneration = -1;
    private string? _activeHandshakeSource;
    private int _initInProgress;
    private bool _initializationRequested;
    private int _webViewGeneration;
    private CoreWebView2? _subscribedProcessCore;
    private bool _terminalWebViewRecreationRequired;
    private int _rendererRecoveryInProgress;
    private int _rendererRecoveryGeneration;
    private int _rendererUnresponsiveEvents;
    private long _lastRendererUnresponsiveTick;
    private TerminalSize _lastSize = TerminalSize.Default;
    private bool _sessionSurfaceActive = true;

    public SshTerminalView()
    {
        _logger = ResolveLogger();
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        DataContextChanged += OnDataContextChanged;
    }

    /// <summary>
    /// Multi-surface tab host toggles Visibility without Unloading this control. Collapse the
    /// WebView2 to stop pixel bleed, but keep the TerminalBridge attached so switching back does
    /// not require an exact scrollback replay.
    /// </summary>
    public void SetSessionSurfaceActive(bool isActive)
    {
        if (_sessionSurfaceActive == isActive) return;
        _sessionSurfaceActive = isActive;
        if (!isActive)
        {
            TerminalContentMask.Visibility = Visibility.Visible;
            TerminalView.Visibility = Visibility.Collapsed;
            return;
        }

        TerminalView.Visibility = Visibility.Visible;
        if (_handshakeReceived)
        {
            TerminalContentMask.Visibility = Visibility.Collapsed;
            TryFocusTerminalHost();
        }
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await AttachCurrentViewModelSafelyAsync().ConfigureAwait(true);
        if (!_sessionSurfaceActive)
        {
            // Loaded can fire while the surface is still Collapsed (background tab). Keep the
            // protocol session attached but hide the WebView composition surface.
            SetSessionSurfaceActive(false);
        }
    }

    private async void OnDataContextChanged(FrameworkElement sender, DataContextChangedEventArgs args)
    {
        // TabView may recycle the selected content container by changing DataContext without an
        // Unloaded/Loaded pair. That is the close-by-middle-click race: without this callback the
        // visible terminal keeps its bridge pointed at the VM that has just been closed.
        if (!IsLoaded) return;
        await AttachCurrentViewModelSafelyAsync().ConfigureAwait(true);
    }

    private async Task AttachCurrentViewModelSafelyAsync()
    {
        var requestedVm = DataContext as ITerminalSessionViewModel;
        try
        {
            await AttachCurrentViewModelAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to attach the terminal view.");

            if (requestedVm is null ||
                !ReferenceEquals(requestedVm, DataContext) ||
                !IsLoaded)
            {
                return;
            }

            TerminalContentMask.Visibility = Visibility.Visible;
            var failureMessage = "Failed to attach the terminal view: " + ex.Message;
            if (IsCommittedRendererOwner(requestedVm))
            {
                EnsureViewModelSubscriptions(requestedVm);
                await FailProtocolSessionAndResetRendererAsync(
                    requestedVm,
                    reloadRenderer: true,
                    browserProcessClosed: false,
                    failureMessage).ConfigureAwait(true);
                return;
            }

            await RetryAttachWithFreshWebViewAsync(requestedVm, failureMessage)
                .ConfigureAwait(true);
        }
    }

    private bool IsCommittedRendererOwner(ITerminalSessionViewModel vm)
    {
        if (!ReferenceEquals(vm, _viewModel)) return false;
        try
        {
            return _subscribedProcessCore is { } core &&
                   vm.OwnsTerminalRenderer(core);
        }
        catch
        {
            return false;
        }
    }

    private async Task RetryAttachWithFreshWebViewAsync(
        ITerminalSessionViewModel requestedVm,
        string failureMessage)
    {
        if (!IsLoaded || !ReferenceEquals(requestedVm, DataContext)) return;

        // The failure happened before this VM committed ownership of the page. Replace only
        // the view-local browser control, then retry binding; never tear down another page's
        // live protocol session merely because this recycled control failed.
        _terminalWebViewRecreationRequired = true;
        try
        {
            await AttachCurrentViewModelAsync().ConfigureAwait(true);
        }
        catch (Exception retryException)
        {
            _logger.LogError(retryException, "Failed to rebuild the terminal view after an attach error.");

            if (!IsLoaded || !ReferenceEquals(requestedVm, DataContext)) return;
            TerminalContentMask.Visibility = Visibility.Visible;
            if (IsCommittedRendererOwner(requestedVm))
            {
                EnsureViewModelSubscriptions(requestedVm);
                await FailProtocolSessionAndResetRendererAsync(
                    requestedVm,
                    reloadRenderer: true,
                    browserProcessClosed: false,
                    failureMessage + " Rebuild failed: " + retryException.Message)
                    .ConfigureAwait(true);
            }
            else
            {
                // Preserve the retry for the next Loaded/DataContext event. The requested VM
                // still belongs to another renderer (or none), so its transport must stay alive.
                _terminalWebViewRecreationRequired = true;
            }
        }
    }

    private async Task AttachCurrentViewModelAsync()
    {
        var newVm = DataContext as ITerminalSessionViewModel;
        var bindingChanged = !ReferenceEquals(newVm, _viewModel);
        var rendererIdentityBeforeRebind =
            bindingChanged ? TryGetTerminalRendererIdentity() : null;
        if (bindingChanged)
        {
            _initializationRecoveryGate.OnBindingChanged();
            HideLocalRendererRetry();
        }

        // WebView2 must remain in layout while xterm.js waits for a usable viewport. Mask a
        // recycled page instead of collapsing it; the status overlays remain visible above the
        // mask, and a same-VM reload can reveal its existing page after reattachment.
        // Background multi-surface tabs keep the composition surface collapsed to avoid bleed.
        TerminalView.Visibility = _sessionSurfaceActive ? Visibility.Visible : Visibility.Collapsed;
        if (bindingChanged || newVm is null || !_sessionSurfaceActive)
        {
            TerminalContentMask.Visibility = Visibility.Visible;
        }

        // BrowserProcessExited permanently closes the WebView2 control. The exit may race an
        // unload and invalidate the in-flight recovery generation, so persist this requirement
        // and replace the control on the next loaded attachment before reading CoreWebView2.
        // A failed automatic replacement stays local to this view until the user explicitly retries.
        if (_terminalWebViewRecreationRequired &&
            _initializationRecoveryGate.RequiresManualRetry)
        {
            ShowLocalRendererRetry();
            return;
        }
        if (_terminalWebViewRecreationRequired)
        {
            RecreateTerminalWebViewAfterBrowserExit();
            _terminalWebViewRecreationRequired = false;
            _handshakeReceived = false;
            _terminalInitializationFailed = false;
            _handshakeGeneration++;
        }

        if (bindingChanged)
        {
            var retiringViewModel = _viewModel;
            if (retiringViewModel is not null)
            {
                retiringViewModel.InitializationRetryRequested -= OnInitializationRetryRequested;
                retiringViewModel.TerminalRendererRecoveryRequested -= OnTerminalRendererRecoveryRequested;
                // The same WebView page is about to be navigated for another VM. Wait until the
                // outgoing bridge has parsed its accepted prefix and delivered parser replies;
                // navigating earlier would destroy the only page capable of acknowledging it.
                await retiringViewModel.DetachViewAsync(
                    rendererIdentityBeforeRebind,
                    preserveTerminalContents: false).ConfigureAwait(true);
                if (!IsLoaded ||
                    !ReferenceEquals(newVm, DataContext) ||
                    !ReferenceEquals(retiringViewModel, _viewModel))
                {
                    return;
                }
            }
            if (rendererIdentityBeforeRebind is CoreWebView2 retiringCore)
            {
                TryRemoveInitializationMessageHandler(retiringCore);
            }
            _viewModel = newVm;
            _handshakeReceived = false;
            _terminalInitializationFailed = false;
            _lastSize = TerminalSize.Default;
            InvalidateRendererRecovery();
            _rendererUnresponsiveEvents = 0;
            _lastRendererUnresponsiveTick = 0;
            _handshakeGeneration++;
            _viewBindingGeneration++;
        }
        if (newVm is null) return;

        // Always (re)subscribe — OnUnloaded unsubscribes on every unload, so a same-VM
        // reload would otherwise leave the event with no listener and RetryAsync (the
        // _webView == null branch) would be a no-op.
        EnsureViewModelSubscriptions(newVm);

        var attachedCore = TerminalView.CoreWebView2;
        if (attachedCore is not null &&
            newVm.TryTakeTerminalRendererRecoveryRequest(attachedCore, out var rendererFailure))
        {
            await FailProtocolSessionAndResetRendererAsync(
                newVm,
                reloadRenderer: true,
                browserProcessClosed: false,
                rendererFailure).ConfigureAwait(true);
            return;
        }

        // Same instance is being reloaded (e.g. NavigationView swap, tab content
        // recycle): the WebView2 and its in-page xterm.js are still alive but
        // OnUnloaded disposed the bridge. Rebind without re-navigating, otherwise
        // the terminal would appear dead — _handshakeReceived gates re-init so
        // a normal flow would short-circuit here and never call AttachAsync.
        if (_handshakeReceived)
        {
            if (TerminalView.CoreWebView2 is not null)
            {
                var bindingGeneration = _viewBindingGeneration;
                var handshakeGeneration = _handshakeGeneration;
                try
                {
                    TryFocusTerminalHost();
                    await newVm.AttachAsync(TerminalView.CoreWebView2, _lastSize).ConfigureAwait(true);
                    if (handshakeGeneration == _handshakeGeneration &&
                        IsCurrentBinding(newVm, bindingGeneration))
                    {
                        CompleteLocalRendererRecovery();
                        if (_sessionSurfaceActive)
                        {
                            TerminalContentMask.Visibility = Visibility.Collapsed;
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (handshakeGeneration != _handshakeGeneration ||
                        !IsCurrentBinding(newVm, bindingGeneration))
                    {
                        return;
                    }
                    await FailProtocolSessionAndResetRendererAsync(
                        newVm,
                        reloadRenderer: true,
                        browserProcessClosed: false,
                        "Failed to attach the terminal renderer: " + ex.Message).ConfigureAwait(true);
                }
                return;
            }

            _handshakeReceived = false;
        }
        await InitializeWebViewAsync().ConfigureAwait(true);
    }

    // WebView2 and xterm own separate focus layers. Push WinUI focus into the host first; AttachAsync
    // then queues term.focus() behind all older output so keyboard input cannot overtake a repaint.
    private void TryFocusTerminalHost()
    {
        if (!IsLoaded) return;

        try
        {
            TerminalView.Focus(FocusState.Programmatic);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "SshTerminalView focus push suppressed (likely teardown race).");
        }
    }

    private CoreWebView2? TryGetTerminalRendererIdentity()
    {
        try { return TerminalView.CoreWebView2 ?? _subscribedProcessCore; }
        catch { return _subscribedProcessCore; }
    }

    private void ShowLocalRendererRetry()
    {
        TerminalContentMask.Visibility = Visibility.Visible;
        TerminalRendererRetryOverlay.Visibility = Visibility.Visible;
    }

    private void HideLocalRendererRetry() =>
        TerminalRendererRetryOverlay.Visibility = Visibility.Collapsed;

    private void CompleteLocalRendererRecovery()
    {
        _initializationRecoveryGate.OnRendererAttached();
        HideLocalRendererRetry();
    }

    private async void OnRetryTerminalRendererClick(object sender, RoutedEventArgs e)
    {
        if (!_initializationRecoveryGate.TryQueueManualRetry()) return;

        HideLocalRendererRetry();
        _terminalInitializationFailed = false;
        await InitializeWebViewSafelyAsync().ConfigureAwait(true);
    }

    private bool TryRequireLocalRendererRetry()
    {
        if (_initializationRecoveryGate.State is not
                TerminalInitializationRecoveryState.AutomaticRetryRunning and not
                TerminalInitializationRecoveryState.ManualRetryRunning &&
            !_initializationRecoveryGate.RequiresManualRetry)
        {
            return false;
        }

        RequireLocalRendererRetry();
        return true;
    }

    private void RequireLocalRendererRetry()
    {
        _initializationRecoveryGate.OnReplacementFailed();
        _terminalWebViewRecreationRequired = true;
        _terminalInitializationFailed = true;
        InvalidateRendererRecovery();
        ShowLocalRendererRetry();
    }

    private async Task<TerminalRendererRecoveryLease?> RouteTerminalRendererFailureAsync(
        ITerminalSessionViewModel vm,
        string failureMessage)
    {
        var recoveryLease = await vm.TryHandleTerminalRendererFailureAsync(
            TryGetTerminalRendererIdentity(),
            failureMessage).ConfigureAwait(true);
        if (recoveryLease is null)
        {
            RequireLocalRendererRetry();
        }

        return recoveryLease;
    }

    private void TryRemoveInitializationMessageHandler(CoreWebView2? core)
    {
        if (core is null) return;
        try
        {
            core.WebMessageReceived -= OnTerminalInitializationMessage;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Terminal WebView was already closed while removing its initialization handler.");
        }
    }

    private void SubscribeToProcessFailures(CoreWebView2 core)
    {
        if (_subscribedProcessCore is not null &&
            !ReferenceEquals(_subscribedProcessCore, core))
        {
            try { _subscribedProcessCore.ProcessFailed -= OnTerminalProcessFailed; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Retired terminal process source was already closed.");
            }
        }

        core.ProcessFailed -= OnTerminalProcessFailed;
        core.ProcessFailed += OnTerminalProcessFailed;
        _subscribedProcessCore = core;
    }

    private void EnsureViewModelSubscriptions(ITerminalSessionViewModel vm)
    {
        vm.InitializationRetryRequested -= OnInitializationRetryRequested;
        vm.InitializationRetryRequested += OnInitializationRetryRequested;
        vm.TerminalRendererRecoveryRequested -= OnTerminalRendererRecoveryRequested;
        vm.TerminalRendererRecoveryRequested += OnTerminalRendererRecoveryRequested;
    }

    private async Task InitializeWebViewAsync()
    {
        // Re-entrancy is latched rather than dropped: browser replacement and DataContext changes
        // can both request a new navigation while an older environment creation is awaiting.
        if (Interlocked.CompareExchange(ref _initInProgress, 1, 0) != 0)
        {
            _initializationRequested = true;
            return;
        }

        _initializationRequested = false;
        var vm = _viewModel;
        if (vm is null)
        {
            _initInProgress = 0;
            return;
        }

        var localReplacementAttempt = false;
        if (_terminalWebViewRecreationRequired)
        {
            if (_initializationRecoveryGate.RequiresManualRetry)
            {
                ShowLocalRendererRetry();
                _initInProgress = 0;
                return;
            }

            localReplacementAttempt = _initializationRecoveryGate.HasQueuedReplacement;
            try
            {
                RecreateTerminalWebViewAfterBrowserExit();
                _terminalWebViewRecreationRequired = false;
                _handshakeReceived = false;
                _terminalInitializationFailed = false;
                _handshakeGeneration++;
            }
            catch (Exception ex)
            {
                _initInProgress = 0;
                if (!localReplacementAttempt) throw;

                _initializationRecoveryGate.OnReplacementFailed();
                _terminalInitializationFailed = true;
                ShowLocalRendererRetry();
                _logger.LogError(ex, "Failed to recreate the terminal WebView2 control.");
                return;
            }
        }
        var bindingGeneration = _viewBindingGeneration;
        var initializingView = TerminalView;
        var webViewGeneration = _webViewGeneration;
        if (!IsCurrentInitialization(vm, bindingGeneration, initializingView, webViewGeneration))
        {
            _initInProgress = 0;
            return;
        }

        string userDataFolder;
        var replaceViewOnInitializationFailure = false;
        try
        {
            // Retry and recycled-view initialization both navigate the page while it is masked,
            // but WebView2 itself stays visible so Chromium receives real bounds and xterm.js can fit.
            initializingView.Visibility = Visibility.Visible;
            TerminalContentMask.Visibility = Visibility.Visible;

            // MarkConnecting is deliberately conservative and does not disturb a live session,
            // a Failed tab, or an explicitly disconnected tab.
            vm.MarkConnecting();

            // Pin WebView2's user-data folder under %LOCALAPPDATA%; the executable-adjacent
            // default is not writable after installation under Program Files.
            userDataFolder = AppPaths.GetWebView2UserDataDirectory();
        }
        catch
        {
            _initInProgress = 0;
            throw;
        }
        try
        {
            var environment = await GetOrCreateSharedEnvironmentAsync(userDataFolder);
            if (!IsCurrentInitialization(vm, bindingGeneration, initializingView, webViewGeneration))
            {
                _initializationRequested = true;
                return;
            }

            // From this point an exception can mean Ensure created a CoreWebView2 whose browser
            // exited before ProcessFailed was subscribed. Never reuse that possibly closed control.
            replaceViewOnInitializationFailure = true;
            await initializingView.EnsureCoreWebView2Async(environment);
            if (!IsCurrentInitialization(vm, bindingGeneration, initializingView, webViewGeneration))
            {
                _initializationRequested = true;
                return;
            }

            var core = initializingView.CoreWebView2
                ?? throw new InvalidOperationException(
                    "WebView2 initialization completed without a CoreWebView2 instance. " +
                    "UserDataFolder=" + userDataFolder);

            core.SetVirtualHostNameToFolderMapping(
                "terminal.wormhole",
                AppPaths.GetWebAssetsDirectory(),
                CoreWebView2HostResourceAccessKind.Allow);

            core.Settings.AreDevToolsEnabled = Debugger.IsAttached;
            core.Settings.AreDefaultContextMenusEnabled = Debugger.IsAttached;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;
            SubscribeToProcessFailures(core);

            var handshakeGeneration = NavigateTerminalPage(core, bindingGeneration);
            _ = ScheduleHandshakeTimeoutAsync(vm, handshakeGeneration);
        }
        catch (Exception ex)
        {
            // A retired initialization must not report against a replacement control or VM.
            if (!IsInitializationIdentityCurrent(
                    vm,
                    bindingGeneration,
                    initializingView,
                    webViewGeneration))
            {
                _initializationRequested = true;
                return;
            }

            if (_terminalWebViewRecreationRequired)
            {
                if (_initializationRecoveryGate.State ==
                    TerminalInitializationRecoveryState.AutomaticRetryQueued)
                {
                    // The first pre-ownership browser exit queued exactly one replacement. Let the
                    // finally block consume its latch after this initialization owner releases it.
                    _initializationRequested = true;
                    return;
                }

                // A committed protocol recovery owns teardown + replacement. The init path must not
                // supersede it while HandleTerminalRendererFailureAsync is still awaiting disposal.
                if (!localReplacementAttempt && IsCommittedRendererOwner(vm))
                {
                    return;
                }
            }

            if (localReplacementAttempt || _initializationRecoveryGate.RequiresManualRetry)
            {
                _terminalWebViewRecreationRequired = true;
                _terminalInitializationFailed = true;
                _initializationRecoveryGate.OnReplacementFailed();
                ShowLocalRendererRetry();
                LogWebViewInitializationFailure(ex, userDataFolder);
                return;
            }

            if (replaceViewOnInitializationFailure)
            {
                // BrowserProcessExited can occur after Ensure succeeds but before the CoreWebView2
                // event subscription below. Preserve a fresh-control requirement for the Retry path.
                _terminalWebViewRecreationRequired = true;
            }
            _terminalInitializationFailed = true;
            EnsureViewModelSubscriptions(vm);
            LogWebViewInitializationFailure(ex, userDataFolder);
            // _handshakeReceived stays false so a Retry click re-runs init.
            await RouteTerminalRendererFailureAsync(vm,
                "Failed to initialize WebView2: " + ex.Message).ConfigureAwait(true);
        }
        finally
        {
            _initInProgress = 0;
            var retryRequested =
                _initializationRequested ||
                bindingGeneration != _viewBindingGeneration ||
                webViewGeneration != _webViewGeneration ||
                !ReferenceEquals(initializingView, TerminalView);
            _initializationRequested = false;

            // A DataContext rebind can queue B while initialization A still owns the latch. Once A
            // releases it, A is intentionally stale; requiring A's identity here drops B's request
            // and leaves the recycled terminal permanently masked. Decide from the current loaded
            // target instead. The recovery gate still blocks an unqueued WebView recreation and
            // every ManualRetryRequired episode.
            var currentTargetIsAvailable =
                IsLoaded &&
                _viewModel is not null &&
                ReferenceEquals(_viewModel, DataContext);
            if (_initializationRecoveryGate.ShouldConsumeInitializationRetry(
                    retryRequested,
                    _terminalWebViewRecreationRequired,
                    currentTargetIsAvailable))
            {
                if (_terminalWebViewRecreationRequired &&
                    _initializationRecoveryGate.HasQueuedReplacement)
                {
                    // This is the pre-ownership handoff, or a replacement page that failed after
                    // protocol teardown. Supersede an older recovery before this path recreates.
                    InvalidateRendererRecovery();
                }
                await InitializeWebViewAsync().ConfigureAwait(true);
            }
        }
    }

    private bool IsCurrentInitialization(
        ITerminalSessionViewModel vm,
        int bindingGeneration,
        WebView2 view,
        int webViewGeneration) =>
        !_terminalWebViewRecreationRequired &&
        IsInitializationIdentityCurrent(vm, bindingGeneration, view, webViewGeneration);

    private bool IsInitializationIdentityCurrent(
        ITerminalSessionViewModel vm,
        int bindingGeneration,
        WebView2 view,
        int webViewGeneration) =>
        webViewGeneration == _webViewGeneration &&
        ReferenceEquals(view, TerminalView) &&
        IsCurrentBinding(vm, bindingGeneration);

    private int NavigateTerminalPage(CoreWebView2 core, int bindingGeneration)
    {
        _handshakeReceived = false;
        _terminalInitializationFailed = false;
        var handshakeGeneration = ++_handshakeGeneration;
        _activeHandshakeBindingGeneration = bindingGeneration;
        _activeHandshakeGeneration = handshakeGeneration;
        _activeHandshakeSource =
            $"https://terminal.wormhole/terminal.html?navigation={bindingGeneration}-{handshakeGeneration}";

        TryRemoveInitializationMessageHandler(core);
        core.WebMessageReceived += OnTerminalInitializationMessage;
        core.Navigate(_activeHandshakeSource);
        return handshakeGeneration;
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
        _rendererRecoveryInProgress = 0;
        if (TryRequireLocalRendererRetry()) return;
        EnsureViewModelSubscriptions(vm);
        await RouteTerminalRendererFailureAsync(vm,
            "Terminal page did not finish loading (no 'ready' handshake). " +
            "The xterm.js assets may be missing or corrupted.").ConfigureAwait(true);
    }

    private async void OnInitializationRetryRequested()
    {
        if (_handshakeReceived) return;
        await InitializeWebViewSafelyAsync().ConfigureAwait(true);
    }

    private async Task InitializeWebViewSafelyAsync()
    {
        var vm = _viewModel;
        var bindingGeneration = _viewBindingGeneration;
        try
        {
            await InitializeWebViewAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled terminal WebView initialization failure.");
            if (vm is not null && IsCurrentBinding(vm, bindingGeneration))
            {
                if (TryRequireLocalRendererRetry()) return;
                TerminalContentMask.Visibility = Visibility.Visible;
                EnsureViewModelSubscriptions(vm);
                await RouteTerminalRendererFailureAsync(vm,
                    "Failed to initialize the terminal renderer: " + ex.Message).ConfigureAwait(true);
            }
        }
    }

    private async void OnTerminalRendererRecoveryRequested()
    {
        // A callback queued before OnUnloaded unsubscribed must leave the page-scoped request
        // intact. AttachCurrentViewModelAsync consumes it when that exact page is loaded again.
        if (!IsLoaded) return;

        var vm = _viewModel;
        if (vm is null) return;

        CoreWebView2? core;
        try { core = TerminalView.CoreWebView2; }
        catch { core = null; }

        if (core is null ||
            !vm.TryTakeTerminalRendererRecoveryRequest(core, out var failureMessage))
        {
            return;
        }

        await FailProtocolSessionAndResetRendererAsync(
            vm,
            reloadRenderer: true,
            browserProcessClosed: false,
            failureMessage).ConfigureAwait(true);
    }

    private async void OnTerminalInitializationMessage(
        CoreWebView2 sender,
        CoreWebView2WebMessageReceivedEventArgs args)
    {
        var vm = _viewModel;
        var bindingGeneration = _viewBindingGeneration;
        try
        {
            await HandleTerminalInitializationMessageAsync(sender, args).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to handle the terminal initialization handshake.");
            if (vm is not null && IsCurrentBinding(vm, bindingGeneration))
            {
                if (TryRequireLocalRendererRetry()) return;
                TerminalContentMask.Visibility = Visibility.Visible;
                EnsureViewModelSubscriptions(vm);
                await RouteTerminalRendererFailureAsync(vm,
                    "Terminal initialization failed: " + ex.Message).ConfigureAwait(true);
            }
        }
    }

    private async Task HandleTerminalInitializationMessageAsync(
        CoreWebView2 sender,
        CoreWebView2WebMessageReceivedEventArgs args)
    {
        var bindingGeneration = _activeHandshakeBindingGeneration;
        var handshakeGeneration = _activeHandshakeGeneration;
        if (bindingGeneration != _viewBindingGeneration ||
            handshakeGeneration != _handshakeGeneration ||
            !string.Equals(args.Source, _activeHandshakeSource, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var msg = args.TryGetWebMessageAsString();
        if (msg is null) return;

        if (msg.StartsWith("error:", StringComparison.Ordinal))
        {
            TryRemoveInitializationMessageHandler(sender);
            _terminalInitializationFailed = true;
            _rendererRecoveryInProgress = 0;

            var detail = msg.Substring("error:".Length);
            LogTerminalInitializationFailure(detail);
            if (TryRequireLocalRendererRetry()) return;
            var errorVm = _viewModel;
            if (errorVm is not null)
            {
                EnsureViewModelSubscriptions(errorVm);
                await RouteTerminalRendererFailureAsync(errorVm,
                    "Terminal page failed to initialize: " + detail).ConfigureAwait(true);
            }
            return;
        }


        var hasReadySize = TryParseTerminalSizeFrame(msg, "ready:", out var size);
        if (!hasReadySize && !string.Equals(msg, "ready", StringComparison.Ordinal)) return;

        _handshakeReceived = true;
        _rendererRecoveryInProgress = 0;
        _rendererUnresponsiveEvents = 0;
        _lastRendererUnresponsiveTick = 0;
        if (!hasReadySize) size = TerminalSize.Default;
        _lastSize = size;
        LogTerminalReady(size);

        var vm = _viewModel;
        if (vm is null || !IsCurrentBinding(vm, bindingGeneration)) return;
        if (vm.TryTakeTerminalRendererRecoveryRequest(sender, out var rendererFailure))
        {
            await FailProtocolSessionAndResetRendererAsync(
                vm,
                reloadRenderer: true,
                browserProcessClosed: false,
                rendererFailure).ConfigureAwait(true);
            return;
        }
        vm.UpdateTerminalSize(size);

        try
        {
            TryFocusTerminalHost();
            await vm.AttachAsync(TerminalView.CoreWebView2, size);
            if (handshakeGeneration != _handshakeGeneration ||
                !IsCurrentBinding(vm, bindingGeneration))
            {
                return;
            }

            TryRemoveInitializationMessageHandler(sender);
            EnsureViewModelSubscriptions(vm);
            CompleteLocalRendererRecovery();
            if (_sessionSurfaceActive)
            {
                TerminalContentMask.Visibility = Visibility.Collapsed;
            }
        }
        catch (Exception ex)
        {
            // A retired navigation must not hide the replacement's mask or report its exception
            // against the current renderer/session.
            if (handshakeGeneration != _handshakeGeneration ||
                !IsCurrentBinding(vm, bindingGeneration))
            {
                return;
            }

            TryRemoveInitializationMessageHandler(sender);
            await FailProtocolSessionAndResetRendererAsync(
                vm,
                reloadRenderer: true,
                browserProcessClosed: false,
                "Failed to attach the terminal renderer: " + ex.Message).ConfigureAwait(true);
        }
    }

    private static bool TryParseTerminalSizeFrame(
        string message,
        string prefix,
        out TerminalSize size)
    {
        size = TerminalSize.Default;
        if (!message.StartsWith(prefix, StringComparison.Ordinal)) return false;

        var dimensions = message.AsSpan(prefix.Length);
        var separator = dimensions.IndexOf('x');
        if (separator <= 0 ||
            separator >= dimensions.Length - 1 ||
            !uint.TryParse(dimensions[..separator], out var columns) ||
            !uint.TryParse(dimensions[(separator + 1)..], out var rows) ||
            columns == 0 ||
            rows == 0)
        {
            return false;
        }

        size = new TerminalSize(columns, rows);
        return true;
    }
    private async void OnTerminalProcessFailed(object? sender, CoreWebView2ProcessFailedEventArgs args)
    {
        // A queued event from a retired WebView must never tear down the replacement session.
        if (!ReferenceEquals(sender, _subscribedProcessCore)) return;

        _logger.LogWarning(
            "Terminal WebView2 process failed. Kind={ProcessFailedKind}; ExitCode={ExitCode}.",
            args.ProcessFailedKind,
            args.ExitCode);

        var browserProcessExited =
            args.ProcessFailedKind == CoreWebView2ProcessFailedKind.BrowserProcessExited;
        var pageProcessExited =
            args.ProcessFailedKind == CoreWebView2ProcessFailedKind.RenderProcessExited ||
            browserProcessExited;
        if (pageProcessExited)
        {
            // Invalidate this control's page even when its VM has since moved to another view.
            // The local renderer must never be reused after its process has exited.
            _handshakeReceived = false;
            _terminalInitializationFailed = false;
            _handshakeGeneration++;
        }
        if (browserProcessExited)
        {
            _terminalWebViewRecreationRequired = true;
        }

        var vm = _viewModel;
        if (vm is null) return;
        if (!vm.OwnsTerminalRenderer(sender))
        {
            _logger.LogDebug(
                "Ignored terminal process failure from a renderer no longer owned by the bound session.");
            if (pageProcessExited &&
                IsLoaded &&
                ReferenceEquals(vm, DataContext))
            {
                // The process may have failed during first-page initialization, before AttachAsync
                // registered ownership. Rebuild only this view; a session may belong to another page.
                if (browserProcessExited)
                {
                    var action = _initializationRecoveryGate.OnUnownedBrowserProcessExited();
                    if (action == TerminalBrowserExitAction.Ignore) return;
                    if (action == TerminalBrowserExitAction.RequireManualRetry)
                    {
                        InvalidateRendererRecovery();
                        _terminalInitializationFailed = true;
                        ShowLocalRendererRetry();
                        return;
                    }
                }
                await InitializeWebViewSafelyAsync().ConfigureAwait(true);
            }
            return;
        }
        var bindingGeneration = _viewBindingGeneration;
        var processFailureLease = vm.CaptureTerminalRendererRecoveryLease();

        try
        {
            switch (args.ProcessFailedKind)
            {
                case CoreWebView2ProcessFailedKind.RenderProcessUnresponsive:
                    if (!IsLoaded) return;
                    // WebView2 repeats this event. One short incident gets a grace event; two
                    // reports within the window mean the renderer is no longer making progress.
                    var now = Environment.TickCount64;
                    if (_lastRendererUnresponsiveTick == 0 ||
                        now - _lastRendererUnresponsiveTick > RendererUnresponsiveGraceMilliseconds)
                    {
                        _rendererUnresponsiveEvents = 0;
                    }
                    _lastRendererUnresponsiveTick = now;
                    if (++_rendererUnresponsiveEvents < 2) return;
                    await FailProtocolSessionAndResetRendererAsync(
                        vm,
                        reloadRenderer: true,
                        browserProcessClosed: false,
                        "The terminal renderer stopped responding. The connection was closed to preserve a clean terminal state; retry to reconnect.");
                    break;

                case CoreWebView2ProcessFailedKind.RenderProcessExited:
                    _rendererUnresponsiveEvents = 0;
                    _lastRendererUnresponsiveTick = 0;
                    await FailProtocolSessionAndResetRendererAsync(
                        vm,
                        reloadRenderer: IsLoaded,
                        browserProcessClosed: false,
                        "The terminal renderer exited. The connection was closed to preserve a clean terminal state; retry to reconnect.");
                    break;

                case CoreWebView2ProcessFailedKind.BrowserProcessExited:
                    _rendererUnresponsiveEvents = 0;
                    _lastRendererUnresponsiveTick = 0;
                    await FailProtocolSessionAndResetRendererAsync(
                        vm,
                        reloadRenderer: false,
                        browserProcessClosed: true,
                        "The terminal browser process stopped. A clean renderer is being created; retry to reconnect.");
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to handle a terminal WebView2 process failure.");
            if (bindingGeneration == _viewBindingGeneration &&
                ReferenceEquals(vm, _viewModel) &&
                vm.IsTerminalRendererRecoveryCurrent(processFailureLease) &&
                vm.OwnsTerminalRenderer(sender))
            {
                if (IsLoaded)
                {
                    EnsureViewModelSubscriptions(vm);
                }
                await RouteTerminalRendererFailureAsync(vm,
                    "Failed to recover the terminal renderer: " + ex.Message).ConfigureAwait(true);
            }
        }
    }

    private async Task FailProtocolSessionAndResetRendererAsync(
        ITerminalSessionViewModel vm,
        bool reloadRenderer,
        bool browserProcessClosed,
        string failureMessage)
    {
        // BrowserProcessExited permanently closes the control. Set this before the recovery CAS so
        // the requirement survives an overlapping recovery, unload, or stale generation.
        if (browserProcessClosed)
        {
            _terminalWebViewRecreationRequired = true;
        }

        var bindingGeneration = _viewBindingGeneration;
        var recoveryEntryLease = vm.CaptureTerminalRendererRecoveryLease();
        try
        {
            var recoveryResult = await FailProtocolSessionAndResetRendererCoreAsync(
                vm,
                reloadRenderer,
                browserProcessClosed,
                failureMessage).ConfigureAwait(true);
            // A browser exit can arrive while another recovery is waiting for its replacement
            // handshake. Supersede that stale generation instead of leaving a closed control loaded
            // until the user happens to switch tabs.
            if (recoveryResult == RendererRecoveryResult.Busy &&
                browserProcessClosed &&
                _terminalWebViewRecreationRequired &&
                bindingGeneration == _viewBindingGeneration &&
                ReferenceEquals(vm, _viewModel) &&
                IsLoaded)
            {
                InvalidateRendererRecovery();
                await FailProtocolSessionAndResetRendererCoreAsync(
                    vm,
                    reloadRenderer: false,
                    browserProcessClosed: true,
                    failureMessage).ConfigureAwait(true);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to recover the terminal renderer.");

            if (bindingGeneration == _viewBindingGeneration &&
                ReferenceEquals(vm, _viewModel) &&
                vm.IsTerminalRendererRecoveryCurrent(recoveryEntryLease) &&
                IsCommittedRendererOwner(vm))
            {
                if (IsLoaded)
                {
                    TerminalContentMask.Visibility = Visibility.Visible;
                    EnsureViewModelSubscriptions(vm);
                }
                await RouteTerminalRendererFailureAsync(vm,
                    "Failed to recover the terminal renderer: " + ex.Message).ConfigureAwait(true);
            }
        }
    }

    private async Task<RendererRecoveryResult> FailProtocolSessionAndResetRendererCoreAsync(
        ITerminalSessionViewModel vm,
        bool reloadRenderer,
        bool browserProcessClosed,
        string failureMessage)
    {
        if (Interlocked.CompareExchange(ref _rendererRecoveryInProgress, 1, 0) != 0)
        {
            return RendererRecoveryResult.Busy;
        }

        var recoveryGeneration = Interlocked.Increment(ref _rendererRecoveryGeneration);
        var bindingGeneration = _viewBindingGeneration;
        CoreWebView2? core;
        try { core = TerminalView.CoreWebView2; }
        catch { core = null; }
        var awaitingHandshake = false;
        try
        {
            _handshakeReceived = false;
            _terminalInitializationFailed = browserProcessClosed;
            _handshakeGeneration++;
            TerminalContentMask.Visibility = Visibility.Visible;

            // A raw output tail is not a terminal-state checkpoint: it may omit alternate-screen,
            // parser, or DEC-mode state. Close the protocol before replacing the renderer.
            var vmRecoveryLease = await RouteTerminalRendererFailureAsync(vm, failureMessage)
                .ConfigureAwait(true);
            if (vmRecoveryLease is not { } acceptedRecoveryLease)
            {
                return RendererRecoveryResult.Handled;
            }
            if (!vm.IsTerminalRendererRecoveryCurrent(acceptedRecoveryLease) ||
                !IsRendererRecoveryCurrent(recoveryGeneration, vm, bindingGeneration))
            {
                return RendererRecoveryResult.Stale;
            }

            if (browserProcessClosed)
            {
                // The renderer process is already gone, so no page remains that could complete an
                // ordered retirement. Detach without delaying replacement for the retirement timeout.
                vm.DetachView(core, preserveTerminalContents: false);
            }
            else
            {
                await vm.DetachViewAsync(
                    core,
                    preserveTerminalContents: false).ConfigureAwait(true);
                if (!vm.IsTerminalRendererRecoveryCurrent(acceptedRecoveryLease) ||
                    !IsRendererRecoveryCurrent(recoveryGeneration, vm, bindingGeneration))
                    return RendererRecoveryResult.Stale;
            }
            vm.InitializationRetryRequested -= OnInitializationRetryRequested;

            if (browserProcessClosed || _terminalWebViewRecreationRequired)
            {
                var priorHandshakeGeneration = _activeHandshakeGeneration;
                RecreateTerminalWebViewAfterBrowserExit();
                _terminalWebViewRecreationRequired = false;
                if (!IsRendererRecoveryCurrent(recoveryGeneration, vm, bindingGeneration))
                {
                    return RendererRecoveryResult.Stale;
                }

                _terminalInitializationFailed = false;
                await InitializeWebViewAsync().ConfigureAwait(true);
                awaitingHandshake =
                    IsRendererRecoveryCurrent(recoveryGeneration, vm, bindingGeneration) &&
                    _activeHandshakeGeneration != priorHandshakeGeneration &&
                    !_handshakeReceived &&
                    !_terminalInitializationFailed &&
                    _activeHandshakeBindingGeneration == bindingGeneration;
                return RendererRecoveryResult.Handled;
            }
            if (!IsRendererRecoveryCurrent(recoveryGeneration, vm, bindingGeneration))
            {
                return RendererRecoveryResult.Stale;
            }
            if (!reloadRenderer || core is null)
            {
                return RendererRecoveryResult.Handled;
            }
            if (!ReferenceEquals(core, TerminalView.CoreWebView2))
            {
                return RendererRecoveryResult.Stale;
            }

            _terminalInitializationFailed = false;
            var handshakeGeneration = NavigateTerminalPage(core, bindingGeneration);
            awaitingHandshake = true;
            _ = ScheduleHandshakeTimeoutAsync(vm, handshakeGeneration);
        }
        finally
        {
            if (!awaitingHandshake)
            {
                CompleteRendererRecovery(recoveryGeneration);
            }
        }
        return RendererRecoveryResult.Handled;
    }

    private bool IsRendererRecoveryCurrent(
        int recoveryGeneration,
        ITerminalSessionViewModel vm,
        int bindingGeneration) =>
        Volatile.Read(ref _rendererRecoveryGeneration) == recoveryGeneration &&
        IsCurrentBinding(vm, bindingGeneration);

    private void CompleteRendererRecovery(int recoveryGeneration)
    {
        if (Volatile.Read(ref _rendererRecoveryGeneration) == recoveryGeneration)
        {
            Interlocked.Exchange(ref _rendererRecoveryInProgress, 0);
        }
    }

    private void InvalidateRendererRecovery()
    {
        Interlocked.Increment(ref _rendererRecoveryGeneration);
        Interlocked.Exchange(ref _rendererRecoveryInProgress, 0);
    }

    private void RecreateTerminalWebViewAfterBrowserExit()
    {
        var completesQueuedReplacement = _initializationRecoveryGate.HasQueuedReplacement;
        var failedView = TerminalView;
        var childIndex = TerminalRoot.Children.IndexOf(failedView);
        if (childIndex < 0)
        {
            throw new InvalidOperationException("The failed terminal WebView was no longer attached to its host.");
        }

        // Build and configure the candidate while the old control, subscriptions, and public
        // identity remain untouched. A constructor/property failure therefore leaves a later
        // manual retry with the exact same valid starting point.
        var replacement = CreateConfiguredTerminalWebView(failedView);
        try
        {
            // Keep the old child attached until insertion succeeds. The temporary adjacent slot
            // is synchronous and stays below the existing mask/status overlays.
            TerminalRoot.Children.Insert(childIndex + 1, replacement);
            TerminalRoot.Children.RemoveAt(childIndex);
        }
        catch
        {
            RollbackTerminalWebViewReplacement(failedView, childIndex, replacement);
            throw;
        }

        // Commit only after the visual-tree swap completed. Nothing below can strand TerminalView
        // on a detached/closed control if candidate creation, configuration, or insertion fails.
        var failedProcessCore = _subscribedProcessCore;
        TerminalView = replacement;
        _webViewGeneration++;
        _subscribedProcessCore = null;
        _activeHandshakeSource = null;
        _activeHandshakeGeneration = -1;
        _activeHandshakeBindingGeneration = -1;
        if (completesQueuedReplacement)
        {
            _initializationRecoveryGate.OnReplacementSucceeded();
        }

        try
        {
            if (failedProcessCore is not null)
            {
                failedProcessCore.ProcessFailed -= OnTerminalProcessFailed;
                TryRemoveInitializationMessageHandler(failedProcessCore);
            }
            else if (failedView.CoreWebView2 is { } failedCore)
            {
                TryRemoveInitializationMessageHandler(failedCore);
                failedCore.ProcessFailed -= OnTerminalProcessFailed;
            }
        }
        catch
        {
            // BrowserProcessExited closes CoreWebView2 before this callback; replacement is committed.
        }
        CloseTerminalWebViewBestEffort(failedView);
    }

    private static WebView2 CreateConfiguredTerminalWebView(WebView2 failedView)
    {
        var replacement = new WebView2();
        try
        {
            replacement.DefaultBackgroundColor = failedView.DefaultBackgroundColor;
            replacement.HorizontalAlignment = HorizontalAlignment.Stretch;
            replacement.VerticalAlignment = VerticalAlignment.Stretch;
            replacement.MinHeight = 240;
            replacement.Visibility = Visibility.Visible;
            return replacement;
        }
        catch
        {
            CloseTerminalWebViewBestEffort(replacement);
            throw;
        }
    }

    private void RollbackTerminalWebViewReplacement(
        WebView2 failedView,
        int childIndex,
        WebView2 replacement)
    {
        var replacementIndex = TerminalRoot.Children.IndexOf(replacement);
        if (replacementIndex >= 0)
        {
            TerminalRoot.Children.RemoveAt(replacementIndex);
        }
        if (TerminalRoot.Children.IndexOf(failedView) < 0)
        {
            TerminalRoot.Children.Insert(
                Math.Min(childIndex, TerminalRoot.Children.Count),
                failedView);
        }
        CloseTerminalWebViewBestEffort(replacement);
    }

    private static void CloseTerminalWebViewBestEffort(WebView2 view)
    {
        try { view.Close(); }
        catch { /* a failed browser process or partial candidate may already be closed */ }
    }

    private void LogTerminalReady(TerminalSize size)
    {
        _logger.LogInformation(
            "Terminal page ready with geometry {Columns}x{Rows}.",
            size.Columns,
            size.Rows);
    }

    private void LogTerminalInitializationFailure(string detail)
    {
        _logger.LogError("Terminal page reported initialization failure: {Detail}", detail);
    }

    private void LogWebViewInitializationFailure(Exception ex, string userDataFolder)
    {
        var baseDirectory = AppContext.BaseDirectory;
        var loaderPath = Path.Combine(baseDirectory, "WebView2Loader.dll");
        _logger.LogError(
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

    private static ILogger<SshTerminalView> ResolveLogger()
    {
        try
        {
            var logger = App.Current?.Services?.GetService<ILogger<SshTerminalView>>();
            return logger is null
                ? NullLogger<SshTerminalView>.Instance
                : new NonThrowingLogger<SshTerminalView>(logger);
        }
        catch
        {
            return NullLogger<SshTerminalView>.Instance;
        }
    }

    // The VM outlives the view (it lives in ShellViewModel.Tabs across navigations),
    // so we must unsubscribe here or every navigation accumulates a stale handler
    // that keeps the old SshTerminalView alive and double-runs init on retry.
    // Also tell the VM to drop the bridge — otherwise background SSH output keeps
    // posting to a disposed WebView2 until reconnect or tab close.
    private async void OnUnloaded(object sender, RoutedEventArgs e)
    {
        var retiringRendererIdentity = TryGetTerminalRendererIdentity();
        var retiringViewModel = _viewModel;

        // Prime the cover for a possible same-control reload before removing WebView2 from layout.
        TerminalContentMask.Visibility = Visibility.Visible;

        // Collapse the WebView2 BEFORE detaching: WinUI 3's TabView leaving parent visibility
        // to its child doesn't reliably suspend WebView2's composition surface, so a
        // background tab still painting (heavy SSH output, or an xterm.js re-render fired
        // by text selection) can bleed pixels into the selected tab. Setting Visibility on
        // the WebView2 element itself propagates to its render surface.
        // (RdpSurfaceHost solves the equivalent airspace problem differently — it reparents
        // the ActiveX HWND via DetachView — so the mechanism is unique to this file.)
        TerminalView.Visibility = Visibility.Collapsed;

        _viewBindingGeneration++;
        var unloadBindingGeneration = _viewBindingGeneration;
        _handshakeGeneration++;
        InvalidateRendererRecovery();
        _rendererUnresponsiveEvents = 0;
        _lastRendererUnresponsiveTick = 0;
        if (retiringViewModel is not null)
        {
            retiringViewModel.InitializationRetryRequested -= OnInitializationRetryRequested;
            retiringViewModel.TerminalRendererRecoveryRequested -= OnTerminalRendererRecoveryRequested;
            try
            {
                await retiringViewModel.DetachViewAsync(
                    retiringRendererIdentity).ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Terminal bridge retirement failed during unload.");
            }
        }

        if (IsLoaded || unloadBindingGeneration != _viewBindingGeneration) return;
        try
        {
            TryRemoveInitializationMessageHandler(
                retiringRendererIdentity as CoreWebView2);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Terminal WebView was already closed during unload.");
        }
    }
}
