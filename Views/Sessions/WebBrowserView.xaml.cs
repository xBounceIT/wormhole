using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.Web.WebView2.Core;
using Wormhole.Helpers;
using Wormhole.Services;
using Wormhole.Services.BitwardenBrowser;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;
using WinUIWebView2 = Microsoft.UI.Xaml.Controls.WebView2;

namespace Wormhole.Views.Sessions;

/// <summary>
/// Hosts the embedded WebView2 browser for an <see cref="HttpSessionViewModel"/> (HTTP/HTTPS
/// connections). The VM owns the connection lifecycle and hands the view a resolved
/// <see cref="HttpConnectionTarget"/> via <see cref="HttpSessionViewModel.NavigateRequested"/>; the
/// view creates the WebView2 with the right environment (a SOCKS5-proxied one when the target carries a
/// proxy endpoint, else a shared default) and reports the navigation result back to the VM.
/// </summary>
// CA1001 suppressed deliberately (same convention as SshSessionViewModel): the only IDisposable field
// is the _createGate SemaphoreSlim, which holds no OS handle unless AvailableWaitHandle is touched
// (it isn't). A UserControl has no deterministic dispose hook in WinUI; making it IDisposable buys
// nothing here.
#pragma warning disable CA1001
public sealed partial class WebBrowserView : UserControl
#pragma warning restore CA1001
{
    // Shared environment for non-proxied web tabs (direct connections + loopback port-forwards). A
    // proxied (SOCKS) tab can't use it — Chromium proxy args are fixed at environment creation — so it
    // builds its own. Cached process-wide; concurrent first callers race via CompareExchange.
    private static CoreWebView2Environment? s_sharedEnvironment;

    private HttpSessionViewModel? _viewModel;
    private WinUIWebView2? _webView;
    private CoreWebView2Environment? _currentEnvironment;
    private HttpConnectionTarget? _currentTarget;
    private Uri? _bitwardenPopupUri;
    private string? _bitwardenIconPath;
    private bool _bitwardenExtensionReady;
    private string? _bitwardenProfileUserDataFolder;
    // Temp user-data folder backing this tab's isolated environment (a SOCKS-proxy or ignore-cert tab);
    // deleted (best-effort) when that WebView2 is torn down. Null for shared-environment (plain) tabs.
    private string? _isolatedUserDataFolder;
    // Bumped on every CreateAndNavigate (and on unload) so a slower in-flight creation that lost the
    // race bails instead of binding a stale WebView2.
    private int _createGeneration;
    // Serializes CreateAndNavigateAsync so two overlapping creates (initial connect racing a re-attach,
    // a Retry, etc.) can't interleave their teardown/build on the shared _webView field — without it a
    // losing generation's DisposeWebView() would tear down the winner's control. Never disposed (holds
    // no OS handle unless AvailableWaitHandle is touched, which it isn't), same convention as
    // SshSessionViewModel._commandGate.
    private readonly SemaphoreSlim _createGate = new(1, 1);
    // True between issuing the initial Navigate and its first NavigationCompleted. Gates the
    // Connected/Failed report so later in-page navigations (link clicks) can't flip the tab's status.
    private bool _awaitingInitialNavigation;

    public WebBrowserView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Restore the surface that OnUnloaded collapsed to suppress airspace bleed in background tabs.
        // The WebView2 itself is only restored when this view still belongs to the same session: on a
        // VM change the control is stale (about to be torn down below) and re-showing it would flash
        // the previous session's page during the gated-teardown await.
        WebViewHost.Visibility = Visibility.Visible;
        var newVm = DataContext as HttpSessionViewModel;
        var vmChanged = newVm is not null && !ReferenceEquals(newVm, _viewModel);
        if (!vmChanged && _webView is not null) _webView.Visibility = Visibility.Visible;

        if (newVm is null) return;

        if (vmChanged)
        {
            if (_viewModel is not null) _viewModel.NavigateRequested -= OnNavigateRequested;
            _viewModel = newVm;

            // WinUI's TabView recycles item containers, so this same view instance can be rebound from
            // a closed session's VM to a new one (close a web tab, open the next). Any WebView2 still
            // attached was built for the PREVIOUS session: if we leave it, the live-WebView guard below
            // short-circuits and the new session never runs AttachAsync — its "use tunnel" route prompt
            // never appears and the tab is stuck on the connecting spinner until the app is restarted.
            // Bump the generation so an in-flight create for the old VM bails (and disposes after
            // itself at its own mismatch checks), clear the initial-navigation flag so a stray late
            // NavigationCompleted from the old core can't report against the new VM, hide the stale
            // surface, then tear the old control down UNDER the create gate — disposing outside the
            // gate could Close() a control the old create is still inside EnsureCoreWebView2Async on,
            // or delete an isolated user-data folder its environment creation is using (see the
            // _createGate comment). SshTerminalView guards the same recycle hazard by resetting its
            // per-VM handshake state on a VM change.
            var generation = ++_createGeneration;
            _awaitingInitialNavigation = false;
            if (_webView is not null) _webView.Visibility = Visibility.Collapsed;

            await _createGate.WaitAsync().ConfigureAwait(true);
            try
            {
                // Superseded while waiting (an unload, or a newer rebind queued behind the gate):
                // teardown belongs to whoever owns the newer generation — the old VM's in-flight
                // create disposes after itself when it resumes and sees the mismatch.
                if (generation == _createGeneration) await DisposeWebViewAsync().ConfigureAwait(true);
            }
            finally
            {
                _createGate.Release();
            }
            // A newer Loaded/unload took over while we waited on the gate; let it drive the connect
            // (and the toolbar refresh).
            if (generation != _createGeneration) return;
            // Clear the previous session's URL and history state out of the toolbar while the new
            // session connects (the create flow refreshes it once navigation starts).
            UpdateToolbar();
        }
        // Always (re)subscribe — OnUnloaded drops it on every unload so a discarded view instance
        // (Sessions↔Settings round-trip) is left with no VM→view edge and is garbage-collected (its
        // WebView2 released with it, the same way SshTerminalView relies on GC for its terminal control).
        // newVm == _viewModel here on both paths; using it keeps nullable flow analysis satisfied.
        newVm.NavigateRequested -= OnNavigateRequested;
        newVm.NavigateRequested += OnNavigateRequested;

        // A live WebView2 already rendering this session (tab switch on the same view instance): keep it
        // so page state is preserved. Only (re)connect when there is nothing live to rebind to.
        if (_webView?.CoreWebView2 is not null) return;

        try
        {
            await newVm.AttachAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            newVm.ReportFailure(ex.Message);
        }
    }

    private async void OnUnloaded(object sender, RoutedEventArgs e)
    {
        // Collapse the surface so a background tab still painting can't bleed into the selected tab
        // (same airspace issue SshTerminalView guards against). The live WebView2 is kept so a same-
        // instance reload (tab content recycle) can rebind in OnLoaded without reloading the page.
        WebViewHost.Visibility = Visibility.Collapsed;
        if (_webView is not null) _webView.Visibility = Visibility.Collapsed;

        var vm = _viewModel;
        // Invalidate any in-flight create so it bails instead of binding/leaking a WebView2 after the
        // view goes away (e.g. the tab is closed mid-connect). Then drop the VM subscription so a
        // truly-discarded instance is unrooted and GC-eligible (see OnLoaded).
        var generation = ++_createGeneration;
        if (vm is not null) vm.NavigateRequested -= OnNavigateRequested;

        if (vm is null || IsTabStillOpen(vm)) return;

        try
        {
            await _createGate.WaitAsync().ConfigureAwait(true);
            try
            {
                if (generation == _createGeneration)
                {
                    await DisposeWebViewAsync().ConfigureAwait(true);
                }
            }
            finally
            {
                _createGate.Release();
            }
        }
        catch (Exception ex)
        {
            LogWarning(ex, "Failed to dispose a closed HTTPS WebView2 tab.");
        }
    }

    private static bool IsTabStillOpen(HttpSessionViewModel vm)
    {
        var shell = App.Current?.Services?.GetService<ShellViewModel>();
        return shell is null || shell.Tabs.Contains(vm);
    }

    private async void OnNavigateRequested(HttpConnectionTarget target)
    {
        // Capture the VM this navigate belongs to. If the container is recycled onto a different
        // session while the create is in flight, _viewModel is reassigned — a failure from the
        // superseded build must land on the session that requested it, not the new one (whose
        // Connecting status would accept the report and fail a healthy connect).
        var vm = _viewModel;
        try
        {
            await CreateAndNavigateAsync(target).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            LogError(ex, "Failed to create or navigate the web view.");
            vm?.ReportNavigationFailed("Failed to start the browser: " + ex.Message);
        }
    }

    private async Task CreateAndNavigateAsync(HttpConnectionTarget target)
    {
        // Bump the generation BEFORE queueing on the gate so an older create still waiting its turn sees
        // it has been superseded and bails. The gate then serializes the actual teardown/build so only
        // one generation owns _webView at a time.
        var generation = ++_createGeneration;
        await _createGate.WaitAsync().ConfigureAwait(true);
        try
        {
            // Superseded while we waited for the gate: a newer create (or an unload) bumped the
            // generation. We created nothing yet, so leave the current _webView for the winner.
            if (generation != _createGeneration) return;

            // Tear down any previous control + isolated env first (Retry, or a re-navigate whose tunnel
            // got a different SOCKS port, needs a fresh environment). Safe: we hold the gate, so _webView
            // is either the prior winner's control or null.
            await DisposeWebViewAsync().ConfigureAwait(true);

            var environmentSelection = await ResolveEnvironmentAsync(target).ConfigureAwait(true);
            // ResolveEnvironmentAsync may have created an isolated user-data folder + environment;
            // DisposeWebViewAsync's CleanupIsolatedUserDataFolder reclaims the folder if we bail here.
            if (generation != _createGeneration) { await DisposeWebViewAsync().ConfigureAwait(true); return; }

            var webView = new WinUIWebView2
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch,
            };
            // Match the dark surface so there's no white flash before the page paints.
            try { webView.DefaultBackgroundColor = Windows.UI.Color.FromArgb(0xFF, 0x0c, 0x0c, 0x0c); }
            catch (Exception ex) { LogDebug(ex, "Setting WebView2 DefaultBackgroundColor failed (cosmetic)."); }

            WebViewHost.Children.Clear();
            WebViewHost.Children.Add(webView);
            _webView = webView;
            _currentTarget = null;

            // EnsureCoreWebView2Async returns a WinRT IAsyncAction (no ConfigureAwait); it already resumes
            // on the UI thread.
            await webView.EnsureCoreWebView2Async(environmentSelection.Environment);
            if (generation != _createGeneration)
            {
                await DisposeWebViewAsync().ConfigureAwait(true);
                return;
            }

            var core = webView.CoreWebView2
                ?? throw new InvalidOperationException("WebView2 initialization completed without a CoreWebView2 instance.");
            _currentEnvironment = environmentSelection.Environment;

            core.Settings.AreDevToolsEnabled = Debugger.IsAttached;
            // A browser surface benefits from the default context menu (copy/paste, open link, save).
            core.Settings.AreDefaultContextMenusEnabled = true;
            // No SmartScreen reputation checks: these tabs render private appliance/firewall admin
            // pages whose URLs shouldn't be sent to Microsoft — and on a tunneled tab the check itself
            // would route through the customer's VPN. (Why the supported setting and not a browser
            // flag: see WebViewBrowserArguments.) Guarded so an older WebView2 Runtime without the
            // setting can't fail the tab; logged at Warning because a swallowed failure here means
            // appliance URLs DO keep flowing to SmartScreen — Debug would be invisible at the
            // configured Information minimum level.
            try { core.Settings.IsReputationCheckingRequired = false; }
            catch (Exception ex) { LogWarning(ex, "Disabling SmartScreen reputation checking failed (runtime too old?); appliance URLs will still be sent to SmartScreen."); }

            if (environmentSelection.BitwardenExtensionPath is { } extensionPath
                && environmentSelection.UserDataFolder is { } extensionUserDataFolder)
            {
                _bitwardenProfileUserDataFolder = extensionUserDataFolder;
                await TryEnsureBitwardenExtensionAsync(core, extensionPath, extensionUserDataFolder).ConfigureAwait(true);
            }

            if (target.IgnoreCertErrors)
            {
                core.ServerCertificateErrorDetected -= OnServerCertificateErrorDetected;
                core.ServerCertificateErrorDetected += OnServerCertificateErrorDetected;
            }
            core.NavigationCompleted -= OnNavigationCompleted;
            core.NavigationCompleted += OnNavigationCompleted;
            core.SourceChanged -= OnCoreSourceChanged;
            core.SourceChanged += OnCoreSourceChanged;
            core.HistoryChanged -= OnCoreHistoryChanged;
            core.HistoryChanged += OnCoreHistoryChanged;
            core.NewWindowRequested -= OnNewWindowRequested;
            core.NewWindowRequested += OnNewWindowRequested;

            UpdateToolbar();
            _awaitingInitialNavigation = true;
            _currentTarget = target;
            core.Navigate(target.NavigateUri.ToString());
        }
        finally
        {
            _createGate.Release();
        }
    }

    private async Task<BrowserEnvironmentSelection> ResolveEnvironmentAsync(HttpConnectionTarget target)
    {
        // Don't create a user-data folder/environment until the startup sweep of orphaned web folders
        // has finished, or it could delete the folder we just created (completed instantly after the
        // first wait).
        await App.WebBrowserDataCleanup.ConfigureAwait(true);

        await TryUpdateBitwardenExtensionIfStaleAsync(target).ConfigureAwait(true);

        var browserArguments = BitwardenBrowserWebViewProfile.BuildBrowserArguments(target.Socks5Proxy);
        if (TryGetBitwardenExtensionInstall(target) is { } bitwardenInstall)
        {
            var folder = BitwardenBrowserWebViewProfile.GetUserDataFolder(browserArguments, target.IgnoreCertErrors);
            Directory.CreateDirectory(folder);
            var options = new CoreWebView2EnvironmentOptions
            {
                AdditionalBrowserArguments = browserArguments,
                AreBrowserExtensionsEnabled = true,
            };
            var environment = await CoreWebView2Environment.CreateWithOptionsAsync(null, folder, options);
            return new BrowserEnvironmentSelection(environment, bitwardenInstall.ExtensionPath, folder);
        }

        // A web tab needs its OWN environment (dedicated user-data folder + browser process) when it
        // either routes through a SOCKS5 proxy (Chromium proxy args are fixed at env creation) OR
        // ignores certificate errors. The cert case is about isolation, not proxying: WebView2 caches an
        // AlwaysAllow server-certificate decision for the lifetime of the environment, so if an
        // ignore-cert tab shared the default environment, a LATER tab to the same host with the toggle
        // OFF would silently inherit that allow and skip validation (its ServerCertificateErrorDetected
        // wouldn't even fire). Isolating ignore-cert sessions scopes the bypass to the connection that
        // opted in; plain (toggle-off) tabs use the shared environment, which never holds an allow.
        if (target.Socks5Proxy is not null || target.IgnoreCertErrors)
        {
            var folder = AppPaths.GetWebBrowserIsolatedUserDataDirectory(Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            _isolatedUserDataFolder = folder;
            var options = new CoreWebView2EnvironmentOptions
            {
                AdditionalBrowserArguments = browserArguments,
            };
            var environment = await CoreWebView2Environment.CreateWithOptionsAsync(null, folder, options);
            return new BrowserEnvironmentSelection(environment, null, null);
        }

        return new BrowserEnvironmentSelection(await GetOrCreateSharedEnvironmentAsync().ConfigureAwait(true), null, null);
    }

    private static async Task<CoreWebView2Environment> GetOrCreateSharedEnvironmentAsync()
    {
        var existing = Volatile.Read(ref s_sharedEnvironment);
        if (existing is not null) return existing;

        // Argument-keyed folder (not the root): a concurrently-running build with different browser
        // arguments would otherwise make environment creation fail with ERROR_INVALID_STATE — see
        // WebViewBrowserArguments.KeyedSharedFolderName. Stale keyed folders are removed by the
        // startup wipe of the webview2-web root, so no sweep is needed here.
        var folder = AppPaths.GetWebBrowserSharedUserDataDirectory();
        Directory.CreateDirectory(folder);
        // Same background-traffic hardening as the isolated environments: appliance GUIs never need
        // Chromium's background services (see WebViewBrowserArguments for the per-switch rationale).
        var created = await CoreWebView2Environment.CreateWithOptionsAsync(
            null, folder, new CoreWebView2EnvironmentOptions
            {
                AdditionalBrowserArguments = WebViewBrowserArguments.Build(socks5Proxy: null),
            });
        var winner = Interlocked.CompareExchange(ref s_sharedEnvironment, created, null);
        return winner ?? created;
    }

    private static async Task TryUpdateBitwardenExtensionIfStaleAsync(HttpConnectionTarget target)
    {
        if (!BitwardenBrowserWebViewProfile.IsHttpsTarget(target.NavigateUri, target.OriginalUri)) return;

        var settings = App.Current?.Services?.GetService<IAppSettingsService>();
        if (settings?.Current.EnableBitwardenBrowserExtension != true) return;

        var updateService = App.Current?.Services?.GetService<IBitwardenBrowserExtensionUpdateService>();
        if (updateService is null) return;

        try
        {
            await updateService.UpdateIfStaleAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            LogWarning(ex, "Bitwarden browser extension stale auto-update failed before HTTPS tab creation.");
        }
    }

    private static BitwardenBrowserExtensionInstall? TryGetBitwardenExtensionInstall(HttpConnectionTarget target)
    {
        if (!BitwardenBrowserWebViewProfile.IsHttpsTarget(target.NavigateUri, target.OriginalUri)) return null;

        var settings = App.Current?.Services?.GetService<IAppSettingsService>();
        if (settings?.Current.EnableBitwardenBrowserExtension != true) return null;

        var installer = App.Current?.Services?.GetService<IBitwardenBrowserExtensionInstaller>();
        return installer?.GetConfiguredInstall();
    }

    private async Task TryEnsureBitwardenExtensionAsync(CoreWebView2 core, string extensionPath, string userDataFolder)
    {
        _bitwardenExtensionReady = false;
        _bitwardenPopupUri = null;
        _bitwardenIconPath = null;
        UpdateBitwardenButtonIcon();
        try
        {
            var activation = await EnsureBitwardenExtensionAsync(core, extensionPath, userDataFolder).ConfigureAwait(true);
            _bitwardenPopupUri = activation.PopupUri;
            _bitwardenIconPath = activation.IconPath;
            UpdateBitwardenButtonIcon();
            _bitwardenExtensionReady = true;
        }
        catch (Exception ex)
        {
            LogWarning(ex, "Bitwarden browser extension could not be loaded for this HTTPS tab.");
            _bitwardenIconPath = null;
            UpdateBitwardenButtonIcon();
        }
        finally
        {
            UpdateToolbar();
        }
    }

    private static async Task<BitwardenExtensionActivation> EnsureBitwardenExtensionAsync(
        CoreWebView2 core,
        string extensionPath,
        string userDataFolder)
    {
        var manifest = BitwardenBrowserExtensionManifest.Read(extensionPath);
        var markerPath = BitwardenBrowserExtensionMarker.GetPath(userDataFolder);
        var installedExtensions = await core.Profile.GetBrowserExtensionsAsync();
        CoreWebView2BrowserExtension? extension = null;

        if (BitwardenBrowserExtensionMarker.TryReadInstalledExtensionId(markerPath, extensionPath, out var extensionId))
        {
            extension = FindInstalledBitwardenExtension(installedExtensions, extensionId);
        }

        if (extension is null)
        {
            await RemoveStaleBitwardenExtensionsAsync(installedExtensions, markerPath).ConfigureAwait(true);
            extension = await core.Profile.AddBrowserExtensionAsync(extensionPath);
            Directory.CreateDirectory(userDataFolder);
            await BitwardenBrowserExtensionMarker.WriteAsync(markerPath, extensionPath, extension.Id).ConfigureAwait(true);
        }

        if (!extension.IsEnabled)
        {
            await extension.EnableAsync(true);
        }

        return new BitwardenExtensionActivation(
            extension.Id,
            BuildBitwardenPopupUri(extension.Id, manifest.DefaultPopup),
            manifest.IconPath);
    }

    private static CoreWebView2BrowserExtension? FindInstalledBitwardenExtension(
        IReadOnlyList<CoreWebView2BrowserExtension> extensions,
        string? extensionId)
    {
        if (string.IsNullOrWhiteSpace(extensionId)) return null;
        return extensions.FirstOrDefault(extension =>
            string.Equals(extension.Id, extensionId, StringComparison.Ordinal));
    }

    private static async Task RemoveStaleBitwardenExtensionsAsync(
        IReadOnlyList<CoreWebView2BrowserExtension> extensions,
        string markerPath)
    {
        var staleIds = new HashSet<string>(StringComparer.Ordinal);
        if (BitwardenBrowserExtensionMarker.TryReadInstalledExtensionId(markerPath, out var markerExtensionId)
            && markerExtensionId is not null)
        {
            staleIds.Add(markerExtensionId);
        }

        foreach (var installed in extensions)
        {
            if (IsBitwardenExtensionName(installed.Name)) staleIds.Add(installed.Id);
        }

        foreach (var installed in extensions.Where(extension => staleIds.Contains(extension.Id)))
        {
            await installed.RemoveAsync();
        }
    }

    private static bool IsBitwardenExtensionName(string name) =>
        name.Contains("Bitwarden", StringComparison.OrdinalIgnoreCase);

    private static Uri? BuildBitwardenPopupUri(string extensionId, string? popupPath)
    {
        if (string.IsNullOrWhiteSpace(extensionId) || string.IsNullOrWhiteSpace(popupPath)) return null;
        var normalizedPopupPath = popupPath.TrimStart('/');
        return Uri.TryCreate($"chrome-extension://{extensionId}/{normalizedPopupPath}", UriKind.Absolute, out var uri)
            ? uri
            : null;
    }

    private void OnServerCertificateErrorDetected(CoreWebView2 sender, CoreWebView2ServerCertificateErrorDetectedEventArgs args)
    {
        // The per-connection "ignore certificate errors" opt-in is on (we only subscribe in that case):
        // proceed past self-signed / name-mismatch / untrusted-chain certs for this host.
        args.Action = CoreWebView2ServerCertificateErrorAction.AlwaysAllow;
    }

    private void OnNavigationCompleted(CoreWebView2 sender, CoreWebView2NavigationCompletedEventArgs args)
    {
        UpdateToolbar();

        // Only the FIRST top-level navigation decides the tab's Connected/Failed status. Later
        // navigations (the user clicking around the appliance GUI) must not flip a healthy tab to Failed.
        if (!_awaitingInitialNavigation) return;

        if (args.IsSuccess)
        {
            _awaitingInitialNavigation = false;
            _viewModel?.ReportNavigationSucceeded();
            return;
        }

        // A cancel (e.g. an immediate client-side redirect) isn't a real failure — keep waiting for the
        // navigation that actually completes.
        if (args.WebErrorStatus == CoreWebView2WebErrorStatus.OperationCanceled) return;

        _awaitingInitialNavigation = false;
        _viewModel?.ReportNavigationFailed(
            DescribeWebError(args.WebErrorStatus), IsGenericTransportFailure(args.WebErrorStatus));
    }

    // Statuses Chromium reports when the connection itself died rather than the page content. For a
    // SOCKS-proxied tab these are how a sidecar dial failure surfaces — Chromium gets a SOCKS error
    // reply (ERR_SOCKS_CONNECTION_FAILED) and WebView2 collapses it into Unknown — so the VM follows
    // up with an in-tunnel reachability probe to produce an actionable message. Cert statuses are
    // deliberately excluded: those mean the target WAS reached.
    private static bool IsGenericTransportFailure(CoreWebView2WebErrorStatus status) => status is
        CoreWebView2WebErrorStatus.Unknown
        or CoreWebView2WebErrorStatus.CannotConnect
        or CoreWebView2WebErrorStatus.ServerUnreachable
        or CoreWebView2WebErrorStatus.Timeout
        or CoreWebView2WebErrorStatus.ConnectionAborted
        or CoreWebView2WebErrorStatus.ConnectionReset
        or CoreWebView2WebErrorStatus.Disconnected
        or CoreWebView2WebErrorStatus.HostNameNotResolved;

    private static string DescribeWebError(CoreWebView2WebErrorStatus status) => status switch
    {
        CoreWebView2WebErrorStatus.CertificateCommonNameIsIncorrect
            or CoreWebView2WebErrorStatus.CertificateExpired
            or CoreWebView2WebErrorStatus.ClientCertificateContainsErrors
            or CoreWebView2WebErrorStatus.CertificateRevoked
            or CoreWebView2WebErrorStatus.CertificateIsInvalid =>
            "The server's certificate could not be validated. If this appliance uses a self-signed "
            + "certificate, enable “Ignore certificate errors” for this connection.",
        CoreWebView2WebErrorStatus.HostNameNotResolved =>
            "The host name could not be resolved.",
        CoreWebView2WebErrorStatus.ServerUnreachable =>
            "The server is unreachable.",
        CoreWebView2WebErrorStatus.Timeout =>
            "The connection timed out.",
        CoreWebView2WebErrorStatus.ConnectionAborted
            or CoreWebView2WebErrorStatus.ConnectionReset =>
            "The connection was reset.",
        CoreWebView2WebErrorStatus.Disconnected =>
            "The connection was lost.",
        _ => $"Navigation failed ({status}).",
    };

    private void OnCoreSourceChanged(CoreWebView2 sender, CoreWebView2SourceChangedEventArgs args) => UpdateToolbar();

    private void OnCoreHistoryChanged(CoreWebView2 sender, object args) => UpdateToolbar();

    private void OnNewWindowRequested(CoreWebView2 sender, CoreWebView2NewWindowRequestedEventArgs args)
    {
        // Never let WebView2 create an unmanaged popup window: it would not be bound to this tab's
        // per-session proxy/cert environment and could bypass the selected tunnel route.
        args.Handled = true;

        var navigationUri = WebViewNewWindowNavigation.GetInSessionNavigationUri(
            args.Uri,
            _currentTarget?.NavigateUri,
            _currentTarget?.OriginalUri);
        if (navigationUri is null)
        {
            LogDebug("Suppressed WebView2 new-window request without a navigable target.");
            return;
        }

        try
        {
            sender.Navigate(navigationUri);
        }
        catch (Exception ex)
        {
            LogDebug(ex, "WebView2 new-window in-session navigation threw.");
        }
    }

    private void UpdateToolbar()
    {
        var core = _webView?.CoreWebView2;
        BackButton.IsEnabled = core?.CanGoBack ?? false;
        ForwardButton.IsEnabled = core?.CanGoForward ?? false;
        AddressText.Text = core?.Source ?? string.Empty;
        BitwardenButton.Visibility = _bitwardenExtensionReady && _bitwardenPopupUri is not null
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void UpdateBitwardenButtonIcon()
    {
        if (_bitwardenIconPath is { } iconPath && File.Exists(iconPath))
        {
            try
            {
                BitwardenIconImage.Source = new BitmapImage(new Uri(Path.GetFullPath(iconPath)));
                BitwardenIconImage.Visibility = Visibility.Visible;
                BitwardenFallbackIcon.Visibility = Visibility.Collapsed;
                return;
            }
            catch (Exception ex)
            {
                LogDebug(ex, "Could not load Bitwarden extension icon; using fallback toolbar icon.");
            }
        }

        BitwardenIconImage.Source = null;
        BitwardenIconImage.Visibility = Visibility.Collapsed;
        BitwardenFallbackIcon.Visibility = Visibility.Visible;
    }

    private void OnBackClick(object sender, RoutedEventArgs e)
    {
        try { if (_webView?.CoreWebView2 is { CanGoBack: true } core) core.GoBack(); }
        catch (Exception ex) { LogDebug(ex, "WebView2 GoBack threw."); }
    }

    private void OnForwardClick(object sender, RoutedEventArgs e)
    {
        try { if (_webView?.CoreWebView2 is { CanGoForward: true } core) core.GoForward(); }
        catch (Exception ex) { LogDebug(ex, "WebView2 GoForward threw."); }
    }

    private void OnReloadClick(object sender, RoutedEventArgs e)
    {
        try { _webView?.CoreWebView2?.Reload(); }
        catch (Exception ex) { LogDebug(ex, "WebView2 Reload threw."); }
    }

    private async void OnBitwardenClick(object sender, RoutedEventArgs e)
    {
        var environment = _currentEnvironment;
        var popupUri = _bitwardenPopupUri;
        if (environment is null || popupUri is null) return;

        var popupWebView = new WinUIWebView2
        {
            Width = 380,
            Height = 560,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch,
        };
        try { popupWebView.DefaultBackgroundColor = Windows.UI.Color.FromArgb(0xFF, 0x1f, 0x1f, 0x1f); }
        catch (Exception ex) { LogDebug(ex, "Setting Bitwarden popup background failed (cosmetic)."); }

        var flyout = new Flyout
        {
            Content = popupWebView,
            Placement = FlyoutPlacementMode.BottomEdgeAlignedRight,
            FlyoutPresenterStyle = CreateBitwardenFlyoutPresenterStyle(),
        };
        flyout.Closed += (_, _) =>
        {
            try { popupWebView.Close(); }
            catch (Exception ex) { LogDebug(ex, "Bitwarden popup WebView2 Close threw."); }
        };
        flyout.Opened += async (_, _) =>
        {
            try
            {
                await popupWebView.EnsureCoreWebView2Async(environment);
                if (popupWebView.CoreWebView2 is { } core)
                {
                    core.Settings.AreDevToolsEnabled = Debugger.IsAttached;
                    core.Settings.AreDefaultContextMenusEnabled = true;
                    core.Navigate(popupUri.ToString());
                }
            }
            catch (Exception ex)
            {
                LogWarning(ex, "Failed to open Bitwarden extension popup.");
                flyout.Content = new TextBlock
                {
                    Text = "Could not open Bitwarden.",
                    Margin = new Thickness(12),
                    TextWrapping = TextWrapping.Wrap,
                };
            }
        };
        flyout.ShowAt(BitwardenButton);
    }

    private static Style CreateBitwardenFlyoutPresenterStyle()
    {
        var style = new Style(typeof(FlyoutPresenter));
        style.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(0)));
        return style;
    }
    private async Task DisposeWebViewAsync()
    {
        var webView = _webView;
        var target = _currentTarget;
        var shouldClearBitwardenWebData = _bitwardenProfileUserDataFolder is not null;
        _webView = null;
        _currentEnvironment = null;
        _currentTarget = null;
        _bitwardenPopupUri = null;
        _bitwardenExtensionReady = false;
        _bitwardenProfileUserDataFolder = null;
        if (webView is not null)
        {
            var core = webView.CoreWebView2;
            if (core is not null)
            {
                core.ServerCertificateErrorDetected -= OnServerCertificateErrorDetected;
                core.NavigationCompleted -= OnNavigationCompleted;
                core.SourceChanged -= OnCoreSourceChanged;
                core.HistoryChanged -= OnCoreHistoryChanged;
                core.NewWindowRequested -= OnNewWindowRequested;

                if (shouldClearBitwardenWebData && target is not null)
                {
                    await ClearBitwardenWebDataAsync(core, target).ConfigureAwait(true);
                }
            }
            try { webView.Close(); }
            catch (Exception ex) { LogDebug(ex, "WebView2 Close threw during teardown."); }
            WebViewHost.Children.Remove(webView);
        }
        CleanupIsolatedUserDataFolder();
        _bitwardenIconPath = null;
        UpdateBitwardenButtonIcon();
    }

    private static async Task ClearBitwardenWebDataAsync(CoreWebView2 core, HttpConnectionTarget target)
    {
        foreach (var origin in GetWebOrigins(target, core.Source))
        {
            try
            {
                var payload = JsonSerializer.Serialize(new
                {
                    origin,
                    storageTypes = "all",
                });
                await core.CallDevToolsProtocolMethodAsync("Storage.clearDataForOrigin", payload);
            }
            catch (Exception ex)
            {
                LogDebug(ex, "Could not clear origin storage for a Bitwarden-enabled HTTPS tab.");
            }
        }
    }

    private static HashSet<string> GetWebOrigins(HttpConnectionTarget target, string? currentSource)
    {
        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddOrigin(target.NavigateUri);
        if (target.OriginalUri is not null) AddOrigin(target.OriginalUri);
        if (Uri.TryCreate(currentSource, UriKind.Absolute, out var sourceUri)) AddOrigin(sourceUri);
        return origins;

        void AddOrigin(Uri uri)
        {
            if (uri.Scheme is not ("http" or "https")) return;
            origins.Add(uri.GetLeftPart(UriPartial.Authority));
        }
    }

    private void CleanupIsolatedUserDataFolder()
    {
        var folder = _isolatedUserDataFolder;
        _isolatedUserDataFolder = null;
        if (folder is null) return;
        try
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
        }
        catch (Exception ex)
        {
            // The browser process may still hold a lock immediately after Close(); the orphaned temp
            // folder is harmless and can be swept on a later run. Best-effort only.
            LogDebug(ex, "Could not delete isolated web env user-data folder (browser may still hold a lock).");
        }
    }

    private sealed record BrowserEnvironmentSelection(
        CoreWebView2Environment Environment,
        string? BitwardenExtensionPath,
        string? UserDataFolder);

    private sealed record BitwardenExtensionActivation(string Id, Uri? PopupUri, string? IconPath);

    private static void LogError(Exception ex, string message) =>
        App.Current?.Services?.GetService<ILogger<WebBrowserView>>()?.LogError(ex, "{Message}", message);

    private static void LogWarning(Exception ex, string message) =>
        App.Current?.Services?.GetService<ILogger<WebBrowserView>>()?.LogWarning(ex, "{Message}", message);

    private static void LogDebug(Exception ex, string message) =>
        App.Current?.Services?.GetService<ILogger<WebBrowserView>>()?.LogDebug(ex, "{Message}", message);

    private static void LogDebug(string message) =>
        App.Current?.Services?.GetService<ILogger<WebBrowserView>>()?.LogDebug("{Message}", message);
}
