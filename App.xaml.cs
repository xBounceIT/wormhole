using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Serilog;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Backup;
using Wormhole.Services.Mcp;
using Wormhole.Services.MRemoteNg;
using Wormhole.Services.Rdp;
using Wormhole.Services.Security;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;
using Wormhole.Services.Tunneling.AzureVpn;
using Wormhole.Services.Tunneling.CiscoSecureClient;
using Wormhole.Services.Tunneling.Fortinet;
using Wormhole.Services.Tunneling.OpenVpn;
using Wormhole.Services.Tunneling.Stormshield;
using Wormhole.Services.Tunneling.Watchguard;
using Wormhole.Services.Tunneling.WireGuard;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;

namespace Wormhole;

public partial class App : Application
{
    public new static App Current => (App)Application.Current;

    public IServiceProvider Services { get; }

    public MainWindow? MainWindow { get; private set; }

    public App()
    {
        this.InitializeComponent();
        SqliteTypeHandlers.Register();
        Services = ConfigureServices();
        // Three independent unhandled-exception sources need separate hooks so we have a
        // chance to log something before the process dies. None of these will catch a true
        // native SEH like 0xC06D007F that originates inside mstscax's delay-load helper
        // (the CLR can't translate those to managed exceptions reliably), but they cover
        // every catchable managed boundary — and for the SEH case we at least get a final
        // log line from Serilog's flush-on-exit if anything observable made it that far.
        UnhandledException += OnUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
    }

    /// <summary>
    /// The startup sweep of orphaned web-browser WebView2 folders, run off the UI thread. Web-environment
    /// creation in <c>WebBrowserView</c> awaits this so a web tab never races the delete — there is no web
    /// session until well after this is kicked off, so it has ample time to finish in the background.
    /// </summary>
    internal static Task WebBrowserDataCleanup { get; private set; } = Task.CompletedTask;

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            await LaunchAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            Services.GetService<ILogger<App>>()?.LogCritical(ex, "Unhandled exception during application launch.");
            FlushLogsForTermination();
            throw;
        }
    }

    private async Task LaunchAsync()
    {
        Directory.CreateDirectory(AppPaths.GetAppDataDirectory());

        var crashDiagnostics = Services.GetRequiredService<ICrashDiagnosticsService>();
        crashDiagnostics.Initialize();
        crashDiagnostics.LogStartupContext();
        crashDiagnostics.LogNewCrashDumps();

        // Reclaim orphaned web-browser WebView2 folders off the UI thread (the delete of a Chromium
        // profile can be slow); the first web tab awaits WebBrowserDataCleanup before creating its env.
        WebBrowserDataCleanup = Task.Run(ClearWebBrowserUserData);

        var runner = Services.GetRequiredService<MigrationRunner>();
        await runner.RunAsync();

        await RecoverFromRdpCrashSentinelAsync().ConfigureAwait(true);

        MainWindow = Services.GetRequiredService<MainWindow>();
        MainWindow.Activate();

        await MainWindow.RunStartupAuthenticationAsync().ConfigureAwait(true);

        await StartMcpServerIfEnabledAsync().ConfigureAwait(true);
    }

    /// <summary>
    /// Starts the in-app MCP server when the user has opted in. Started after the window is
    /// activated so the session registry's UI dispatcher (App.Current.MainWindow.DispatcherQueue)
    /// is available. A startup failure (e.g. port already in use) must never block the app.
    /// </summary>
    private async Task StartMcpServerIfEnabledAsync()
    {
        var settings = Services.GetRequiredService<IAppSettingsService>();
        if (!settings.Current.EnableMcpServer) return;

        try
        {
            await Services.GetRequiredService<IMcpServerHost>().StartAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            Services.GetService<ILogger<App>>()?.LogError(ex, "Failed to start MCP server at launch.");
        }
    }

    /// <summary>
    /// Check whether the previous run died mid-handshake on an embedded RDP connect and, if
    /// so, auto-flag the offending profile to route through mstsc.exe. The motivating case
    /// is Azure-AD-joined targets whose WAM delay-load fault (SEH 0xC06D007F) the CLR can't
    /// translate to a catchable exception — without the sentinel-driven recovery the user
    /// reopens the same profile and crashes again, in a death loop.
    ///
    /// Recovery contract: read the sentinel first (does NOT delete), apply the DB update,
    /// then clear the sentinel on success. If the DB update fails, the sentinel persists
    /// and the next launch retries — losing the crash signal to a transient DB error would
    /// resurrect the crash loop. Runs once at startup, before the first window is activated —
    /// deferring past Activate would race the user double-clicking the offending profile
    /// before the auto-flag DB write lands, and the in-memory tree snapshot would still
    /// hold the pre-recovery row even after the write.
    /// </summary>
    private async Task RecoverFromRdpCrashSentinelAsync()
    {
        var logger = Services.GetRequiredService<ILoggerFactory>().CreateLogger("RdpCrashRecovery");
        IRdpCrashSentinelService? sentinel = null;
        try
        {
            sentinel = Services.GetRequiredService<IRdpCrashSentinelService>();
            var orphan = await sentinel.TryReadOrphanAsync().ConfigureAwait(true);
            if (orphan is null) return;

            logger.LogWarning(
                "Detected orphan RDP crash sentinel: previous run died mid-handshake on {Host} (node {NodeId}, started {StartedAtUtc}). Auto-flagging the profile to use mstsc.exe.",
                orphan.Host, orphan.NodeId, orphan.StartedAtUtc);

            var repo = Services.GetRequiredService<IConnectionRepository>();
            var node = await repo.GetByIdAsync(orphan.NodeId).ConfigureAwait(true);
            if (node is null)
            {
                logger.LogWarning("Orphan sentinel referenced a node ({NodeId}) that no longer exists — clearing sentinel.", orphan.NodeId);
                await sentinel.ClearAsync().ConfigureAwait(true);
                return;
            }
            // Guard against retypes / kind changes since the sentinel was written. Mirror the
            // Kind=1 AND Protocol=1 filter from migration 0005 so we never write
            // RdpUseExternalClient=true on a non-RDP node or a folder.
            if (node.Kind != NodeKind.Connection || node.Protocol != ProtocolType.Rdp)
            {
                logger.LogWarning(
                    "Orphan sentinel node {NodeId} is no longer an RDP connection (Kind={Kind}, Protocol={Protocol}) — clearing sentinel without auto-flag.",
                    orphan.NodeId, node.Kind, node.Protocol);
                await sentinel.ClearAsync().ConfigureAwait(true);
                return;
            }
            if (node.RdpUseExternalClient == true)
            {
                logger.LogInformation("Orphan node {NodeId} already routed via mstsc.exe — clearing sentinel.", orphan.NodeId);
                await sentinel.ClearAsync().ConfigureAwait(true);
                return;
            }
            node.RdpUseExternalClient = true;
            await repo.UpdateAsync(node).ConfigureAwait(true);
            // Clear ONLY after the DB write succeeds. If UpdateAsync throws, the outer catch
            // logs and the sentinel persists — next launch retries the auto-flag instead of
            // losing the crash signal to a transient DB error.
            await sentinel.ClearAsync().ConfigureAwait(true);
            logger.LogInformation("Auto-flagged node {NodeId} ({Host}) for external mstsc.exe routing.", orphan.NodeId, orphan.Host);
        }
        catch (Exception ex)
        {
            // Recovery must never block startup. Worst case, the sentinel persists and we
            // retry on the next launch.
            logger.LogError(ex, "RDP crash sentinel recovery failed; sentinel left in place for retry on next launch.");
        }
    }

    /// <summary>
    /// Wipe the web-browser WebView2 user-data root: no web session is live at launch, and web sessions
    /// deliberately don't persist across restarts, so this also reclaims any per-tab proxy sub-folders
    /// orphaned by a Sessions↔Settings navigation (see <c>WebBrowserView</c>). Best-effort — a locked
    /// folder or any IO error is swallowed.
    /// </summary>
    private void ClearWebBrowserUserData()
    {
        try
        {
            var dir = AppPaths.GetWebBrowserUserDataDirectory();
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
        catch (Exception ex)
        {
            Services.GetService<ILogger<App>>()?.LogDebug(
                ex, "Could not clear the web-browser WebView2 user-data folder at startup (best-effort).");
        }
    }

    private static ServiceProvider ConfigureServices()
    {
        Directory.CreateDirectory(AppPaths.GetLogsDirectory());
        var settingsService = new AppSettingsService();

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .Enrich.FromLogContext()
            .WriteTo.File(
                LogFiles.GetDailySinkPath(),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: LogFiles.NormalizeRetentionDays(settingsService.Current.LogRetentionDays),
                shared: true)
            .CreateLogger();

        var services = new ServiceCollection();

        services.AddLogging(builder =>
        {
            builder.ClearProviders();
            builder.AddSerilog(dispose: true);
        });

        var connectionString = $"Data Source={AppPaths.GetDatabaseFilePath()}";
        services.AddSingleton<ISqliteConnectionFactory>(_ => new SqliteConnectionFactory(connectionString));
        services.AddSingleton<MigrationRunner>();

        services.AddSingleton<IAppSettingsService>(settingsService);
        services.AddSingleton<IAppAuthenticationService, AppAuthenticationService>();
        services.AddSingleton<IRemoteDesktopSessionDetector, RemoteDesktopSessionDetector>();
        services.AddSingleton<IWindowsHelloService, WindowsHelloService>();
        services.AddSingleton<IAppAuthenticationVerifier, AppAuthenticationVerifier>();
        services.AddSingleton<IAppLockState, AppLockState>();
        services.AddSingleton<AppInactivityLockEvaluator>();
        services.AddSingleton<ICredentialService, CredentialService>();
        services.AddSingleton<IConnectionRepository, ConnectionRepository>();
        services.AddSingleton<ICredentialRepository, CredentialRepository>();
        services.AddSingleton<IConnectionCredentialBindingService, ConnectionCredentialBindingService>();
        services.AddSingleton<ITunnelConfigRepository, TunnelConfigRepository>();
        services.AddSingleton<ICrashDiagnosticsService, CrashDiagnosticsService>();
        services.AddSingleton<InheritanceResolver>();
        services.AddSingleton<IConnectionProfileResolver, ConnectionProfileResolver>();

        services.AddSingleton<ITunnelProvider, WireGuardTunnelProvider>();
        services.AddSingleton<ITunnelProvider, OpenVpnTunnelProvider>();
        services.AddSingleton<ITunnelProvider, FortinetTunnelProvider>();
        services.AddSingleton<IWatchguardSamlAuthService, DialogWatchguardSamlAuthService>();
        services.AddSingleton<IWatchguardProfileCache, WatchguardProfileCache>();
        services.AddSingleton<ITunnelProvider, WatchguardTunnelProvider>();
        services.AddSingleton<IStormshieldConfigCache, StormshieldConfigCache>();
        services.AddSingleton<IWindowsTemporaryHostRouteService, WindowsTemporaryHostRouteService>();
        services.AddSingleton<ITunnelProvider, StormshieldTunnelProvider>();
        // The concrete OAuth client is shared: the sign-in popup needs its code-exchange method
        // (not on the interface), while the provider's silent-refresh path uses the interface.
        services.AddSingleton<AzureVpnOAuthClient>();
        services.AddSingleton<IAzureVpnOAuthClient>(sp => sp.GetRequiredService<AzureVpnOAuthClient>());
        services.AddSingleton<IAzureVpnAuthService, DialogAzureVpnAuthService>();
        services.AddSingleton<IAzureVpnTokenCache, AzureVpnTokenCache>();
        services.AddSingleton<ITunnelProvider, AzureVpnTunnelProvider>();
        services.AddSingleton<ITunnelProvider, CiscoSecureClientTunnelProvider>();
        services.AddSingleton<IOtpPromptService, DialogOtpPromptService>();
        services.AddSingleton<ITlsTrustPromptService, DialogTlsTrustPromptService>();
        services.AddSingleton<TunnelManager>();
        services.AddSingleton<ITunnelRoutePrompter, TunnelRoutePrompter>();
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddSingleton<IDialogService, DialogService>();
        services.AddSingleton<ISshSessionService, SshSessionService>();
        services.AddSingleton<IVncSessionService, VncSessionService>();
        services.AddSingleton<ISerialSessionService, SerialSessionService>();
        services.AddSingleton<IPrivateKeyInspector, SshNetPrivateKeyInspector>();
        services.AddSingleton<ISshCredentialResolver, SshCredentialResolver>();
        services.AddSingleton<ISessionTabFactory, SessionTabFactory>();
        services.AddSingleton<IRdpSessionService, RdpSessionService>();
        services.AddSingleton<IRdpCrashSentinelService, RdpCrashSentinelService>();
        services.AddSingleton<ISftpService, SftpService>();
        services.AddSingleton<IFileTransferDialogService, FileTransferDialogService>();
        services.AddSingleton<IMRemoteNgImportService, MRemoteNgImportService>();
        services.AddSingleton<IBackupService, BackupService>();

        services.AddSingleton<IMcpSessionRegistry, McpSessionRegistry>();
        services.AddSingleton<IMcpServerHost, McpServerHost>();

        var assemblyVersion = typeof(App).Assembly.GetName().Version?.ToString() ?? "0.0.0";
        services.AddHttpClient(UpdateService.HttpClientName, client =>
        {
            client.BaseAddress = new Uri("https://api.github.com/");
            client.Timeout = TimeSpan.FromSeconds(30);
            client.DefaultRequestHeaders.UserAgent.ParseAdd($"Wormhole/{assemblyVersion}");
            client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        });
        services.AddHttpClient(UpdateService.DownloadHttpClientName, client =>
        {
            // Installer downloads can be tens to hundreds of MB on slow connections —
            // give them a generous window. Cancellation still propagates via the
            // service's CancellationTokenSource on app shutdown.
            client.Timeout = TimeSpan.FromMinutes(30);
            client.DefaultRequestHeaders.UserAgent.ParseAdd($"Wormhole/{assemblyVersion}");
        });
        services.AddSingleton<IInstallerLauncher, DefaultInstallerLauncher>();
        services.AddSingleton<IUpdateService, UpdateService>();

        services.AddSingleton<ShellViewModel>();
        services.AddSingleton<ConnectionTreeViewModel>();
        services.AddSingleton<QuickConnectViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<CredentialsViewModel>();
        services.AddSingleton<TunnelConfigsViewModel>();
        services.AddSingleton<UpdateViewModel>();
        services.AddTransient<ConnectionEditorViewModel>();
        services.AddTransient<FolderEditorViewModel>();
        services.AddTransient<SshSessionViewModel>();
        services.AddTransient<SerialSessionViewModel>();
        services.AddTransient<RdpSessionViewModel>();
        services.AddTransient<HttpSessionViewModel>();
        services.AddTransient<VncSessionViewModel>();
        services.AddTransient<MRemoteNgImportDialogViewModel>();
        services.AddTransient<BackupExportDialogViewModel>();
        services.AddTransient<BackupImportDialogViewModel>();
        services.AddTransient<TunnelTestDialogViewModel>();

        services.AddSingleton<MainWindow>();

        return services.BuildServiceProvider();
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        var logger = Services.GetService<ILogger<App>>();
        logger?.LogError(e.Exception, "Unhandled exception reached App boundary.");
        FlushLogsForTermination();
    }

    private void OnAppDomainUnhandledException(object sender, System.UnhandledExceptionEventArgs e)
    {
        // Last-chance hook for exceptions that escape the WinUI dispatcher. e.ExceptionObject
        // is `object` because pre-2.0 CLR could raise non-Exception types; in practice it's
        // always an Exception today. e.IsTerminating tells us whether the runtime will exit
        // after we return — for delay-load SEH and similar fatal failures it's true, so this
        // is the only place we'll get to record the cause before the process dies.
        var logger = Services.GetService<ILogger<App>>();
        var ex = e.ExceptionObject as Exception;
        logger?.LogCritical(
            ex,
            "AppDomain unhandled exception (terminating={Terminating}): {Type} — {Message}",
            e.IsTerminating,
            ex?.GetType().FullName ?? e.ExceptionObject?.GetType().FullName ?? "null",
            ex?.Message ?? "<no message>");

        // Force Serilog to flush before the runtime tears down. Without this, a final
        // [ERR]/[CRT] line about why we died often gets buffered out of existence and the
        // user sees the post-crash log file end mid-handshake (which is exactly what
        // happened with the 0xC06D007F mstscax delay-load crash that motivated this hook).
        FlushLogsForTermination();
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        var logger = Services.GetService<ILogger<App>>();
        logger?.LogError(e.Exception, "Unobserved Task exception.");
        // Marking observed prevents the runtime from re-raising it on finalizer thread and
        // taking down the process. The exception is already a bug — but a crash from a
        // background continuation we forgot to await shouldn't kill the user's session.
        e.SetObserved();
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        Services.GetService<ILogger<App>>()?.LogInformation("Wormhole process exiting.");
        FlushLogsForTermination();
    }

    private static void FlushLogsForTermination()
    {
        try { Log.CloseAndFlush(); }
        catch { /* nothing useful to do while the process is exiting */ }
    }
}
