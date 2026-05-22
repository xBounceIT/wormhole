using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Serilog;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Services;
using Wormhole.Services.Rdp;
using Wormhole.Services.Ssh;
using Wormhole.Services.Tunneling;
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
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        Directory.CreateDirectory(AppPaths.GetAppDataDirectory());

        var runner = Services.GetRequiredService<MigrationRunner>();
        await runner.RunAsync();

        await RecoverFromRdpCrashSentinelAsync().ConfigureAwait(true);

        MainWindow = Services.GetRequiredService<MainWindow>();
        MainWindow.Activate();
    }

    /// <summary>
    /// Check whether the previous run died mid-handshake on an embedded RDP connect and, if
    /// so, auto-flag the offending profile to route through mstsc.exe. The motivating case
    /// is Azure-AD-joined targets whose WAM delay-load fault (SEH 0xC06D007F) the CLR can't
    /// translate to a catchable exception — without the sentinel-driven recovery the user
    /// reopens the same profile and crashes again, in a death loop. Runs once at startup,
    /// before the first window is activated, so a banner / refresh later in startup sees the
    /// updated DB state.
    /// </summary>
    private async Task RecoverFromRdpCrashSentinelAsync()
    {
        var logger = Services.GetRequiredService<ILoggerFactory>().CreateLogger("RdpCrashRecovery");
        try
        {
            var sentinel = Services.GetRequiredService<IRdpCrashSentinelService>();
            var orphan = await sentinel.TryClaimOrphanAsync().ConfigureAwait(true);
            if (orphan is null) return;

            logger.LogWarning(
                "Detected orphan RDP crash sentinel: previous run died mid-handshake on {Host} (node {NodeId}, started {StartedAtUtc}). Auto-flagging the profile to use mstsc.exe.",
                orphan.Host, orphan.NodeId, orphan.StartedAtUtc);

            var repo = Services.GetRequiredService<IConnectionRepository>();
            var node = await repo.GetByIdAsync(orphan.NodeId).ConfigureAwait(true);
            if (node is null)
            {
                logger.LogWarning("Orphan sentinel referenced a node ({NodeId}) that no longer exists — skipping auto-flag.", orphan.NodeId);
                return;
            }
            if (node.RdpUseExternalClient == true)
            {
                logger.LogInformation("Orphan node {NodeId} already routed via mstsc.exe — sentinel cleared without further action.", orphan.NodeId);
                return;
            }
            node.RdpUseExternalClient = true;
            await repo.UpdateAsync(node).ConfigureAwait(true);
            logger.LogInformation("Auto-flagged node {NodeId} ({Host}) for external mstsc.exe routing.", orphan.NodeId, orphan.Host);
        }
        catch (Exception ex)
        {
            // Recovery must never block startup. Worst case, the user hits the same crash
            // again — but at least the rest of the app comes up so they can fix things
            // manually via the editor.
            logger.LogError(ex, "RDP crash sentinel recovery failed; continuing startup.");
        }
    }

    private static ServiceProvider ConfigureServices()
    {
        Directory.CreateDirectory(AppPaths.GetLogsDirectory());

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .Enrich.FromLogContext()
            .WriteTo.File(
                Path.Combine(AppPaths.GetLogsDirectory(), "wormhole-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
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

        services.AddSingleton<IAppSettingsService, AppSettingsService>();
        services.AddSingleton<ICredentialService, CredentialService>();
        services.AddSingleton<IConnectionRepository, ConnectionRepository>();
        services.AddSingleton<ICredentialRepository, CredentialRepository>();
        services.AddSingleton<ITunnelConfigRepository, TunnelConfigRepository>();
        services.AddSingleton<InheritanceResolver>();

        services.AddSingleton<ITunnelProvider, WireGuardTunnelProvider>();
        services.AddSingleton<TunnelManager>();
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddSingleton<IDialogService, DialogService>();
        services.AddSingleton<ISshSessionService, SshSessionService>();
        services.AddSingleton<IPrivateKeyInspector, SshNetPrivateKeyInspector>();
        services.AddSingleton<ISshCredentialResolver, SshCredentialResolver>();
        services.AddSingleton<ISessionTabFactory, SessionTabFactory>();
        services.AddSingleton<IRdpSessionService, RdpSessionService>();
        services.AddSingleton<IRdpCrashSentinelService, RdpCrashSentinelService>();
        services.AddSingleton<ISftpService, SftpService>();

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
        services.AddSingleton<UpdateViewModel>();
        services.AddTransient<ConnectionEditorViewModel>();
        services.AddTransient<SshSessionViewModel>();
        services.AddTransient<RdpSessionViewModel>();
        services.AddTransient<SftpSessionViewModel>();
        services.AddTransient<TunnelConfigsViewModel>();

        services.AddSingleton<MainWindow>();

        return services.BuildServiceProvider();
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        var logger = Services.GetService<ILogger<App>>();
        logger?.LogError(e.Exception, "Unhandled exception reached App boundary.");
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
        try { Log.CloseAndFlush(); }
        catch { /* nothing useful to do — we're terminating */ }
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
}
