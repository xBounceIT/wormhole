using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Serilog;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Services;
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
        UnhandledException += OnUnhandledException;
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        Directory.CreateDirectory(AppPaths.GetAppDataDirectory());

        var runner = Services.GetRequiredService<MigrationRunner>();
        await runner.RunAsync();

        MainWindow = Services.GetRequiredService<MainWindow>();
        MainWindow.Activate();
    }

    private static IServiceProvider ConfigureServices()
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
        services.AddSingleton<ISftpService, SftpService>();
        services.AddSingleton<IFileTransferDialogService, FileTransferDialogService>();

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
}
