using System;
using System.Reflection;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class UpdateViewModel : ObservableObject
{
    private static readonly TimeSpan StartupThrottle = TimeSpan.FromHours(24);

    private readonly IUpdateService _updateService;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<UpdateViewModel> _logger;
    private readonly DispatcherQueue? _dispatcher;

    [ObservableProperty] private bool isUpdateAvailable;
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private double downloadProgress;
    [ObservableProperty] private string currentVersionText = "Wormhole 0.0.0";
    [ObservableProperty] private string latestVersionText = string.Empty;
    [ObservableProperty] private string releaseNotes = string.Empty;
    [ObservableProperty] private string status = string.Empty;
    [ObservableProperty] private string lastCheckText = "Never";
    [ObservableProperty] private string infoBarMessage = string.Empty;
    [ObservableProperty] private string? releaseUrl;

    public UpdateViewModel(
        IUpdateService updateService,
        IAppSettingsService settings,
        ILogger<UpdateViewModel> logger)
    {
        _updateService = updateService;
        _settings = settings;
        _logger = logger;
        _dispatcher = DispatcherQueue.GetForCurrentThread();

        var infoVersion = Assembly.GetEntryAssembly()?
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;
        var assemblyVersion = Assembly.GetEntryAssembly()?.GetName().Version?.ToString();
        currentVersionText = $"Wormhole {infoVersion ?? assemblyVersion ?? "0.0.0"}";
        lastCheckText = FormatLastCheck(_settings.Current.LastUpdateCheck);

        _updateService.UpdateAvailable += OnUpdateAvailable;
    }

    public async Task RunStartupCheckAsync()
    {
        if (!_settings.Current.AutoCheckForUpdates) return;
        var last = _settings.Current.LastUpdateCheck;
        if (last is not null && DateTimeOffset.UtcNow - last < StartupThrottle) return;
        try { await CheckNowAsync().ConfigureAwait(false); }
        catch (Exception ex) { _logger.LogWarning(ex, "Startup update check failed."); }
    }

    [RelayCommand]
    private async Task CheckNowAsync()
    {
        if (IsBusy) return;
        Marshal(() => { IsBusy = true; Status = "Checking for updates…"; });
        try
        {
            var result = await _updateService.CheckAsync().ConfigureAwait(false);
            Marshal(() => ApplyResult(result));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Update check failed.");
            Marshal(() => Status = "Couldn't reach the update server.");
        }
        finally
        {
            Marshal(() =>
            {
                IsBusy = false;
                LastCheckText = FormatLastCheck(_settings.Current.LastUpdateCheck);
            });
        }
    }

    [RelayCommand]
    private async Task InstallAsync()
    {
        var latest = _updateService.LatestKnown;
        if (latest is null || !latest.IsUpdateAvailable) return;
        if (IsBusy) return;

        Marshal(() => { IsBusy = true; DownloadProgress = 0; Status = "Downloading…"; });
        try
        {
            var progress = new Progress<double>(p => Marshal(() => DownloadProgress = p));
            var path = await _updateService.DownloadInstallerAsync(latest, progress).ConfigureAwait(false);
            Marshal(() => Status = "Launching installer…");
            await _updateService.LaunchInstallerAndExitAsync(path).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Update install failed.");
            Marshal(() => Status = "Install failed: " + ex.Message);
        }
        finally
        {
            Marshal(() => IsBusy = false);
        }
    }

    [RelayCommand]
    private void Dismiss()
    {
        var latest = _updateService.LatestKnown;
        if (latest?.LatestVersion is null) return;
        _settings.Current.SkippedUpdateVersion = latest.LatestVersion.ToString();
        _settings.Save();
    }

    [RelayCommand]
    private void OpenReleasePage()
    {
        if (string.IsNullOrWhiteSpace(ReleaseUrl)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = ReleaseUrl,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to open release URL {Url}.", ReleaseUrl);
        }
    }

    private void OnUpdateAvailable(object? sender, UpdateCheckResult result) =>
        Marshal(() => ApplyResult(result));

    private void ApplyResult(UpdateCheckResult result)
    {
        if (result.CheckFailed)
        {
            // Leave any previously surfaced update visible; just report the failure.
            Status = "Couldn't reach the update server. Try again later.";
            return;
        }

        ReleaseUrl = result.ReleaseUrl;
        ReleaseNotes = result.ReleaseNotes ?? string.Empty;
        if (result.IsUpdateAvailable && result.LatestVersion is not null)
        {
            var versionString = result.LatestVersion.ToString();
            LatestVersionText = result.ReleaseName ?? $"Wormhole {versionString}";
            InfoBarMessage = $"Wormhole {versionString} is available.";
            Status = $"Update available: {versionString}";
            IsUpdateAvailable = !string.Equals(
                _settings.Current.SkippedUpdateVersion, versionString, StringComparison.Ordinal);
        }
        else
        {
            IsUpdateAvailable = false;
            LatestVersionText = string.Empty;
            InfoBarMessage = string.Empty;
            Status = "You're on the latest version.";
        }
    }

    private void Marshal(Action action)
    {
        if (_dispatcher is null || _dispatcher.HasThreadAccess) { action(); return; }
        _dispatcher.TryEnqueue(() => action());
    }

    private static string FormatLastCheck(DateTimeOffset? when)
    {
        if (when is null) return "Never";
        return $"Last checked {when.Value.ToLocalTime():g}";
    }
}
