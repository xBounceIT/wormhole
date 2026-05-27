using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Models;
using Wormhole.Models.Backup;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly IAppSettingsService _settingsService;
    private readonly IDialogService _dialog;
    private readonly ConnectionTreeViewModel _connectionTree;
    private readonly CredentialsViewModel _credentials;
    private readonly TunnelConfigsViewModel _tunnels;
    private readonly ILogger<SettingsViewModel> _logger;

    [ObservableProperty]
    private ApplicationTheme theme;

    [ObservableProperty]
    private bool confirmOnTabClose;

    [ObservableProperty]
    private bool autoCheckForUpdates;

    [ObservableProperty]
    private bool autoCopyOnSelect;

    public UpdateViewModel Update { get; }

    public SettingsViewModel(
        IAppSettingsService settingsService,
        UpdateViewModel update,
        IDialogService dialog,
        ConnectionTreeViewModel connectionTree,
        CredentialsViewModel credentials,
        TunnelConfigsViewModel tunnels,
        ILogger<SettingsViewModel> logger)
    {
        _settingsService = settingsService;
        _dialog = dialog;
        _connectionTree = connectionTree;
        _credentials = credentials;
        _tunnels = tunnels;
        _logger = logger;
        Update = update;
        theme = _settingsService.Current.Theme;
        confirmOnTabClose = _settingsService.Current.ConfirmOnTabClose;
        autoCheckForUpdates = _settingsService.Current.AutoCheckForUpdates;
        autoCopyOnSelect = _settingsService.Current.AutoCopyOnSelect;
    }

    partial void OnThemeChanged(ApplicationTheme value)
    {
        _settingsService.Current.Theme = value;
        _settingsService.Save();
    }

    partial void OnConfirmOnTabCloseChanged(bool value)
    {
        _settingsService.Current.ConfirmOnTabClose = value;
        _settingsService.Save();
    }

    partial void OnAutoCheckForUpdatesChanged(bool value)
    {
        _settingsService.Current.AutoCheckForUpdates = value;
        _settingsService.Save();
    }

    partial void OnAutoCopyOnSelectChanged(bool value)
    {
        _settingsService.Current.AutoCopyOnSelect = value;
        _settingsService.Save();
    }

    [RelayCommand]
    private async Task ExportBackupAsync()
    {
        try
        {
            await _dialog.PromptForBackupExportAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup export dialog failed.");
            await _dialog.ShowMessageAsync("Couldn't export backup", ex.Message);
        }
    }

    [RelayCommand]
    private async Task ImportBackupAsync()
    {
        try
        {
            _ = await _dialog.PromptForBackupImportAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup import dialog failed.");
            await _dialog.ShowMessageAsync("Couldn't import backup", ex.Message);
        }

        // Always refresh after the dialog closes. BackupService.ImportAsync is non-transactional
        // — a cancellation midway returns a null Result but may have already persisted credentials,
        // tunnels, and some nodes. Without an unconditional refresh, that partial state stays
        // invisible until the next restart, leaving the UI desynced from the DB.
        try
        {
            await _connectionTree.RefreshAsync();
            await _credentials.LoadCommand.ExecuteAsync(null);
            await _tunnels.LoadCommand.ExecuteAsync(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh views after backup import.");
        }
    }
}
