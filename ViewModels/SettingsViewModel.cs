using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly IAppSettingsService _settingsService;

    [ObservableProperty]
    private ApplicationTheme theme;

    [ObservableProperty]
    private bool confirmOnTabClose;

    [ObservableProperty]
    private bool autoCheckForUpdates;

    public UpdateViewModel Update { get; }

    public SettingsViewModel(IAppSettingsService settingsService, UpdateViewModel update)
    {
        _settingsService = settingsService;
        Update = update;
        theme = _settingsService.Current.Theme;
        confirmOnTabClose = _settingsService.Current.ConfirmOnTabClose;
        autoCheckForUpdates = _settingsService.Current.AutoCheckForUpdates;
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
}
