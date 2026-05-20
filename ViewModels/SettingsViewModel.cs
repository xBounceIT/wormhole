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

    public SettingsViewModel(IAppSettingsService settingsService)
    {
        _settingsService = settingsService;
        theme = _settingsService.Current.Theme;
        confirmOnTabClose = _settingsService.Current.ConfirmOnTabClose;
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
}
