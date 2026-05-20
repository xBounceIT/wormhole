using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Wormhole.Models;
using Wormhole.ViewModels;

namespace Wormhole.Views.Pages;

public sealed partial class SettingsPage : Page
{
    public SettingsViewModel ViewModel { get; }

    public int ThemeIndex
    {
        get => (int)ViewModel.Theme;
        set => OnThemeIndexChanged(value);
    }

    public SettingsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<SettingsViewModel>();
        this.InitializeComponent();
    }

    private void OnThemeIndexChanged(int value)
    {
        if (value is < 0 or > 2) return;
        ViewModel.Theme = (ApplicationTheme)value;
    }
}
