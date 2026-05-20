using System;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Wormhole.Services;
using Wormhole.ViewModels;
using Wormhole.Views.Pages;

namespace Wormhole;

public sealed partial class MainWindow : Window
{
    private readonly INavigationService _navigationService;

    public ShellViewModel ViewModel { get; }

    public MainWindow(ShellViewModel viewModel, INavigationService navigationService)
    {
        ViewModel = viewModel;
        _navigationService = navigationService;

        this.InitializeComponent();

        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);

        SystemBackdrop = new MicaBackdrop { Kind = Microsoft.UI.Composition.SystemBackdrops.MicaKind.Base };

        _navigationService.Initialize(ContentFrame);
        _navigationService.Navigate(typeof(SessionsPage));

        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            await ViewModel.Update.RunStartupCheckAsync().ConfigureAwait(false);
        });
    }

    private void UpdateInfoBar_CloseButtonClick(InfoBar sender, object args)
    {
        ViewModel.Update.DismissCommand.Execute(null);
    }

    private void NavView_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
    {
        if (args.InvokedItemContainer is not NavigationViewItem item) return;
        switch (item.Tag as string)
        {
            case "Sessions":
                _navigationService.Navigate(typeof(SessionsPage));
                break;
            case "Settings":
                _navigationService.Navigate(typeof(SettingsPage));
                break;
        }
    }
}
