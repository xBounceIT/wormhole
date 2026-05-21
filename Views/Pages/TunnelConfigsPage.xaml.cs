using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels;

namespace Wormhole.Views.Pages;

public sealed partial class TunnelConfigsPage : Page
{
    public TunnelConfigsViewModel ViewModel { get; }

    public TunnelConfigsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<TunnelConfigsViewModel>();
        this.InitializeComponent();
    }

    private async void Page_Loaded(object sender, RoutedEventArgs e)
    {
        await ViewModel.LoadAsync();
    }
}
