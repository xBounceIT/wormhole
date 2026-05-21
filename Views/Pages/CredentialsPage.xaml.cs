using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Wormhole.Models;
using Wormhole.ViewModels;

namespace Wormhole.Views.Pages;

public sealed partial class CredentialsPage : Page
{
    public CredentialsViewModel ViewModel { get; }

    public CredentialsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<CredentialsViewModel>();
        this.InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _ = ViewModel.LoadCommand.ExecuteAsync(null);
    }

    private void OnCardDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CredentialProfile profile })
        {
            ViewModel.EditCredentialCommand.Execute(profile);
        }
    }

    private void OnEditMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CredentialProfile profile })
        {
            ViewModel.EditCredentialCommand.Execute(profile);
        }
    }

    private void OnDeleteMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CredentialProfile profile })
        {
            ViewModel.DeleteCredentialCommand.Execute(profile);
        }
    }
}
