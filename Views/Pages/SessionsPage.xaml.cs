using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels;

namespace Wormhole.Views.Pages;

public sealed partial class SessionsPage : Page
{
    public ShellViewModel ViewModel { get; }

    public SessionsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<ShellViewModel>();
        this.InitializeComponent();
    }
}
