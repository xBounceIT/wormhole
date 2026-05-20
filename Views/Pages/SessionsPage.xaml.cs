using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Pages;

public sealed partial class SessionsPage : Page
{
    public ShellViewModel ViewModel { get; }

    public SessionsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<ShellViewModel>();
        this.InitializeComponent();
    }

    private async void SessionTabs_TabCloseRequested(TabView sender, TabViewTabCloseRequestedEventArgs args)
    {
        if (args.Item is SshSessionViewModel ssh)
        {
            await ssh.DetachAsync();
        }
        if (args.Item is SessionTabViewModel tab)
        {
            ViewModel.Tabs.Remove(tab);
        }
    }
}
