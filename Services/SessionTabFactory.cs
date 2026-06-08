using Microsoft.Extensions.DependencyInjection;
using Wormhole.Models;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;
using Wormhole.Views.Pages;

namespace Wormhole.Services;

public sealed class SessionTabFactory : ISessionTabFactory
{
    private readonly IServiceProvider _serviceProvider;
    private readonly INavigationService _navigation;

    public SessionTabFactory(IServiceProvider serviceProvider, INavigationService navigation)
    {
        _serviceProvider = serviceProvider;
        _navigation = navigation;
    }

    public void Open(ConnectionProfile profile)
    {
        // Resolve ShellViewModel lazily — eager injection would create a cycle:
        // ShellVM -> ConnectionTreeVM -> ISessionTabFactory -> ShellVM.
        var shell = _serviceProvider.GetRequiredService<ShellViewModel>();
        SessionTabViewModel vm = profile.Protocol switch
        {
            ProtocolType.Ssh => _serviceProvider.GetRequiredService<SshSessionViewModel>(),
            ProtocolType.Rdp => _serviceProvider.GetRequiredService<RdpSessionViewModel>(),
            ProtocolType.Http or ProtocolType.Https => _serviceProvider.GetRequiredService<HttpSessionViewModel>(),
            _ => throw new ArgumentOutOfRangeException(nameof(profile),
                $"Unknown protocol {profile.Protocol}.")
        };
        vm.Initialize(profile);
        shell.Tabs.Add(vm);
        shell.SelectedTab = vm;
        _navigation.Navigate(typeof(SessionsPage));
    }
}
