using System;
using Microsoft.Extensions.DependencyInjection;
using Wormhole.Models;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;
using Wormhole.Views.Pages;

namespace Wormhole.Services;

public interface ISessionTabFactory
{
    void OpenSsh(ConnectionProfile profile);
}

public sealed class SessionTabFactory : ISessionTabFactory
{
    private readonly IServiceProvider _serviceProvider;
    private readonly INavigationService _navigation;

    public SessionTabFactory(IServiceProvider serviceProvider, INavigationService navigation)
    {
        _serviceProvider = serviceProvider;
        _navigation = navigation;
    }

    public void OpenSsh(ConnectionProfile profile)
    {
        if (profile.Protocol != ProtocolType.Ssh)
            throw new ArgumentException($"OpenSsh requires an SSH profile; got {profile.Protocol}.", nameof(profile));

        // Resolve ShellViewModel lazily — eager injection would create a cycle:
        // ShellVM -> ConnectionTreeVM -> ISessionTabFactory -> ShellVM.
        var shell = _serviceProvider.GetRequiredService<ShellViewModel>();
        var vm = _serviceProvider.GetRequiredService<SshSessionViewModel>();
        vm.Initialize(profile);
        shell.Tabs.Add(vm);
        shell.SelectedTab = vm;
        _navigation.Navigate(typeof(SessionsPage));
    }
}
