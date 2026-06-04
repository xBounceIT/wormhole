using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public sealed class TunnelRoutePrompterTests
{
    [Fact]
    public async Task TunnelDisabledProfile_ReturnsSameProfile_WithoutPrompting()
    {
        var (prompter, dialog, _, settings) = Create();
        settings.Current.PromptBeforeTunnelConnect = true; // on, but profile has no tunnel
        var profile = Profile(tunnelEnabled: false);

        var result = await prompter.ResolveRouteAsync(profile, CancellationToken.None);

        Assert.Same(profile, result);
        Assert.Equal(0, dialog.TunnelRoutePromptCount);
    }

    [Fact]
    public async Task SettingOff_ReturnsSameProfile_WithoutPrompting()
    {
        var (prompter, dialog, _, settings) = Create();
        settings.Current.PromptBeforeTunnelConnect = false;
        var profile = Profile(tunnelEnabled: true, configId: Guid.NewGuid());

        var result = await prompter.ResolveRouteAsync(profile, CancellationToken.None);

        Assert.Same(profile, result);
        Assert.Equal(0, dialog.TunnelRoutePromptCount);
    }

    [Fact]
    public async Task SettingOn_UseTunnel_ReturnsProfileUnchanged()
    {
        var (prompter, dialog, _, settings) = Create();
        settings.Current.PromptBeforeTunnelConnect = true;
        dialog.TunnelRouteResult = TunnelRouteChoice.UseTunnel;
        var profile = Profile(tunnelEnabled: true, configId: Guid.NewGuid());

        var result = await prompter.ResolveRouteAsync(profile, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(result!.TunnelEnabled);
        Assert.Equal(1, dialog.TunnelRoutePromptCount);
    }

    [Fact]
    public async Task SettingOn_Direct_ForcesTunnelOff()
    {
        var (prompter, dialog, _, settings) = Create();
        settings.Current.PromptBeforeTunnelConnect = true;
        dialog.TunnelRouteResult = TunnelRouteChoice.Direct;
        var configId = Guid.NewGuid();
        var profile = Profile(tunnelEnabled: true, configId: configId);

        var result = await prompter.ResolveRouteAsync(profile, CancellationToken.None);

        Assert.NotNull(result);
        Assert.False(result!.TunnelEnabled);
        // The config id is left intact — only the enable flag flips for this attempt.
        Assert.Equal(configId, result.TunnelConfigId);
        Assert.Equal(1, dialog.TunnelRoutePromptCount);
    }

    [Fact]
    public async Task SettingOn_Cancel_ReturnsNull()
    {
        var (prompter, dialog, _, settings) = Create();
        settings.Current.PromptBeforeTunnelConnect = true;
        dialog.TunnelRouteResult = TunnelRouteChoice.Cancel;
        var profile = Profile(tunnelEnabled: true, configId: Guid.NewGuid());

        var result = await prompter.ResolveRouteAsync(profile, CancellationToken.None);

        Assert.Null(result);
        Assert.Equal(1, dialog.TunnelRoutePromptCount);
    }

    [Fact]
    public async Task SettingOn_PassesConfiguredTunnelName_ToDialog()
    {
        var (prompter, dialog, configs, settings) = Create();
        settings.Current.PromptBeforeTunnelConnect = true;
        var configId = Guid.NewGuid();
        configs.Configs[configId] = new TunnelConfig { Id = configId, Name = "corp-vpn", Kind = TunnelKind.WireGuard };
        var profile = Profile(tunnelEnabled: true, configId: configId);

        await prompter.ResolveRouteAsync(profile, CancellationToken.None);

        Assert.Equal("corp-vpn", dialog.LastTunnelRouteName);
        Assert.Equal("conn", dialog.LastTunnelRouteConnectionName);
    }

    [Fact]
    public async Task SettingOn_ConfigLookupThrows_StillPromptsWithGenericName()
    {
        var dialog = new FakeDialogService();
        var settings = new FakeAppSettingsService();
        settings.Current.PromptBeforeTunnelConnect = true;
        dialog.TunnelRouteResult = TunnelRouteChoice.UseTunnel;
        var prompter = new TunnelRoutePrompter(
            settings,
            dialog,
            new ThrowingTunnelConfigRepository(),
            NullLoggerFactory.Instance.CreateLogger<TunnelRoutePrompter>());
        var profile = Profile(tunnelEnabled: true, configId: Guid.NewGuid());

        var result = await prompter.ResolveRouteAsync(profile, CancellationToken.None);

        // A repository failure must not block the routing decision: still prompt (with the
        // generic fallback name) and still honor the user's choice.
        Assert.Equal(1, dialog.TunnelRoutePromptCount);
        Assert.Equal("the configured VPN tunnel", dialog.LastTunnelRouteName);
        Assert.NotNull(result);
        Assert.True(result!.TunnelEnabled);
    }

    [Fact]
    public async Task SettingOn_MissingConfig_UsesGenericName()
    {
        var (prompter, dialog, _, settings) = Create();
        settings.Current.PromptBeforeTunnelConnect = true;
        // TunnelConfigId points at a config not present in the repository.
        var profile = Profile(tunnelEnabled: true, configId: Guid.NewGuid());

        await prompter.ResolveRouteAsync(profile, CancellationToken.None);

        Assert.Equal("the configured VPN tunnel", dialog.LastTunnelRouteName);
    }

    private static (TunnelRoutePrompter prompter, FakeDialogService dialog, FakeTunnelConfigRepository configs, FakeAppSettingsService settings) Create()
    {
        var dialog = new FakeDialogService();
        var configs = new FakeTunnelConfigRepository();
        var settings = new FakeAppSettingsService();
        var prompter = new TunnelRoutePrompter(
            settings,
            dialog,
            configs,
            NullLoggerFactory.Instance.CreateLogger<TunnelRoutePrompter>());
        return (prompter, dialog, configs, settings);
    }

    private static ConnectionProfile Profile(bool tunnelEnabled, Guid? configId = null) =>
        new()
        {
            NodeId = Guid.NewGuid(),
            Name = "conn",
            Protocol = ProtocolType.Ssh,
            Host = "192.0.2.10",
            Port = 22,
            TunnelEnabled = tunnelEnabled,
            TunnelConfigId = configId,
        };

    private sealed class FakeAppSettingsService : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged { add { } remove { } }
        public void Save() { }
    }

    private sealed class ThrowingTunnelConfigRepository : ITunnelConfigRepository
    {
        public Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("repository unavailable");
        public Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("repository unavailable");
        public Task AddAsync(TunnelConfig config, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task UpdateAsync(TunnelConfig config, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
