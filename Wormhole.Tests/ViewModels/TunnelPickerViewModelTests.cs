using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class TunnelPickerViewModelTests
{
    [Fact]
    public void Constructor_SeedsBothSentinels()
    {
        var vm = NewPicker();
        Assert.Equal(2, vm.AvailableTunnelConfigs.Count);
        Assert.Same(vm.InheritTunnel, vm.AvailableTunnelConfigs[0]);
        Assert.Same(TunnelPickerViewModel.NoTunnel, vm.AvailableTunnelConfigs[1]);
    }

    [Fact]
    public void Constructor_InheritLabel_AppliesToSentinelName()
    {
        var vm = new TunnelPickerViewModel(new EmptyRepo(), inheritLabel: "(Inherit from parent)");
        Assert.Equal("(Inherit from parent)", vm.InheritTunnel.Name);
    }

    [Fact]
    public async Task LoadAsync_LeadsWithSentinelsThenAppendsRepoEntries()
    {
        var wg = new TunnelConfig { Id = Guid.NewGuid(), Name = "wg-1", Kind = TunnelKind.WireGuard };
        var vm = new TunnelPickerViewModel(new MultiRepo(wg));

        await vm.LoadAsync();

        Assert.Equal(3, vm.AvailableTunnelConfigs.Count);
        Assert.Same(vm.InheritTunnel, vm.AvailableTunnelConfigs[0]);
        Assert.Same(TunnelPickerViewModel.NoTunnel, vm.AvailableTunnelConfigs[1]);
        Assert.Equal("wg-1", vm.AvailableTunnelConfigs[2].Name);
    }

    [Fact]
    public async Task FilterTunnelConfigs_MatchesNameCaseInsensitively()
    {
        var office = new TunnelConfig { Id = Guid.NewGuid(), Name = "Office", Kind = TunnelKind.WireGuard };
        var remote = new TunnelConfig { Id = Guid.NewGuid(), Name = "Remote", Kind = TunnelKind.OpenVpn };
        var vm = new TunnelPickerViewModel(new MultiRepo(office, remote));
        await vm.LoadAsync();

        Assert.Contains(office, vm.FilterTunnelConfigs("off"));
        Assert.Contains(remote, vm.FilterTunnelConfigs("REMOTE"));
        Assert.Empty(vm.FilterTunnelConfigs("missing"));
        Assert.Equal(vm.AvailableTunnelConfigs.Count, vm.FilterTunnelConfigs(null).Count);
    }

    [Fact]
    public async Task ResolveTunnelForCommit_PrefersExactName_ThenUniqueMatch()
    {
        var prod = new TunnelConfig { Id = Guid.NewGuid(), Name = "prod", Kind = TunnelKind.WireGuard };
        var prodBackup = new TunnelConfig { Id = Guid.NewGuid(), Name = "prod-backup", Kind = TunnelKind.OpenVpn };
        var vm = new TunnelPickerViewModel(new MultiRepo(prod, prodBackup));
        await vm.LoadAsync();

        Assert.Same(prod, vm.ResolveTunnelForCommit("PROD"));
        Assert.Same(prodBackup, vm.ResolveTunnelForCommit("backup"));
        Assert.Null(vm.ResolveTunnelForCommit("pro"));
        Assert.Null(vm.ResolveTunnelForCommit("missing"));
        Assert.Null(vm.ResolveTunnelForCommit(""));
    }

    [Fact]
    public async Task Search_DoesNotTreatMissingTunnelAsItsDefaultKind()
    {
        var vm = NewPicker();
        await vm.LoadAsync();
        vm.LoadFrom(new ConnectionNode { TunnelEnabled = true, TunnelConfigId = Guid.NewGuid() });

        Assert.Empty(vm.FilterTunnelConfigs("wireguard"));
        Assert.Null(vm.ResolveTunnelForCommit("wireguard"));
    }

    [Fact]
    public void SelectedTunnel_InheritSentinel_NullsBothBackingFields()
    {
        var vm = NewPicker();
        vm.SelectedTunnel = vm.InheritTunnel;

        Assert.Null(vm.TunnelEnabled);
        Assert.Null(vm.SelectedTunnelConfigId);
        Assert.Same(vm.InheritTunnel, vm.SelectedTunnel);
    }

    [Fact]
    public void SelectedTunnel_NoTunnelSentinel_SetsEnabledFalseAndClearsId()
    {
        var vm = NewPicker();
        vm.SelectedTunnel = TunnelPickerViewModel.NoTunnel;

        Assert.False(vm.TunnelEnabled);
        Assert.Null(vm.SelectedTunnelConfigId);
        Assert.Same(TunnelPickerViewModel.NoTunnel, vm.SelectedTunnel);
    }

    [Fact]
    public async Task LoadFrom_StaleTunnelId_AppendsPlaceholderSoSelectionStaysVisible()
    {
        var deletedId = Guid.NewGuid();
        var vm = NewPicker();
        await vm.LoadAsync();

        var node = new ConnectionNode { TunnelEnabled = true, TunnelConfigId = deletedId };
        vm.LoadFrom(node);

        Assert.Contains(vm.AvailableTunnelConfigs, t => t.Id == deletedId);
        Assert.Equal(deletedId, vm.SelectedTunnel!.Id);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);
        Assert.True(sink.TunnelEnabled);
        Assert.Equal(deletedId, sink.TunnelConfigId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(false)]
    public async Task LoadFrom_WriteTo_RoundTrip_NullAndOffStates(bool? enabled)
    {
        var vm = NewPicker();
        await vm.LoadAsync();

        var node = new ConnectionNode { TunnelEnabled = enabled, TunnelConfigId = null };
        vm.LoadFrom(node);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);

        Assert.Equal(enabled, sink.TunnelEnabled);
        Assert.Null(sink.TunnelConfigId);
    }

    [Fact]
    public async Task LoadFrom_NullEnableWithOverrideId_SurfacesOverrideNotInherit()
    {
        // Regression: a node persisted with (TunnelEnabled=null, TunnelConfigId=<id>) is the
        // "inherit enable, override config" state the InheritanceResolver can produce. The
        // picker must show the override config, not silently mask it as the inherit sentinel.
        var wg = new TunnelConfig { Id = Guid.NewGuid(), Name = "override", Kind = TunnelKind.WireGuard };
        var vm = new TunnelPickerViewModel(new MultiRepo(wg));
        await vm.LoadAsync();

        vm.LoadFrom(new ConnectionNode { TunnelEnabled = null, TunnelConfigId = wg.Id });

        Assert.Same(wg, vm.SelectedTunnel);
        Assert.NotSame(vm.InheritTunnel, vm.SelectedTunnel);
    }

    [Fact]
    public void SelectedTunnel_UnresolvedEnabledState_ReturnsNull()
    {
        // (TunnelEnabled=true, ConfigId=<unknown id>) is an inconsistent intermediate state.
        // The getter must return null so the UI surfaces the inconsistency rather than
        // silently masking it as "(Inherit)".
        var vm = NewPicker();
        vm.SelectedTunnel = vm.InheritTunnel;
        vm.TunnelEnabled = true;
        vm.SelectedTunnelConfigId = Guid.NewGuid();

        Assert.Null(vm.SelectedTunnel);
    }

    [Fact]
    public async Task SelectedTunnel_SetterIsAtomic_AcrossPropertyChangedReentrancy()
    {
        // Regression: simulate a TwoWay ComboBox binding that re-reads the getter inside
        // PropertyChanged(SelectedTunnel) and writes the result straight back to the setter.
        // Pre-fix, the setter assigned TunnelEnabled before SelectedTunnelConfigId via the
        // generated setters, so the re-entrant handler would observe (true, null), get null
        // from the getter, write null back, and the outer setter's second assignment would
        // leave the pair as (null, newId) — the "inherit-enable + override-config" state,
        // not what the user picked. The fix is a field-bypass + single notification.
        var wg = new TunnelConfig { Id = Guid.NewGuid(), Name = "office-wg", Kind = TunnelKind.WireGuard };
        var vm = new TunnelPickerViewModel(new MultiRepo(wg));
        await vm.LoadAsync();
        vm.SelectedTunnel = TunnelPickerViewModel.NoTunnel; // start from (false, null)

        var reentered = false;
        vm.PropertyChanged += (_, e) =>
        {
            if (reentered) return;
            if (e.PropertyName != nameof(TunnelPickerViewModel.SelectedTunnel)) return;
            reentered = true;
            // Mirror what a TwoWay binding would do: re-read and round-trip.
            vm.SelectedTunnel = vm.SelectedTunnel;
        };

        vm.SelectedTunnel = wg;

        // Both fields must reflect the user's selection — not the inconsistent intermediate
        // state a non-atomic setter would settle on.
        Assert.True(vm.TunnelEnabled);
        Assert.Equal(wg.Id, vm.SelectedTunnelConfigId);
        Assert.Same(wg, vm.SelectedTunnel);
    }

    private static TunnelPickerViewModel NewPicker() => new(new EmptyRepo());

    private sealed class EmptyRepo : ITunnelConfigRepository
    {
        public Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<TunnelConfig>>(Array.Empty<TunnelConfig>());
        public Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult<TunnelConfig?>(null);
        public Task AddAsync(TunnelConfig config, CancellationToken ct = default) => throw new NotImplementedException();
        public Task UpdateAsync(TunnelConfig config, CancellationToken ct = default) => throw new NotImplementedException();
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => throw new NotImplementedException();
    }

    private sealed class MultiRepo : ITunnelConfigRepository
    {
        private readonly TunnelConfig[] _configs;
        public MultiRepo(params TunnelConfig[] configs) => _configs = configs;
        public Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<TunnelConfig>>(_configs);
        public Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult<TunnelConfig?>(Array.Find(_configs, c => c.Id == id));
        public Task AddAsync(TunnelConfig config, CancellationToken ct = default) => throw new NotImplementedException();
        public Task UpdateAsync(TunnelConfig config, CancellationToken ct = default) => throw new NotImplementedException();
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => throw new NotImplementedException();
    }
}
