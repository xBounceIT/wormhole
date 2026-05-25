using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class FolderEditorViewModelTests
{
    [Fact]
    public void InheritLabel_IsParentScoped_NotFolderScoped()
    {
        // A folder's parent could be another folder OR the root. "(Inherit from parent)"
        // reads naturally in both cases; the connection editor sticks with the
        // "(Inherit from folder)" wording it's always used.
        var vm = new FolderEditorViewModel(new EmptyRepo());
        Assert.Equal("(Inherit from parent)", vm.TunnelPicker.InheritTunnel.Name);
    }

    [Fact]
    public void IsValid_RequiresNonWhitespaceName()
    {
        var vm = new FolderEditorViewModel(new EmptyRepo());
        Assert.False(vm.IsValid);

        vm.Name = "   ";
        Assert.False(vm.IsValid);

        vm.Name = "Production";
        Assert.True(vm.IsValid);
    }

    [Fact]
    public async Task RoundTrip_InheritState_PersistsAsNullEnabledAndNullId()
    {
        var vm = new FolderEditorViewModel(new EmptyRepo());
        await vm.LoadTunnelConfigsAsync();

        var node = new ConnectionNode { Kind = NodeKind.Folder, Name = "Linux", TunnelEnabled = null, TunnelConfigId = null };
        vm.LoadFrom(node);

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);

        Assert.Equal("Linux", sink.Name);
        Assert.Null(sink.TunnelEnabled);
        Assert.Null(sink.TunnelConfigId);
    }

    [Fact]
    public async Task RoundTrip_NoTunnelOverride_PersistsAsFalseEnabledAndNullId()
    {
        var vm = new FolderEditorViewModel(new EmptyRepo());
        await vm.LoadTunnelConfigsAsync();

        var node = new ConnectionNode { Kind = NodeKind.Folder, Name = "Servers", TunnelEnabled = false, TunnelConfigId = null };
        vm.LoadFrom(node);

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);

        Assert.False(sink.TunnelEnabled);
        Assert.Null(sink.TunnelConfigId);
    }

    [Fact]
    public async Task RoundTrip_NamedTunnel_PersistsBothFields()
    {
        var wg = new TunnelConfig { Id = Guid.NewGuid(), Name = "office-wg", Kind = TunnelKind.WireGuard };
        var vm = new FolderEditorViewModel(new MultiRepo(wg));
        await vm.LoadTunnelConfigsAsync();

        var node = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Production",
            TunnelEnabled = true,
            TunnelConfigId = wg.Id,
        };
        vm.LoadFrom(node);
        Assert.Same(wg, vm.TunnelPicker.SelectedTunnel);

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);

        Assert.Equal("Production", sink.Name);
        Assert.True(sink.TunnelEnabled);
        Assert.Equal(wg.Id, sink.TunnelConfigId);
    }

    [Fact]
    public void WriteTo_TrimsWhitespaceFromName()
    {
        var vm = new FolderEditorViewModel(new EmptyRepo());
        vm.Name = "  Production  ";

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);

        Assert.Equal("Production", sink.Name);
    }

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
