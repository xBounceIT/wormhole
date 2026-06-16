using System;
using System.Collections.Generic;
using System.Linq;
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
        var vm = NewVm();
        Assert.Equal("(Inherit from parent)", vm.TunnelPicker.InheritTunnel.Name);
    }

    [Fact]
    public void IsValid_RequiresNonWhitespaceName()
    {
        var vm = NewVm();
        Assert.False(vm.IsValid);

        vm.Name = "   ";
        Assert.False(vm.IsValid);

        vm.Name = "Production";
        Assert.True(vm.IsValid);
    }

    [Fact]
    public async Task RoundTrip_InheritState_PersistsAsNullEnabledAndNullId()
    {
        var vm = NewVm();
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
        var vm = NewVm();
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
        var vm = NewVm(new MultiRepo(wg));
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
        var vm = NewVm();
        vm.Name = "  Production  ";

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);

        Assert.Equal("Production", sink.Name);
    }

    [Fact]
    public async Task RoundTrip_SshAutoSudoInherit_PersistsNull()
    {
        var vm = NewVm();
        await vm.LoadTunnelConfigsAsync();

        var node = new ConnectionNode { Kind = NodeKind.Folder, Name = "Linux", SshAutoSudo = null };
        vm.LoadFrom(node);
        Assert.Equal(ConnectionEditorViewModel.SshAutoSudoInherit, vm.SshAutoSudoMode);

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);
        Assert.Null(sink.SshAutoSudo);
    }

    [Fact]
    public async Task RoundTrip_SshAutoSudoOn_PersistsTrue()
    {
        // The folder default that makes "Inherit from folder" on a child actually resolve to on.
        var vm = NewVm();
        await vm.LoadTunnelConfigsAsync();

        var node = new ConnectionNode { Kind = NodeKind.Folder, Name = "Linux", SshAutoSudo = true };
        vm.LoadFrom(node);
        Assert.Equal(ConnectionEditorViewModel.SshAutoSudoOn, vm.SshAutoSudoMode);

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);
        Assert.True(sink.SshAutoSudo);
    }

    [Fact]
    public void WriteTo_SshAutoSudoOff_PersistsFalse()
    {
        var vm = NewVm();
        vm.Name = "Linux";
        vm.SshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoOff;

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);
        Assert.False(sink.SshAutoSudo);
    }

    [Fact]
    public async Task RoundTrip_CredentialInherit_PersistsInheritMode()
    {
        var vm = NewVm();
        await vm.LoadCredentialsAsync();

        var node = new ConnectionNode { Kind = NodeKind.Folder, Name = "Linux", CredentialMode = CredentialBindingMode.Inherit };
        vm.LoadFrom(node);

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);

        Assert.Null(sink.CredentialId);
        Assert.Equal(CredentialBindingMode.Inherit, sink.CredentialMode);
    }

    [Fact]
    public async Task RoundTrip_CredentialNone_PersistsNoneMode()
    {
        var vm = NewVm();
        await vm.LoadCredentialsAsync();

        var node = new ConnectionNode { Kind = NodeKind.Folder, Name = "Linux", CredentialMode = CredentialBindingMode.None };
        vm.LoadFrom(node);

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);

        Assert.Null(sink.CredentialId);
        Assert.Equal(CredentialBindingMode.None, sink.CredentialMode);
    }

    [Fact]
    public async Task RoundTrip_SavedCredential_PersistsCredentialAndCopiesUsername()
    {
        var credential = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "prod-admin",
            Username = "admin",
            Protocol = ProtocolType.Ssh,
        };
        var vm = NewVm(credentials: new[] { credential });
        await vm.LoadCredentialsAsync();

        var node = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Linux",
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = credential.Id,
        };
        vm.LoadFrom(node);

        var sink = new ConnectionNode { Kind = NodeKind.Folder };
        vm.WriteTo(sink);

        Assert.Equal(credential.Id, sink.CredentialId);
        Assert.Equal(CredentialBindingMode.Saved, sink.CredentialMode);
        Assert.Equal("admin", sink.Username);
    }

    [Fact]
    public async Task LoadCredentialsAsync_ListsOnlySshAndRdpCredentials()
    {
        var ssh = new CredentialProfile { Id = Guid.NewGuid(), Name = "ssh", Protocol = ProtocolType.Ssh };
        var rdp = new CredentialProfile { Id = Guid.NewGuid(), Name = "rdp", Protocol = ProtocolType.Rdp };
        var http = new CredentialProfile { Id = Guid.NewGuid(), Name = "http", Protocol = ProtocolType.Http };
        var https = new CredentialProfile { Id = Guid.NewGuid(), Name = "https", Protocol = ProtocolType.Https };
        var vm = NewVm(credentials: new[] { ssh, rdp, http, https });

        await vm.LoadCredentialsAsync();

        Assert.Contains(vm.AvailableCredentials, c => c.Id == ssh.Id);
        Assert.Contains(vm.AvailableCredentials, c => c.Id == rdp.Id);
        Assert.DoesNotContain(vm.AvailableCredentials, c => c.Id == http.Id);
        Assert.DoesNotContain(vm.AvailableCredentials, c => c.Id == https.Id);
    }

    [Fact]
    public async Task LoadFrom_MissingSavedCredential_AppendsStaleSelectionAndPreservesUsername()
    {
        var missingCredentialId = Guid.NewGuid();
        var vm = NewVm();
        await vm.LoadCredentialsAsync();
        var node = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Linux",
            CredentialMode = CredentialBindingMode.Saved,
            CredentialId = missingCredentialId,
            Username = "admin",
        };

        vm.LoadFrom(node);

        Assert.Equal(missingCredentialId, vm.SelectedCredential!.Id);
        Assert.Contains("missing credential", vm.SelectedCredential.Name, StringComparison.OrdinalIgnoreCase);
        var sink = node.Clone();
        vm.WriteTo(sink);
        Assert.Equal(missingCredentialId, sink.CredentialId);
        Assert.Equal(CredentialBindingMode.Saved, sink.CredentialMode);
        Assert.Equal("admin", sink.Username);
    }

    [Fact]
    public async Task LoadFrom_LegacyNullModeWithCredential_LoadsAsSavedCredential()
    {
        var credential = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "prod-admin",
            Username = "admin",
            Protocol = ProtocolType.Ssh,
        };
        var vm = NewVm(credentials: new[] { credential });
        await vm.LoadCredentialsAsync();

        var node = new ConnectionNode
        {
            Kind = NodeKind.Folder,
            Name = "Linux",
            CredentialMode = null,
            CredentialId = credential.Id,
        };
        vm.LoadFrom(node);

        Assert.Equal(CredentialBindingMode.Saved, vm.CredentialMode);
        Assert.Equal(credential.Id, vm.SelectedCredential!.Id);
    }

    private static FolderEditorViewModel NewVm(
        ITunnelConfigRepository? tunnels = null,
        IReadOnlyList<CredentialProfile>? credentials = null)
        => new(tunnels ?? new EmptyRepo(), new CredentialRepo(credentials ?? Array.Empty<CredentialProfile>()));

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

    private sealed class CredentialRepo : ICredentialRepository
    {
        private readonly IReadOnlyList<CredentialProfile> _credentials;

        public CredentialRepo(IReadOnlyList<CredentialProfile> credentials) => _credentials = credentials;

        public Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult(_credentials);

        public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult(_credentials.FirstOrDefault(c => c.Id == id));

        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default) => throw new NotImplementedException();
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default) => throw new NotImplementedException();
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
