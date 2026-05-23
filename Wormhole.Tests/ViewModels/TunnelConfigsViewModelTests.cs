using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels;
using Xunit;

// NullLogger<T>.Instance is in Microsoft.Extensions.Logging.Abstractions; the static factory's
// generic CreateLogger<T> extension lives in Microsoft.Extensions.Logging, which is a separate
// namespace we don't need here — pulling NullLogger<T> directly avoids the extra import.

namespace Wormhole.Tests.ViewModels;

public class TunnelConfigsViewModelTests
{
    [Fact]
    public async Task Load_HydratesConfigsFromRepository()
    {
        var (vm, repo, _, _, _) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };

        await vm.LoadCommand.ExecuteAsync(null);

        Assert.Single(vm.Configs);
        Assert.Equal("alpha", vm.Configs[0].Name);
        Assert.False(vm.IsEmpty);
        Assert.True(vm.HasMatches);
    }

    [Fact]
    public async Task IsEmpty_IsTrueWhenNoConfigs()
    {
        var (vm, _, _, _, _) = CreateVm();

        await vm.LoadCommand.ExecuteAsync(null);

        Assert.True(vm.IsEmpty);
        Assert.False(vm.HasMatches);
        Assert.False(vm.HasNoMatches);
    }

    [Fact]
    public async Task Filter_NarrowsByName_CaseInsensitive()
    {
        var (vm, repo, _, _, _) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "corp-vpn", Kind = TunnelKind.WireGuard };
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "home-vpn", Kind = TunnelKind.WireGuard };
        await vm.LoadCommand.ExecuteAsync(null);

        vm.SearchText = "CORP";

        Assert.Single(vm.FilteredConfigs);
        Assert.Equal("corp-vpn", vm.FilteredConfigs[0].Name);
        Assert.True(vm.HasMatches);
        Assert.False(vm.HasNoMatches);
    }

    [Fact]
    public async Task Filter_WhitespaceOnly_ShowsAll()
    {
        var (vm, repo, _, _, _) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "alpha", Kind = TunnelKind.WireGuard };
        await vm.LoadCommand.ExecuteAsync(null);

        vm.SearchText = "   ";

        Assert.Single(vm.FilteredConfigs);
    }

    [Fact]
    public async Task Filter_NoMatch_FlipsHasNoMatches()
    {
        var (vm, repo, _, _, _) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "alpha", Kind = TunnelKind.WireGuard };
        await vm.LoadCommand.ExecuteAsync(null);

        vm.SearchText = "zzz";

        Assert.False(vm.HasMatches);
        Assert.True(vm.HasNoMatches);
        Assert.False(vm.IsEmpty);
    }

    [Fact]
    public async Task AddTunnel_CommitsRowAndSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = NewWireGuardDraft("corp-vpn");

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Single(repo.Configs.Values);
        var stored = repo.Configs.Values.Single();
        Assert.Equal("corp-vpn", stored.Name);
        Assert.True(creds.TunnelConfigs.ContainsKey(stored.Id));
        Assert.Single(vm.Configs);
    }

    [Fact]
    public async Task AddTunnel_NullDraft_NoSideEffects()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = null;

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Empty(vm.Configs);
    }

    [Fact]
    public async Task AddTunnel_DuplicateName_CaseInsensitive_Rejects()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "corp-vpn", Kind = TunnelKind.WireGuard };
        await vm.LoadCommand.ExecuteAsync(null);
        dialog.TunnelPromptResult = NewWireGuardDraft("CORP-VPN");

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Single(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Name already in use");
    }

    [Fact]
    public async Task AddTunnel_MissingRequiredField_RejectsBeforePersist()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        // Empty PeerEndpoint — bypasses dialog IsValid only in a programmatic-caller scenario,
        // but ValidateDraft is the defense-in-depth that protects the repo either way.
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-vpn",
            TunnelKind.WireGuard,
            new WireGuardSettings
            {
                InterfacePrivateKey = "k1",
                InterfaceAddress = "10.0.0.2/32",
                PeerPublicKey = "k2",
                PeerEndpoint = "",
            });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task AddTunnel_WhitespaceName_RejectsViaValidation()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        // Defense-in-depth: a programmatic caller bypassing the dialog's IsValid gate
        // shouldn't be able to insert a whitespace-only Name.
        dialog.TunnelPromptResult = new TunnelDraft(
            "   ",
            TunnelKind.WireGuard,
            new WireGuardSettings
            {
                InterfacePrivateKey = "k1",
                InterfaceAddress = "10.0.0.2/32",
                PeerPublicKey = "k2",
                PeerEndpoint = "host:51820",
            });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task AddTunnel_SecretWriteFails_RollsBackRow()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        creds.ThrowOnStoreTunnelConfig = true;
        dialog.TunnelPromptResult = NewWireGuardDraft("corp-vpn");

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs); // row rolled back
        Assert.Empty(creds.TunnelConfigs); // secret never wrote
        Assert.Empty(vm.Configs);
        Assert.Contains(dialog.Messages, m => m.title == "Couldn't save tunnel");
    }

    [Fact]
    public async Task EditTunnel_AllowsSameNameForSameId()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        var existing = new TunnelConfig { Id = id, Name = "corp-vpn", Kind = TunnelKind.WireGuard };
        repo.Configs[id] = existing;
        creds.TunnelConfigs[id] = JsonSerializer.SerializeToUtf8Bytes(new WireGuardSettings
        {
            InterfacePrivateKey = "k1",
            InterfaceAddress = "10.0.0.2/32",
            PeerPublicKey = "k2",
            PeerEndpoint = "host:51820",
        });
        await vm.LoadCommand.ExecuteAsync(null);

        // Same name, different endpoint — should be allowed.
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-vpn",
            TunnelKind.WireGuard,
            new WireGuardSettings
            {
                InterfacePrivateKey = "k1",
                InterfaceAddress = "10.0.0.2/32",
                PeerPublicKey = "k2",
                PeerEndpoint = "host2:51820",
            });

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.DoesNotContain(dialog.Messages, m => m.title == "Name already in use");
        var stored = JsonSerializer.Deserialize<WireGuardSettings>(creds.TunnelConfigs[id])!;
        Assert.Equal("host2:51820", stored.PeerEndpoint);
    }

    [Fact]
    public async Task EditTunnel_RenameToOtherExistingName_Rejects()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var idA = Guid.NewGuid();
        var idB = Guid.NewGuid();
        repo.Configs[idA] = new TunnelConfig { Id = idA, Name = "alpha", Kind = TunnelKind.WireGuard };
        repo.Configs[idB] = new TunnelConfig { Id = idB, Name = "beta", Kind = TunnelKind.WireGuard };
        await vm.LoadCommand.ExecuteAsync(null);

        dialog.TunnelPromptResult = NewWireGuardDraft("BETA"); // case-insensitive collision

        var alpha = vm.Configs.Single(c => c.Name == "alpha");
        await vm.EditTunnelCommand.ExecuteAsync(alpha);

        Assert.Contains(dialog.Messages, m => m.title == "Name already in use");
        Assert.Equal("alpha", repo.Configs[idA].Name); // unchanged
    }

    [Fact]
    public async Task EditTunnel_SecretWriteFails_RestoresRow()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };
        creds.TunnelConfigs[id] = JsonSerializer.SerializeToUtf8Bytes(new WireGuardSettings
        {
            InterfacePrivateKey = "k1",
            InterfaceAddress = "10.0.0.2/32",
            PeerPublicKey = "k2",
            PeerEndpoint = "host:51820",
        });
        await vm.LoadCommand.ExecuteAsync(null);
        creds.ThrowOnStoreTunnelConfig = true;
        dialog.TunnelPromptResult = NewWireGuardDraft("renamed");

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        // Row Name should have been rolled back to "alpha".
        Assert.Equal("alpha", repo.Configs[id].Name);
        Assert.Contains(dialog.Messages, m => m.title == "Couldn't update tunnel");
    }

    [Fact]
    public async Task DeleteTunnel_WhenReferenced_RefusesAndKeepsRow()
    {
        var (vm, repo, conns, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };
        creds.TunnelConfigs[id] = new byte[] { 1 };
        conns.References[id] = new List<(Guid, string)> { (Guid.NewGuid(), "prod-edge") };
        await vm.LoadCommand.ExecuteAsync(null);
        dialog.ConfirmResult = true; // would be confirmed if we got that far

        await vm.DeleteTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.Single(repo.Configs); // still there
        Assert.True(creds.TunnelConfigs.ContainsKey(id));
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel is in use");
    }

    [Fact]
    public async Task DeleteTunnel_ManyReferences_RendersAndMoreSuffix()
    {
        var (vm, repo, conns, _, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };
        // Repository caps the result at limit (sampleCap+1 = 4); we return 4 to signal "more".
        conns.References[id] = new List<(Guid, string)>
        {
            (Guid.NewGuid(), "a"),
            (Guid.NewGuid(), "b"),
            (Guid.NewGuid(), "c"),
            (Guid.NewGuid(), "d"),
        };
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.DeleteTunnelCommand.ExecuteAsync(vm.Configs[0]);

        var msg = dialog.Messages.Single(m => m.title == "Tunnel is in use").message;
        Assert.Contains("'a', 'b', 'c' and more", msg);
    }

    [Fact]
    public async Task DeleteTunnel_NotConfirmed_KeepsRow()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };
        creds.TunnelConfigs[id] = new byte[] { 1 };
        await vm.LoadCommand.ExecuteAsync(null);
        dialog.ConfirmResult = false;

        await vm.DeleteTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.Single(repo.Configs);
        Assert.True(creds.TunnelConfigs.ContainsKey(id));
    }

    [Fact]
    public async Task DeleteTunnel_Confirmed_ClearsRowAndSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };
        creds.TunnelConfigs[id] = new byte[] { 1 };
        await vm.LoadCommand.ExecuteAsync(null);
        dialog.ConfirmResult = true;

        await vm.DeleteTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.Empty(repo.Configs);
        Assert.False(creds.TunnelConfigs.ContainsKey(id));
        Assert.Empty(vm.Configs);
    }

    private static TunnelDraft NewWireGuardDraft(string name) =>
        new(name, TunnelKind.WireGuard, new WireGuardSettings
        {
            InterfacePrivateKey = "k1",
            InterfaceAddress = "10.0.0.2/32",
            PeerPublicKey = "k2",
            PeerEndpoint = "host:51820",
        });

    private static (
        TunnelConfigsViewModel Vm,
        FakeTunnelConfigRepository Repo,
        FakeConnectionRepository Conns,
        FakeCredentialService Creds,
        FakeDialog Dialog) CreateVm()
    {
        var repo = new FakeTunnelConfigRepository();
        var conns = new FakeConnectionRepository();
        var creds = new FakeCredentialService();
        var dialog = new FakeDialog();
        var vm = new TunnelConfigsViewModel(
            repo, conns, creds, dialog,
            NullLogger<TunnelConfigsViewModel>.Instance);
        return (vm, repo, conns, creds, dialog);
    }

    private sealed class FakeConnectionRepository : IConnectionRepository
    {
        public Dictionary<Guid, List<(Guid Id, string Name)>> References { get; } = new();

        public Task<IReadOnlyList<ConnectionNode>> GetAllAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<ConnectionNode>>(Array.Empty<ConnectionNode>());

        public Task<ConnectionNode?> GetByIdAsync(Guid id, CancellationToken ct = default) =>
            Task.FromResult<ConnectionNode?>(null);

        public Task<IReadOnlyList<(Guid Id, string Name)>> GetByTunnelConfigIdAsync(
            Guid tunnelConfigId, int limit, CancellationToken ct = default)
        {
            if (!References.TryGetValue(tunnelConfigId, out var refs))
                return Task.FromResult<IReadOnlyList<(Guid, string)>>(Array.Empty<(Guid, string)>());
            return Task.FromResult<IReadOnlyList<(Guid, string)>>(refs.Take(limit).ToList());
        }

        public Task AddAsync(ConnectionNode node, CancellationToken ct = default) => Task.CompletedTask;
        public Task UpdateAsync(ConnectionNode node, CancellationToken ct = default) => Task.CompletedTask;
        public Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, CancellationToken ct = default) => Task.CompletedTask;
        public Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, CancellationToken ct = default) => Task.CompletedTask;
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class FakeDialog : IDialogService
    {
        public List<(string title, string message)> Messages { get; } = new();
        public bool ConfirmResult { get; set; } = true;
        public TunnelDraft? TunnelPromptResult { get; set; }

        public Task ShowMessageAsync(string title, string message)
        {
            Messages.Add((title, message));
            return Task.CompletedTask;
        }

        public Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No") =>
            Task.FromResult(ConfirmResult);

        public Task<string?> PromptForTextAsync(string title, string label, string defaultValue = "") =>
            Task.FromResult<string?>(null);

        public Task<ConnectionNode?> EditConnectionAsync(ConnectionNode initial, bool isNew) =>
            Task.FromResult<ConnectionNode?>(null);

        public Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null) =>
            Task.FromResult<CredentialDraft?>(null);

        public Task<TunnelDraft?> PromptForTunnelAsync(TunnelDraft? initial = null) =>
            Task.FromResult(TunnelPromptResult);

        public Task<string?> PromptPasswordAsync(string title, string message) =>
            Task.FromResult<string?>(null);

        public Task<MRemoteNgImportResult?> PromptForMRemoteNgImportAsync() =>
            Task.FromResult<MRemoteNgImportResult?>(null);
    }
}
