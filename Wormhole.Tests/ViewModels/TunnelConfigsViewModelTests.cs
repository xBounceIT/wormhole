using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Tunneling;
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
    public async Task Load_ReplacesConfigsAndFilterWithSingleReset()
    {
        var (vm, repo, _, _, _) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "alpha", Kind = TunnelKind.WireGuard };
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "beta", Kind = TunnelKind.OpenVpn };

        var configResets = 0;
        var filterResets = 0;
        vm.Configs.CollectionChanged += (_, args) =>
        {
            if (args.Action == NotifyCollectionChangedAction.Reset) configResets++;
        };
        vm.FilteredConfigs.CollectionChanged += (_, args) =>
        {
            if (args.Action == NotifyCollectionChangedAction.Reset) filterResets++;
        };

        await vm.LoadCommand.ExecuteAsync(null);

        Assert.Equal(1, configResets);
        Assert.Equal(1, filterResets);
        Assert.Equal(2, vm.Configs.Count);
        Assert.Equal(2, vm.FilteredConfigs.Count);
    }

    [Fact]
    public async Task EnsureLoadedAsync_skips_repository_after_successful_load()
    {
        var (vm, repo, _, _, _) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "alpha", Kind = TunnelKind.WireGuard };

        await vm.EnsureLoadedAsync();
        await vm.EnsureLoadedAsync();

        Assert.Equal(1, repo.GetAllCallCount);
        Assert.Single(vm.Configs);
    }

    [Fact]
    public async Task LoadCommand_still_forces_refresh_after_ensure_loaded()
    {
        var (vm, repo, _, _, _) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "alpha", Kind = TunnelKind.WireGuard };

        await vm.EnsureLoadedAsync();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "beta", Kind = TunnelKind.OpenVpn };

        await vm.LoadCommand.ExecuteAsync(null);

        Assert.Equal(2, repo.GetAllCallCount);
        Assert.Equal(2, vm.Configs.Count);
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
    public async Task SearchText_debounces_filter_rebuilds_to_latest_value()
    {
        var (vm, repo, _, _, _) = CreateVm();
        vm.SearchDebounceDelay = TimeSpan.FromMilliseconds(40);
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "alpha", Kind = TunnelKind.WireGuard };
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "beta", Kind = TunnelKind.OpenVpn };
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "gamma", Kind = TunnelKind.Fortinet };
        await vm.LoadCommand.ExecuteAsync(null);

        vm.SearchText = "a";
        vm.SearchText = "fort";

        Assert.Equal(3, vm.FilteredConfigs.Count);

        // The 40ms debounce applies on a thread-pool continuation; under CI load that can land
        // after a fixed wait, which made racing a single Task.Delay(90) flaky. Poll for the
        // settled state — the debounce collapsing to the LATEST query ("fort") — instead, with a
        // generous ceiling so a slow runner passes while a fast one returns in ~40ms.
        await WaitForFilteredCountAsync(vm, expected: 1, timeout: TimeSpan.FromSeconds(5));

        Assert.Single(vm.FilteredConfigs);
        Assert.Equal("gamma", vm.FilteredConfigs[0].Name);
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
            },
            OpenVpn: null,
            Fortinet: null);

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
            },
            OpenVpn: null,
            Fortinet: null);

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
            },
            OpenVpn: null,
            Fortinet: null);

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.DoesNotContain(dialog.Messages, m => m.title == "Name already in use");
        var stored = JsonSerializer.Deserialize<WireGuardSettings>(creds.TunnelConfigs[id])!;
        Assert.Equal("host2:51820", stored.PeerEndpoint);
    }

    [Fact]
    public async Task EditTunnel_RefreshesActiveFilter()
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
        vm.SearchText = "alpha";
        Assert.Single(vm.FilteredConfigs);

        dialog.TunnelPromptResult = NewWireGuardDraft("renamed");

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.Empty(vm.FilteredConfigs);
        Assert.True(vm.HasNoMatches);
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

    [Fact]
    public async Task TestTunnel_OpensTestDialogForSelectedConfig()
    {
        // The establish-and-tear-down diagnostic now lives in the tunnel-test dialog (which streams
        // live progress + logs). The page VM only routes the selected config to it and gates
        // re-entrancy via IsTestingTunnel — see TunnelTestDialogViewModelTests for the run behavior.
        var (vm, repo, _, _, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.TestTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.False(vm.IsTestingTunnel);
        var tested = Assert.Single(dialog.TunnelTestConfigs);
        Assert.Equal(id, tested.Id);
    }

    [Fact]
    public async Task TestTunnel_NullConfig_DoesNotOpenDialog()
    {
        var (vm, _, _, _, dialog) = CreateVm();

        await vm.TestTunnelCommand.ExecuteAsync(null);

        Assert.Empty(dialog.TunnelTestConfigs);
        Assert.False(vm.IsTestingTunnel);
    }

    [Fact]
    public async Task AddTunnel_OpenVpn_CommitsRowAndSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = NewOpenVpnDraft("corp-ovpn", user: "alice", pass: "s3cret");

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Single(repo.Configs.Values);
        var stored = repo.Configs.Values.Single();
        Assert.Equal("corp-ovpn", stored.Name);
        Assert.Equal(TunnelKind.OpenVpn, stored.Kind);
        Assert.True(creds.TunnelConfigs.ContainsKey(stored.Id));
        var ovpn = JsonSerializer.Deserialize<OpenVpnSettings>(creds.TunnelConfigs[stored.Id])!;
        Assert.Contains("remote vpn.example.com", ovpn.ProfileOvpn);
        Assert.Equal("alice", ovpn.Username);
        Assert.Equal("s3cret", ovpn.Password);
    }

    [Fact]
    public async Task AddTunnel_OpenVpn_MissingProfile_RejectsBeforePersist()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        // Empty profile — programmatic-caller path; ValidateOpenVpn is the defense-in-depth.
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-ovpn",
            TunnelKind.OpenVpn,
            WireGuard: null,
            new OpenVpnSettings { ProfileOvpn = "" },
            Fortinet: null);

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task AddTunnel_FortinetKind_CommitsRowAndSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = NewFortinetDraft("corp-forti");

        await vm.AddTunnelCommand.ExecuteAsync(null);

        var stored = Assert.Single(repo.Configs.Values);
        Assert.Equal(TunnelKind.Fortinet, stored.Kind);
        Assert.True(creds.TunnelConfigs.ContainsKey(stored.Id));
        var roundTrip = JsonSerializer.Deserialize<FortinetSettings>(creds.TunnelConfigs[stored.Id])!;
        Assert.Equal("vpn.example.com", roundTrip.Host);
        Assert.Equal(443, roundTrip.Port);
        Assert.Equal("alice", roundTrip.Username);
        Assert.Equal("s3cret", roundTrip.Password);
    }

    [Fact]
    public async Task AddTunnel_FortinetKind_MissingHost_RejectsBeforePersist()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-forti",
            TunnelKind.Fortinet,
            WireGuard: null,
            OpenVpn: null,
            new FortinetSettings { Host = "", Port = 443, Username = "u", Password = "p" });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task AddTunnel_OpenVpn_NullSettings_RejectsViaValidation()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        // OpenVpn kind without an OpenVpnSettings payload — should never happen from the
        // dialog, but ValidateDraft must catch programmatic misuse before SerializeSecret
        // is asked to serialize null.
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-ovpn",
            TunnelKind.OpenVpn,
            WireGuard: null,
            OpenVpn: null,
            Fortinet: null);

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task EditTunnel_FortinetKind_RoundTripsSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "corp-forti", Kind = TunnelKind.Fortinet };
        creds.TunnelConfigs[id] = JsonSerializer.SerializeToUtf8Bytes(new FortinetSettings
        {
            Host = "vpn.old.com",
            Port = 443,
            Username = "alice",
            Password = "old",
        });
        await vm.LoadCommand.ExecuteAsync(null);

        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-forti",
            TunnelKind.Fortinet,
            WireGuard: null,
            OpenVpn: null,
            new FortinetSettings
            {
                Host = "vpn.new.com",
                Port = 10443,
                Username = "alice",
                Password = "new",
            });

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        var stored = JsonSerializer.Deserialize<FortinetSettings>(creds.TunnelConfigs[id])!;
        Assert.Equal("vpn.new.com", stored.Host);
        Assert.Equal(10443, stored.Port);
        Assert.Equal("new", stored.Password);
    }

    [Fact]
    public async Task AddTunnel_StormshieldKind_CommitsRowAndSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = NewStormshieldDraft("corp-storm");

        await vm.AddTunnelCommand.ExecuteAsync(null);

        var stored = Assert.Single(repo.Configs.Values);
        Assert.Equal(TunnelKind.Stormshield, stored.Kind);
        Assert.True(creds.TunnelConfigs.ContainsKey(stored.Id));
        var roundTrip = JsonSerializer.Deserialize<StormshieldSettings>(creds.TunnelConfigs[stored.Id])!;
        Assert.Equal("rpv.example.com", roundTrip.Server);
        Assert.Equal(StormshieldConnectionMode.Automatic, roundTrip.Mode);
        Assert.Equal("alice", roundTrip.Username);
        Assert.Equal("s3cret", roundTrip.Password);
    }

    [Fact]
    public async Task AddTunnel_StormshieldKind_AutomaticMissingCredentials_RejectsBeforePersist()
    {
        // Automatic mode (no SSO) requires username + password — ValidateStormshield must reject
        // before any row or secret is written.
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-storm",
            TunnelKind.Stormshield,
            WireGuard: null,
            OpenVpn: null,
            Fortinet: null,
            Watchguard: null,
            new StormshieldSettings
            {
                Server = "rpv.example.com",
                Port = 443,
                Mode = StormshieldConnectionMode.Automatic,
                Username = "",
                Password = "",
            });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task AddTunnel_StormshieldKind_ImportMissingProfile_RejectsBeforePersist()
    {
        // Import mode requires a profile — an empty ProfileOvpn must be rejected before persist.
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-storm",
            TunnelKind.Stormshield,
            WireGuard: null,
            OpenVpn: null,
            Fortinet: null,
            Watchguard: null,
            new StormshieldSettings
            {
                Server = "rpv.example.com",
                Port = 443,
                Mode = StormshieldConnectionMode.Import,
                ProfileOvpn = "",
            });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task AddTunnel_StormshieldKind_ImportModeWithoutServer_Persists()
    {
        // Import mode uses the pasted profile's own `remote`, so Server is not required — a user
        // who only has the downloaded .ovpn must be able to save without inventing a gateway value.
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-storm-import",
            TunnelKind.Stormshield,
            WireGuard: null,
            OpenVpn: null,
            Fortinet: null,
            Watchguard: null,
            new StormshieldSettings
            {
                Server = "",
                Mode = StormshieldConnectionMode.Import,
                ProfileOvpn = "client\ndev tun\nremote vpn.example.com 443 tcp\n",
            });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        var stored = Assert.Single(repo.Configs.Values);
        Assert.Equal(TunnelKind.Stormshield, stored.Kind);
        Assert.True(creds.TunnelConfigs.ContainsKey(stored.Id));
        var roundTrip = JsonSerializer.Deserialize<StormshieldSettings>(creds.TunnelConfigs[stored.Id])!;
        Assert.Equal(StormshieldConnectionMode.Import, roundTrip.Mode);
        Assert.Equal(string.Empty, roundTrip.Server);
    }

    [Fact]
    public async Task EditTunnel_StormshieldKind_RoundTripsSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "corp-storm", Kind = TunnelKind.Stormshield };
        creds.TunnelConfigs[id] = JsonSerializer.SerializeToUtf8Bytes(new StormshieldSettings
        {
            Server = "rpv.old.com",
            Port = 443,
            Mode = StormshieldConnectionMode.Automatic,
            Username = "alice",
            Password = "old",
        });
        await vm.LoadCommand.ExecuteAsync(null);

        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-storm",
            TunnelKind.Stormshield,
            WireGuard: null,
            OpenVpn: null,
            Fortinet: null,
            Watchguard: null,
            new StormshieldSettings
            {
                Server = "rpv.new.com",
                Port = 8443,
                Mode = StormshieldConnectionMode.Automatic,
                Username = "alice",
                Password = "new",
                UseOtp = true,
            });

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        var stored = JsonSerializer.Deserialize<StormshieldSettings>(creds.TunnelConfigs[id])!;
        Assert.Equal("rpv.new.com", stored.Server);
        Assert.Equal(8443, stored.Port);
        Assert.Equal("new", stored.Password);
        Assert.True(stored.UseOtp);
    }

    [Fact]
    public async Task EditTunnel_OpenVpn_RoundTripsProfileAndCredentials()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "corp-ovpn", Kind = TunnelKind.OpenVpn };
        creds.TunnelConfigs[id] = JsonSerializer.SerializeToUtf8Bytes(new OpenVpnSettings
        {
            ProfileOvpn = "client\nremote old.example.com 1194\n",
            Username = "alice",
            Password = "old-pass",
        });
        await vm.LoadCommand.ExecuteAsync(null);

        dialog.TunnelPromptResult = NewOpenVpnDraft(
            "corp-ovpn",
            profile: "client\nremote new.example.com 1194\n",
            user: "alice",
            pass: "new-pass");

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        var stored = JsonSerializer.Deserialize<OpenVpnSettings>(creds.TunnelConfigs[id])!;
        Assert.Contains("new.example.com", stored.ProfileOvpn);
        Assert.Equal("new-pass", stored.Password);
    }

    [Fact]
    public async Task EditTunnel_OpenVpn_MissingBlob_WarnsThenLoadsEmptyDraftWithoutThrowing()
    {
        // Defense-in-depth: a missing/corrupt secret on disk should surface as a blank-form
        // repair path, not an unhandled exception in the dialog flow. The warning dialog
        // before the form opens prevents a casual Save from durably overwriting the (possibly
        // recoverable) bytes with empty defaults.
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "corp-ovpn", Kind = TunnelKind.OpenVpn };
        // intentionally no entry in creds.TunnelConfigs
        await vm.LoadCommand.ExecuteAsync(null);

        dialog.TunnelPromptResult = null; // user cancels the dialog after seeing the blank form

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        // No throw; row unchanged. The user should have seen a load-failure warning BEFORE
        // the dialog opened so a casual Save wouldn't durably overwrite recoverable bytes.
        Assert.Equal("corp-ovpn", repo.Configs[id].Name);
        Assert.DoesNotContain(dialog.Messages, m => m.title == "Couldn't update tunnel");
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings couldn't be loaded");
    }

    [Fact]
    public async Task EditTunnel_OpenVpn_CorruptBlob_WarnsBeforeOpeningDialog()
    {
        // A blob that exists but fails JSON.Deserialize must surface a "couldn't be loaded"
        // warning BEFORE the dialog opens, distinct from the missing-blob path. Without this,
        // a casual Save would overwrite the partially-recoverable bytes with empty defaults.
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "corp-ovpn", Kind = TunnelKind.OpenVpn };
        creds.TunnelConfigs[id] = new byte[] { 0xFF, 0xFE, 0xFD, 0xFC }; // not valid JSON
        await vm.LoadCommand.ExecuteAsync(null);
        dialog.TunnelPromptResult = null; // user cancels after seeing the warning

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings couldn't be loaded");
        // Corrupt blob is preserved on disk because the user cancelled — no write happened.
        Assert.Equal(new byte[] { 0xFF, 0xFE, 0xFD, 0xFC }, creds.TunnelConfigs[id]);
    }

    [Fact]
    public async Task EditTunnel_OpenVpn_HealthyBlob_DoesNotWarn()
    {
        // The corruption warning is a defense-in-depth path; a healthy round-trip must not
        // surface it (would scare users and dilute the signal when it really fires).
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "corp-ovpn", Kind = TunnelKind.OpenVpn };
        creds.TunnelConfigs[id] = JsonSerializer.SerializeToUtf8Bytes(new OpenVpnSettings
        {
            ProfileOvpn = "client\n",
        });
        await vm.LoadCommand.ExecuteAsync(null);
        dialog.TunnelPromptResult = null; // user cancels — we're only asserting the absence of the warning

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        Assert.DoesNotContain(dialog.Messages, m => m.title == "Tunnel settings couldn't be loaded");
    }

    [Fact]
    public async Task Filter_NarrowsByKindString_OpenVpn()
    {
        // The filter already searches Kind.ToString() — exercise it for the new value so a
        // refactor of FilteredConfigs doesn't quietly stop matching "OpenVpn".
        var (vm, repo, _, _, _) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "corp", Kind = TunnelKind.WireGuard };
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "home", Kind = TunnelKind.OpenVpn };
        await vm.LoadCommand.ExecuteAsync(null);

        vm.SearchText = "openv";

        Assert.Single(vm.FilteredConfigs);
        Assert.Equal("home", vm.FilteredConfigs[0].Name);
    }

    [Theory]
    [InlineData(TunnelKind.WireGuard, "wire")]
    [InlineData(TunnelKind.OpenVpn, "openv")]
    [InlineData(TunnelKind.Fortinet, "fort")]
    [InlineData(TunnelKind.Watchguard, "watch")]
    [InlineData(TunnelKind.Stormshield, "storm")]
    public async Task Filter_MatchesAllTunnelKindNames(TunnelKind kind, string query)
    {
        var (vm, repo, _, _, _) = CreateVm();
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "match", Kind = kind };
        repo.Configs[Guid.NewGuid()] = new TunnelConfig { Id = Guid.NewGuid(), Name = "other", Kind = OtherKind(kind) };
        await vm.LoadCommand.ExecuteAsync(null);

        vm.SearchText = query;

        Assert.Single(vm.FilteredConfigs);
        Assert.Equal("match", vm.FilteredConfigs[0].Name);
    }

    [Fact]
    public async Task AddTunnel_WatchguardKind_CommitsRowAndSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = NewWatchguardDraft("corp-wgg");

        await vm.AddTunnelCommand.ExecuteAsync(null);

        var stored = Assert.Single(repo.Configs.Values);
        Assert.Equal(TunnelKind.Watchguard, stored.Kind);
        Assert.True(creds.TunnelConfigs.ContainsKey(stored.Id));
        var roundTrip = JsonSerializer.Deserialize<WatchguardSettings>(creds.TunnelConfigs[stored.Id])!;
        Assert.Equal("firebox.example.com", roundTrip.Server);
        Assert.Equal(443, roundTrip.Port);
        Assert.Equal("alice", roundTrip.Username);
        Assert.Equal("s3cret", roundTrip.Password);
        Assert.Equal(string.Empty, roundTrip.Domain);
        Assert.Contains("FAKECA", roundTrip.CaPem);
        Assert.Contains("FAKECERT", roundTrip.ClientCertPem);
        Assert.Contains("FAKEKEY", roundTrip.ClientKeyPem);
    }

    [Fact]
    public async Task AddTunnel_WatchguardKind_MissingCerts_PersistsForNativeDownload()
    {
        // WatchGuard now follows the native client shape: cert/key material is downloaded from
        // client.wgssl during connect, so a save with only gateway + credentials is valid.
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-wgg",
            TunnelKind.Watchguard,
            WireGuard: null,
            OpenVpn: null,
            Fortinet: null,
            Watchguard: new WatchguardSettings
            {
                Server = "firebox.example.com",
                Port = 443,
                Username = "alice",
                Password = "s3cret",
                CaPem = "",
                ClientCertPem = "",
                ClientKeyPem = "",
            });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        var stored = Assert.Single(repo.Configs.Values);
        Assert.Equal(TunnelKind.Watchguard, stored.Kind);
        Assert.True(creds.TunnelConfigs.ContainsKey(stored.Id));
        var roundTrip = JsonSerializer.Deserialize<WatchguardSettings>(creds.TunnelConfigs[stored.Id])!;
        Assert.Equal("firebox.example.com", roundTrip.Server);
        Assert.Equal(string.Empty, roundTrip.CaPem);
        Assert.Empty(dialog.Messages);
    }

    [Fact]
    public async Task AddTunnel_WatchguardKind_SamlMode_AllowsEmptyPassword()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-wgg",
            TunnelKind.Watchguard,
            WireGuard: null,
            OpenVpn: null,
            Fortinet: null,
            Watchguard: new WatchguardSettings
            {
                Server = "firebox.example.com",
                Port = 443,
                AuthMode = WatchguardAuthMode.Saml,
                Username = "",
                Password = "",
            });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        var stored = Assert.Single(repo.Configs.Values);
        var roundTrip = JsonSerializer.Deserialize<WatchguardSettings>(creds.TunnelConfigs[stored.Id])!;
        Assert.Equal(WatchguardAuthMode.Saml, roundTrip.AuthMode);
        Assert.Equal(string.Empty, roundTrip.Password);
    }

    [Fact]
    public async Task AddTunnel_WatchguardKind_AutomaticMode_AllowsEmptyPasswordForSamlDiscovery()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        dialog.TunnelPromptResult = new TunnelDraft(
            "corp-wgg",
            TunnelKind.Watchguard,
            WireGuard: null,
            OpenVpn: null,
            Fortinet: null,
            Watchguard: new WatchguardSettings
            {
                Server = "firebox.example.com",
                Port = 443,
                AuthMode = WatchguardAuthMode.Automatic,
                Username = "",
                Password = "",
            });

        await vm.AddTunnelCommand.ExecuteAsync(null);

        var stored = Assert.Single(repo.Configs.Values);
        var roundTrip = JsonSerializer.Deserialize<WatchguardSettings>(creds.TunnelConfigs[stored.Id])!;
        Assert.Equal(WatchguardAuthMode.Automatic, roundTrip.AuthMode);
        Assert.Equal(string.Empty, roundTrip.Username);
        Assert.Equal(string.Empty, roundTrip.Password);
        Assert.Empty(dialog.Messages);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public async Task AddTunnel_WatchguardKind_RejectsOutOfRangePort(int port)
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var draft = NewWatchguardDraft("corp-wgg");
        draft.Watchguard!.Port = port;
        dialog.TunnelPromptResult = draft;

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task AddTunnel_WatchguardKind_RejectsPemWithAngleBrackets()
    {
        // Hoisted-from-the-builder injection check (ValidateWatchguard -> ValidateFieldSafety):
        // a PEM body containing '<' / '>' would let a literal </ca> close the inline block early
        // and inject directives. Must be rejected at Save, not deferred to a connect-time throw.
        var (vm, repo, _, creds, dialog) = CreateVm();
        var draft = NewWatchguardDraft("corp-wgg");
        draft.Watchguard!.CaPem = "-----BEGIN CERTIFICATE-----\n</ca>\nup /tmp/pwn\n-----END CERTIFICATE-----";
        dialog.TunnelPromptResult = draft;

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task AddTunnel_WatchguardKind_RejectsVerifyX509NameWithControlChars()
    {
        // Same hoisted check for the verify-x509-name subject, which is inlined between quotes
        // in the profile: a newline would let the value inject extra OpenVPN directives.
        var (vm, repo, _, creds, dialog) = CreateVm();
        var draft = NewWatchguardDraft("corp-wgg");
        draft.Watchguard!.VerifyX509Name = "subject\nup /tmp/pwn";
        dialog.TunnelPromptResult = draft;

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Empty(repo.Configs);
        Assert.Empty(creds.TunnelConfigs);
        Assert.Contains(dialog.Messages, m => m.title == "Tunnel settings incomplete");
    }

    [Fact]
    public async Task EditTunnel_WatchguardKind_RoundTripsSecret()
    {
        var (vm, repo, _, creds, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "corp-wgg", Kind = TunnelKind.Watchguard };
        creds.TunnelConfigs[id] = JsonSerializer.SerializeToUtf8Bytes(new WatchguardSettings
        {
            Server = "old.example.com",
            Port = 443,
            Username = "alice",
            Password = "old",
            CaPem = "-----BEGIN CERTIFICATE-----\nOLDCA\n-----END CERTIFICATE-----",
            ClientCertPem = "-----BEGIN CERTIFICATE-----\nOLDCERT\n-----END CERTIFICATE-----",
            ClientKeyPem = "-----BEGIN PRIVATE KEY-----\nOLDKEY\n-----END PRIVATE KEY-----",
        });
        await vm.LoadCommand.ExecuteAsync(null);

        var updated = NewWatchguardDraft("corp-wgg");
        updated.Watchguard!.Server = "new.example.com";
        updated.Watchguard.Port = 6443;
        updated.Watchguard.Password = "new";
        updated.Watchguard.ProfileOvpn = "client\nremote imported.example.com 443\ncipher AES-256-CBC\n";
        dialog.TunnelPromptResult = updated;

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        var stored = JsonSerializer.Deserialize<WatchguardSettings>(creds.TunnelConfigs[id])!;
        Assert.Equal("new.example.com", stored.Server);
        Assert.Equal(6443, stored.Port);
        Assert.Equal("new", stored.Password);
        Assert.Contains("remote imported.example.com 443", stored.ProfileOvpn);
    }

    [Fact]
    public async Task AddTunnel_AppendsToFilteredWithoutReset()
    {
        var (vm, repo, _, _, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };
        await vm.LoadCommand.ExecuteAsync(null);
        dialog.TunnelPromptResult = NewWireGuardDraft("corp-vpn");

        var resetEvents = 0;
        var addEvents = 0;
        vm.FilteredConfigs.CollectionChanged += (_, args) =>
        {
            if (args.Action == NotifyCollectionChangedAction.Reset) resetEvents++;
            if (args.Action == NotifyCollectionChangedAction.Add) addEvents++;
        };

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.Equal(0, resetEvents);
        Assert.Equal(1, addEvents);
        Assert.Equal(2, vm.FilteredConfigs.Count);
        Assert.Equal("corp-vpn", vm.FilteredConfigs[^1].Name);
    }

    [Fact]
    public async Task EditTunnel_RenameWithUnchangedMembership_RaisesNoFilteredEvents()
    {
        var (vm, repo, _, _, dialog) = CreateVm();
        var id = Guid.NewGuid();
        repo.Configs[id] = new TunnelConfig { Id = id, Name = "alpha", Kind = TunnelKind.WireGuard };
        await vm.LoadCommand.ExecuteAsync(null);
        dialog.TunnelPromptResult = NewWireGuardDraft("renamed");

        var events = 0;
        vm.FilteredConfigs.CollectionChanged += (_, _) => events++;

        await vm.EditTunnelCommand.ExecuteAsync(vm.Configs[0]);

        // No search active, so membership is unchanged: the in-place rename must not
        // rebuild the filtered view (TunnelConfig is observable — the card updates via
        // PropertyChanged, not a collection event).
        Assert.Equal(0, events);
        Assert.Equal("renamed", vm.FilteredConfigs.Single().Name);
    }

    [Fact]
    public async Task AddingNonMatchingTunnel_notifies_no_match_state()
    {
        // Regression (Codex review): the incremental mirror can flip IsEmpty without changing
        // FilteredConfigs (first tunnel added under a non-matching search), so HasNoMatches must
        // still be notified or the page shows neither the empty nor the no-match state.
        var (vm, _, _, _, dialog) = CreateVm();
        await vm.LoadCommand.ExecuteAsync(null);
        vm.SearchText = "zzz"; // matches neither the name nor the kind of the tunnel about to be added
        dialog.TunnelPromptResult = NewWireGuardDraft("corp-vpn");

        var notified = new List<string>();
        vm.PropertyChanged += (_, e) => { if (e.PropertyName is not null) notified.Add(e.PropertyName); };

        await vm.AddTunnelCommand.ExecuteAsync(null);

        Assert.False(vm.IsEmpty);
        Assert.False(vm.HasMatches);
        Assert.True(vm.HasNoMatches);
        Assert.Contains(nameof(vm.HasNoMatches), notified);
    }

    private static TunnelDraft NewWireGuardDraft(string name) =>
        new(name, TunnelKind.WireGuard, new WireGuardSettings
        {
            InterfacePrivateKey = "k1",
            InterfaceAddress = "10.0.0.2/32",
            PeerPublicKey = "k2",
            PeerEndpoint = "host:51820",
        }, OpenVpn: null, Fortinet: null);

    private static TunnelDraft NewOpenVpnDraft(string name, string profile = "client\nproto udp\nremote vpn.example.com 1194\n", string? user = null, string? pass = null) =>
        new(name, TunnelKind.OpenVpn, WireGuard: null, new OpenVpnSettings
        {
            ProfileOvpn = profile,
            Username = user,
            Password = pass,
        }, Fortinet: null);

    private static TunnelDraft NewFortinetDraft(string name) =>
        new(name, TunnelKind.Fortinet, WireGuard: null, OpenVpn: null, new FortinetSettings
        {
            Host = "vpn.example.com",
            Port = 443,
            Username = "alice",
            Password = "s3cret",
        });

    private static TunnelDraft NewStormshieldDraft(string name) =>
        new(name, TunnelKind.Stormshield, WireGuard: null, OpenVpn: null, Fortinet: null, Watchguard: null,
            new StormshieldSettings
            {
                Server = "rpv.example.com",
                Port = 443,
                Mode = StormshieldConnectionMode.Automatic,
                Username = "alice",
                Password = "s3cret",
            });

    private static TunnelDraft NewWatchguardDraft(string name) =>
        new(name, TunnelKind.Watchguard, WireGuard: null, OpenVpn: null, Fortinet: null, Watchguard: new WatchguardSettings
        {
            Server = "firebox.example.com",
            Port = 443,
            Username = "alice",
            Password = "s3cret",
            CaPem = "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----",
            ClientCertPem = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----",
            ClientKeyPem = "-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----",
        });

    private static TunnelKind OtherKind(TunnelKind kind) =>
        kind == TunnelKind.WireGuard ? TunnelKind.OpenVpn : TunnelKind.WireGuard;

    // Polls until the view-model's debounced filter settles to the expected count or the
    // timeout elapses, then returns. Avoids racing a fixed Task.Delay against a thread-pool
    // continuation (flaky on loaded CI runners) while staying fast on a healthy runner; if the
    // count never settles, the caller's assertion still fires with the actual value.
    private static async Task WaitForFilteredCountAsync(TunnelConfigsViewModel vm, int expected, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (vm.FilteredConfigs.Count != expected && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }
    }

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
            repo, conns, creds, new FakeStormshieldConfigCache(), new FakeAzureVpnTokenCache(), dialog,
            NullLogger<TunnelConfigsViewModel>.Instance);
        vm.SearchDebounceDelay = TimeSpan.Zero;
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
        public List<TunnelConfig> TunnelTestConfigs { get; } = new();

        public Task ShowMessageAsync(string title, string message)
        {
            Messages.Add((title, message));
            return Task.CompletedTask;
        }

        public Task ShowTunnelTestAsync(TunnelConfig config)
        {
            TunnelTestConfigs.Add(config);
            return Task.CompletedTask;
        }

        public Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No") =>
            Task.FromResult(ConfirmResult);

        public Task<TunnelRouteChoice> PromptTunnelRouteAsync(string connectionName, string tunnelName) =>
            Task.FromResult(TunnelRouteChoice.UseTunnel);

        public Task<string?> PromptForTextAsync(string title, string label, string defaultValue = "") =>
            Task.FromResult<string?>(null);

        public Task<ConnectionNode?> EditConnectionAsync(ConnectionNode initial, bool isNew) =>
            Task.FromResult<ConnectionNode?>(null);

        public Task<ConnectionNode?> EditFolderAsync(ConnectionNode initial, bool isNew) =>
            Task.FromResult<ConnectionNode?>(null);

        public Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null) =>
            Task.FromResult<CredentialDraft?>(null);

        public Task<TunnelDraft?> PromptForTunnelAsync(TunnelDraft? initial = null) =>
            Task.FromResult(TunnelPromptResult);

        public Task<string?> PromptPasswordAsync(string title, string message) =>
            Task.FromResult<string?>(null);

        public Task ShowCredentialsAsync(string title, string username, string secretLabel, string secret) =>
            Task.CompletedTask;

        public Task<(string Username, string Password)?> PromptCredentialsAsync(string title, string message, string? initialUsername = null) =>
            Task.FromResult<(string Username, string Password)?>(null);

        public Task<MRemoteNgImportResult?> PromptForMRemoteNgImportAsync() =>
            Task.FromResult<MRemoteNgImportResult?>(null);

        public Task<Wormhole.Models.Backup.BackupExportResult?> PromptForBackupExportAsync() =>
            Task.FromResult<Wormhole.Models.Backup.BackupExportResult?>(null);

        public Task<Wormhole.Models.Backup.BackupImportResult?> PromptForBackupImportAsync() =>
            Task.FromResult<Wormhole.Models.Backup.BackupImportResult?>(null);
    }
}
