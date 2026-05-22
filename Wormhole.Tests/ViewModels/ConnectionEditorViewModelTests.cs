using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class ConnectionEditorViewModelTests
{
    [Fact]
    public void ValidateDriveList_EmptyString_Errors()
    {
        Assert.NotNull(ConnectionEditorViewModel.ValidateDriveList(""));
    }

    [Fact]
    public void ValidateDriveList_SingleLetter_Accepted()
    {
        Assert.Null(ConnectionEditorViewModel.ValidateDriveList("C"));
    }

    [Fact]
    public void ValidateDriveList_MultipleLetters_Accepted()
    {
        Assert.Null(ConnectionEditorViewModel.ValidateDriveList("C,D,E"));
    }

    [Theory]
    [InlineData("CC", "'CC'")]
    [InlineData("3", "'3'")]
    [InlineData("@", "'@'")]
    public void ValidateDriveList_InvalidEntries_ProduceErrorMentioningOffender(string raw, string contains)
    {
        var err = ConnectionEditorViewModel.ValidateDriveList(raw);
        Assert.NotNull(err);
        Assert.Contains(contains, err);
    }

    [Fact]
    public void ValidateDriveList_DuplicateLetters_Errors()
    {
        var err = ConnectionEditorViewModel.ValidateDriveList("C,C,D");
        Assert.NotNull(err);
        Assert.Contains("'C'", err);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("C", "C")]
    [InlineData("c,d", "C,D")]
    [InlineData("C, D, E", "C,D,E")]
    [InlineData("C,C,D", "C,D")]
    public void NormaliseDriveList_RoundTripsToCanonicalForm(string raw, string expected)
    {
        Assert.Equal(expected, ConnectionEditorViewModel.NormaliseDriveList(raw));
    }

    [Fact]
    public async Task GatewayValidation_AlwaysUseWithEmptyHostname_BlocksValidity()
    {
        var vm = await NewEditorAsync();
        vm.Name = "n";
        vm.Host = "h";
        vm.Protocol = ProtocolType.Rdp;

        vm.RdpGatewayUsageMethod = 1; // Always use
        vm.RdpGatewayHostname = string.Empty;

        Assert.False(vm.IsValid);
        Assert.NotNull(vm.GatewayHostnameError);

        vm.RdpGatewayHostname = "gw.example.com";
        Assert.True(vm.IsValid);
        Assert.Null(vm.GatewayHostnameError);
    }

    [Fact]
    public async Task ExperiencePreset_Modem_DisablesExpensiveFeatures()
    {
        var vm = await NewEditorAsync();
        vm.RdpDesktopBackground = true;
        vm.RdpFontSmoothing = true;
        vm.RdpVisualStyles = true;

        vm.RdpConnectionSpeed = 1; // Modem — triggers preset

        Assert.False(vm.RdpDesktopBackground);
        Assert.False(vm.RdpFontSmoothing);
        Assert.False(vm.RdpVisualStyles);
        Assert.True(vm.RdpBitmapCaching); // bitmap caching stays on even on Modem
    }

    [Fact]
    public async Task ExperiencePreset_LAN_EnablesAllExperienceFlags()
    {
        var vm = await NewEditorAsync();
        // Force everything off, then flip to LAN.
        vm.RdpDesktopBackground = false;
        vm.RdpFontSmoothing = false;
        vm.RdpDesktopComposition = false;
        vm.RdpWindowDrag = false;
        vm.RdpMenuAnimation = false;
        vm.RdpVisualStyles = false;
        vm.RdpBitmapCaching = false;

        vm.RdpConnectionSpeed = 6; // LAN

        Assert.True(vm.RdpDesktopBackground);
        Assert.True(vm.RdpFontSmoothing);
        Assert.True(vm.RdpDesktopComposition);
        Assert.True(vm.RdpWindowDrag);
        Assert.True(vm.RdpMenuAnimation);
        Assert.True(vm.RdpVisualStyles);
        Assert.True(vm.RdpBitmapCaching);
    }

    [Fact]
    public async Task LoadFrom_ThenWriteTo_IsLossless()
    {
        var credId = Guid.NewGuid();
        var gwCredId = Guid.NewGuid();
        var source = new ConnectionNode
        {
            Id = Guid.NewGuid(),
            Kind = NodeKind.Connection,
            Name = "rdp-rich",
            Protocol = ProtocolType.Rdp,
            Host = "vm.example.com",
            Port = 3389,
            Username = "alice",
            CredentialId = credId,
            RdpDomain = "CORP",
            RdpScreenSize = "1920x1080",
            RdpFullScreen = true,
            RdpColorDepth = 24,
            RdpUseAllMonitors = true,
            RdpAudioMode = 2,
            RdpAudioCaptureMode = 1,
            RdpKeyboardHookMode = 1,
            RdpRedirectClipboard = false,
            RdpRedirectPrinters = true,
            RdpRedirectSmartCards = true,
            RdpRedirectPorts = true,
            RdpRedirectDevices = true,
            RdpRedirectDrives = "C,D",
            RdpConnectionSpeed = 6,
            RdpDesktopBackground = false,
            RdpFontSmoothing = true,
            RdpDesktopComposition = false,
            RdpWindowDrag = true,
            RdpMenuAnimation = false,
            RdpVisualStyles = true,
            RdpBitmapCaching = true,
            RdpAutoReconnect = false,
            RdpServerAuthentication = 2,
            RdpGatewayUsageMethod = 1,
            RdpGatewayHostname = "gw.example.com",
            RdpGatewayCredentialId = gwCredId,
            RdpGatewayBypassLocal = false,
            RdpGatewayUseSameCreds = true,
        };

        var vm = await NewEditorAsync();
        vm.LoadFrom(source);
        var sink = new ConnectionNode { Id = source.Id, Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.Equal(source.Name, sink.Name);
        Assert.Equal(source.Protocol, sink.Protocol);
        Assert.Equal(source.Host, sink.Host);
        Assert.Equal(source.Port, sink.Port);
        Assert.Equal(source.Username, sink.Username);
        Assert.Equal(source.CredentialId, sink.CredentialId);
        Assert.Equal(source.RdpDomain, sink.RdpDomain);
        Assert.Equal(source.RdpScreenSize, sink.RdpScreenSize);
        Assert.Equal(source.RdpFullScreen, sink.RdpFullScreen);
        Assert.Equal(source.RdpColorDepth, sink.RdpColorDepth);
        Assert.Equal(source.RdpUseAllMonitors, sink.RdpUseAllMonitors);
        Assert.Equal(source.RdpAudioMode, sink.RdpAudioMode);
        Assert.Equal(source.RdpAudioCaptureMode, sink.RdpAudioCaptureMode);
        Assert.Equal(source.RdpKeyboardHookMode, sink.RdpKeyboardHookMode);
        Assert.Equal(source.RdpRedirectClipboard, sink.RdpRedirectClipboard);
        Assert.Equal(source.RdpRedirectPrinters, sink.RdpRedirectPrinters);
        Assert.Equal(source.RdpRedirectSmartCards, sink.RdpRedirectSmartCards);
        Assert.Equal(source.RdpRedirectPorts, sink.RdpRedirectPorts);
        Assert.Equal(source.RdpRedirectDevices, sink.RdpRedirectDevices);
        Assert.Equal(source.RdpRedirectDrives, sink.RdpRedirectDrives);
        Assert.Equal(source.RdpConnectionSpeed, sink.RdpConnectionSpeed);
        Assert.Equal(source.RdpDesktopBackground, sink.RdpDesktopBackground);
        Assert.Equal(source.RdpFontSmoothing, sink.RdpFontSmoothing);
        Assert.Equal(source.RdpDesktopComposition, sink.RdpDesktopComposition);
        Assert.Equal(source.RdpWindowDrag, sink.RdpWindowDrag);
        Assert.Equal(source.RdpMenuAnimation, sink.RdpMenuAnimation);
        Assert.Equal(source.RdpVisualStyles, sink.RdpVisualStyles);
        Assert.Equal(source.RdpBitmapCaching, sink.RdpBitmapCaching);
        Assert.Equal(source.RdpAutoReconnect, sink.RdpAutoReconnect);
        Assert.Equal(source.RdpServerAuthentication, sink.RdpServerAuthentication);
        Assert.Equal(source.RdpGatewayUsageMethod, sink.RdpGatewayUsageMethod);
        Assert.Equal(source.RdpGatewayHostname, sink.RdpGatewayHostname);
        Assert.Equal(source.RdpGatewayCredentialId, sink.RdpGatewayCredentialId);
        Assert.Equal(source.RdpGatewayBypassLocal, sink.RdpGatewayBypassLocal);
        Assert.Equal(source.RdpGatewayUseSameCreds, sink.RdpGatewayUseSameCreds);
    }

    [Fact]
    public async Task LoadFrom_AllDrives_TogglesMode()
    {
        var vm = await NewEditorAsync();
        var node = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "x",
            Protocol = ProtocolType.Rdp,
            Host = "h",
            RdpRedirectDrives = "all",
        };

        vm.LoadFrom(node);

        Assert.Equal("all", vm.RdpDriveRedirectMode);
        Assert.Equal(string.Empty, vm.RdpCustomDriveList);
        Assert.False(vm.IsCustomDriveList);
    }

    [Fact]
    public async Task LoadFrom_CustomDrives_PopulatesList()
    {
        var vm = await NewEditorAsync();
        var node = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "x",
            Protocol = ProtocolType.Rdp,
            Host = "h",
            RdpRedirectDrives = "C,D",
        };

        vm.LoadFrom(node);

        Assert.Equal("custom", vm.RdpDriveRedirectMode);
        Assert.Equal("C,D", vm.RdpCustomDriveList);
        Assert.True(vm.IsCustomDriveList);
    }

    [Fact]
    public async Task IsValid_RequiresNonEmptyNameAndHost()
    {
        var vm = await NewEditorAsync();
        Assert.False(vm.IsValid);

        vm.Name = "n";
        Assert.False(vm.IsValid);

        vm.Host = "h";
        Assert.True(vm.IsValid);

        vm.Port = 0;
        Assert.False(vm.IsValid);

        vm.Port = 22;
        Assert.True(vm.IsValid);
    }

    [Fact]
    public async Task IsValid_AllowsNullPortForProtocolDefault()
    {
        // Regression test: null Port means "inherit / use protocol default" and must not
        // gate saving. The NumberBox's "Default for protocol" placeholder relies on this —
        // re-saving an existing connection without typing a number must keep the Save button
        // enabled.
        var vm = await NewEditorAsync();
        vm.Name = "n";
        vm.Host = "h";
        vm.Port = null;

        Assert.True(vm.IsValid);
    }

    [Fact]
    public async Task WriteTo_BlankUsernameWithSelectedCredential_FallsBackToCredentialUsername()
    {
        // Regression for the credential-backed connect path: if the user picks a saved
        // credential but doesn't type into the free-text Username field, the persisted
        // node.Username must still resolve to a non-null login — otherwise the SSH and RDP
        // services reject the profile with "no username supplied".
        var credential = new CredentialProfile
        {
            Name = "prod-svc",
            Username = "svcacct",
            Protocol = ProtocolType.Ssh,
        };
        var repo = new SingleCredentialRepository(credential);
        var vm = new ConnectionEditorViewModel(repo);
        await vm.LoadCredentialsAsync();

        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = credential;
        vm.Username = string.Empty;

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.Equal("svcacct", node.Username);
        Assert.Equal(credential.Id, node.CredentialId);
    }

    [Fact]
    public async Task AvailableCredentials_FiltersToConnectionProtocol()
    {
        var sshCred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(sshCred, rdpCred);
        var vm = new ConnectionEditorViewModel(repo);
        await vm.LoadCredentialsAsync();

        // AvailableCredentials always leads with the "(None)" sentinel for "prompt every
        // time"; the next slot is the protocol-filtered repository entry.
        Assert.Equal(2, vm.AvailableCredentials.Count);
        Assert.Equal(Guid.Empty, vm.AvailableCredentials[0].Id);
        Assert.Equal("ssh", vm.AvailableCredentials[1].Name);

        vm.Protocol = ProtocolType.Rdp;

        Assert.Equal(2, vm.AvailableCredentials.Count);
        Assert.Equal(Guid.Empty, vm.AvailableCredentials[0].Id);
        Assert.Equal("rdp", vm.AvailableCredentials[1].Name);
    }

    [Fact]
    public async Task AvailableCredentials_ExcludesSshKeyCredsForRdpConnections()
    {
        // RDP login resolves the password secret only; offering a key-based credential
        // would funnel the user into a misleading prompt path.
        var rdpPwd = new CredentialProfile { Name = "rdp-pwd", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var rdpKey = new CredentialProfile { Name = "rdp-key", Protocol = ProtocolType.Rdp, Kind = CredentialKind.SshKey };
        var repo = new MultiCredentialRepository(rdpPwd, rdpKey);
        var vm = new ConnectionEditorViewModel(repo);
        vm.Protocol = ProtocolType.Rdp;
        await vm.LoadCredentialsAsync();

        // Sentinel + the one password-kind credential, key-kind filtered out.
        Assert.Equal(2, vm.AvailableCredentials.Count);
        Assert.Equal(Guid.Empty, vm.AvailableCredentials[0].Id);
        Assert.Equal("rdp-pwd", vm.AvailableCredentials[1].Name);
    }

    [Fact]
    public async Task NoneSentinel_ClearsCredentialBindingBackToPromptEveryTime()
    {
        // Pre-fix the ComboBox couldn't clear a saved credential — placeholder text isn't a
        // selectable item. The sentinel entry lets users round-trip back to "no credential".
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(cred);
        var vm = new ConnectionEditorViewModel(repo);
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = cred;
        Assert.Equal(cred.Id, vm.CredentialId);

        var none = vm.AvailableCredentials[0];
        Assert.Equal(Guid.Empty, none.Id);
        vm.SelectedCredential = none;

        Assert.Null(vm.CredentialId);
        // Selecting "None" again returns the sentinel from the getter, not raw null — the
        // ComboBox needs an in-collection item to display.
        Assert.Equal(Guid.Empty, vm.SelectedCredential!.Id);
    }

    [Fact]
    public async Task ProtocolChange_ClearsIncompatibleCredentialSelection()
    {
        var sshCred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(sshCred, rdpCred);
        var vm = new ConnectionEditorViewModel(repo);
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = sshCred;
        Assert.Equal(sshCred.Id, vm.CredentialId);

        // Switch the connection to RDP. The SSH cred is no longer a valid pick — the editor
        // must drop it rather than leave a protocol-incompatible binding to be saved later.
        vm.Protocol = ProtocolType.Rdp;

        Assert.Null(vm.CredentialId);
        // Selected falls back to the None sentinel (Guid.Empty) rather than raw null — the
        // picker needs an in-collection item to display the cleared state.
        Assert.Equal(Guid.Empty, vm.SelectedCredential!.Id);
    }

    [Fact]
    public async Task LoadFrom_StaleCredential_StillVisibleInPicker()
    {
        // Edit round-trip: a node bound to a credential whose protocol no longer matches the
        // connection (e.g. user changed the credential after saving the connection) must still
        // show the binding in the picker — otherwise opening the editor would silently lose
        // the existing CredentialId on save.
        var staleCred = new CredentialProfile { Name = "old-ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(staleCred);
        var vm = new ConnectionEditorViewModel(repo);
        await vm.LoadCredentialsAsync();

        var node = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            CredentialId = staleCred.Id,
        };

        vm.LoadFrom(node);

        Assert.Contains(vm.AvailableCredentials, c => c.Id == staleCred.Id);
        Assert.Equal(staleCred.Id, vm.CredentialId);
    }

    [Fact]
    public async Task WriteTo_ExplicitUsernameOverridesCredentialUsername()
    {
        // The free-text Username field is shown alongside the credential picker so users can
        // override the credential's stored username on a per-connection basis.
        var credential = new CredentialProfile
        {
            Name = "prod-svc",
            Username = "svcacct",
            Protocol = ProtocolType.Ssh,
        };
        var repo = new SingleCredentialRepository(credential);
        var vm = new ConnectionEditorViewModel(repo);
        await vm.LoadCredentialsAsync();

        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = credential;
        vm.Username = "alice";

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.Equal("alice", node.Username);
    }

    private static async Task<ConnectionEditorViewModel> NewEditorAsync()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository());
        await vm.LoadCredentialsAsync();
        return vm;
    }

    private sealed class EmptyCredentialRepository : ICredentialRepository
    {
        public Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<CredentialProfile>>(Array.Empty<CredentialProfile>());
        public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult<CredentialProfile?>(null);
        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default) => throw new NotImplementedException();
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default) => throw new NotImplementedException();
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => throw new NotImplementedException();
    }

    private sealed class SingleCredentialRepository : ICredentialRepository
    {
        private readonly CredentialProfile _credential;
        public SingleCredentialRepository(CredentialProfile credential) => _credential = credential;
        public Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<CredentialProfile>>(new[] { _credential });
        public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult<CredentialProfile?>(id == _credential.Id ? _credential : null);
        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default) => throw new NotImplementedException();
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default) => throw new NotImplementedException();
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => throw new NotImplementedException();
    }

    private sealed class MultiCredentialRepository : ICredentialRepository
    {
        private readonly CredentialProfile[] _credentials;
        public MultiCredentialRepository(params CredentialProfile[] credentials) => _credentials = credentials;
        public Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<CredentialProfile>>(_credentials);
        public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult<CredentialProfile?>(Array.Find(_credentials, c => c.Id == id));
        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default) => throw new NotImplementedException();
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default) => throw new NotImplementedException();
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => throw new NotImplementedException();
    }
}
