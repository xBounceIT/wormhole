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
}
