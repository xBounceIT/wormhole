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
    public async Task LoadFrom_RdpServerAuthenticationDefault_IsWarnPrompt()
    {
        var vm = await NewEditorAsync();
        var node = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "rdp-default",
            Protocol = ProtocolType.Rdp,
            Host = "h",
        };

        vm.LoadFrom(node);

        Assert.Equal(2, vm.RdpServerAuthentication);
        Assert.Equal(2, vm.ServerAuthChoices[0].Key);
        Assert.Contains("Warn", vm.ServerAuthChoices[0].Value);
        Assert.Equal(1, vm.ServerAuthChoices[1].Key);
        Assert.Equal(0, vm.ServerAuthChoices[2].Key);
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo());
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo());
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo());
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
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(cred);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = cred;
        Assert.Equal(cred.Id, vm.CredentialId);

        var none = vm.AvailableCredentials[0];
        Assert.Equal(Guid.Empty, none.Id);
        vm.SelectedCredential = none;

        // CredentialId reverts to null, but the getter returns the sentinel so the
        // ComboBox has an in-collection item to display.
        Assert.Null(vm.CredentialId);
        Assert.Equal(Guid.Empty, vm.SelectedCredential!.Id);
    }

    [Fact]
    public async Task ProtocolChange_ClearsIncompatibleCredentialSelection()
    {
        var sshCred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(sshCred, rdpCred);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = sshCred;
        Assert.Equal(sshCred.Id, vm.CredentialId);

        // Switch the connection to RDP. The SSH cred is no longer a valid pick — the editor
        // must drop it rather than leave a protocol-incompatible binding to be saved later.
        vm.Protocol = ProtocolType.Rdp;

        Assert.Null(vm.CredentialId);
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo());
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = credential;
        vm.Username = "alice";

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.Equal("alice", node.Username);
    }

    [Fact]
    public async Task CanUseSshAutoSudo_TrueOnlyForSshWithSavedCredential()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        // SSH but "prompt every time" (no saved credential) → the feature has no password to
        // send, so the checkbox stays hidden.
        Assert.Equal(ProtocolType.Ssh, vm.Protocol);
        Assert.False(vm.CanUseSshAutoSudo);

        vm.SelectedCredential = cred;
        Assert.True(vm.CanUseSshAutoSudo);
    }

    [Fact]
    public async Task CanUseSshAutoSudo_FalseForNonSshProtocol()
    {
        var sshCred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new MultiCredentialRepository(sshCred, rdpCred), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = sshCred;
        Assert.True(vm.CanUseSshAutoSudo);

        vm.Protocol = ProtocolType.Rdp;
        Assert.False(vm.CanUseSshAutoSudo);
    }

    [Fact]
    public async Task WriteTo_AutoSudo_PersistsForSshWithCredential_ClearedWhenCredentialDropped()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();
        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = cred;
        vm.SshAutoSudo = true;

        var node = new ConnectionNode();
        vm.WriteTo(node);
        Assert.True(node.SshAutoSudo);

        // Dropping the credential hides the checkbox; a stale checked value must not persist as
        // true — there'd be no password to send at connect time.
        vm.SelectedCredential = null;
        var node2 = new ConnectionNode();
        vm.WriteTo(node2);
        Assert.Null(node2.SshAutoSudo);
    }

    [Fact]
    public async Task LoadFrom_AutoSudo_RoundTrips()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        var source = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "box",
            Protocol = ProtocolType.Ssh,
            Host = "h",
            CredentialId = cred.Id,
            SshAutoSudo = true,
        };
        vm.LoadFrom(source);

        Assert.True(vm.SshAutoSudo);
        Assert.True(vm.CanUseSshAutoSudo);

        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);
        Assert.True(sink.SshAutoSudo);
    }

    [Fact]
    public async Task CanUseSshAutoSudo_FalseForSshKeyCredential()
    {
        // SSH-key credentials never yield a login password (the secret is a key passphrase),
        // so Auto sudo would be a silent no-op. The checkbox must stay hidden and a stale
        // checked value must never persist.
        var keyCred = new CredentialProfile { Name = "ssh-key", Protocol = ProtocolType.Ssh, Kind = CredentialKind.SshKey };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(keyCred), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();
        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = keyCred;

        Assert.False(vm.CanUseSshAutoSudo);

        // Even if SshAutoSudo were somehow set, WriteTo must not persist it for a key credential.
        vm.SshAutoSudo = true;
        var node = new ConnectionNode();
        vm.WriteTo(node);
        Assert.Null(node.SshAutoSudo);
    }

    [Fact]
    public async Task WriteTo_AutoSudo_PreservesInheritedNullWhenUnchanged()
    {
        // A child connection that inherits Auto sudo from its folder (own value null) must keep
        // inheriting after an unrelated edit such as a rename — saving must not bake in an
        // explicit false that severs inheritance from future folder changes.
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        var source = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "box",
            Protocol = ProtocolType.Ssh,
            Host = "h",
            CredentialId = cred.Id,
            SshAutoSudo = null, // inherits the folder default
        };
        vm.LoadFrom(source);
        Assert.False(vm.SshAutoSudo); // the node's own null surfaces as an unchecked box

        // User only renames; the checkbox is left untouched.
        vm.Name = "box-renamed";
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.Null(sink.SshAutoSudo); // inheritance preserved, not collapsed to false
    }

    [Fact]
    public async Task WriteTo_AutoSudo_ExplicitToggleOverridesInheritedNull()
    {
        // When the user actually ticks the box on an inheriting connection, that is a deliberate
        // override and must persist as an explicit true.
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        var source = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "box",
            Protocol = ProtocolType.Ssh,
            Host = "h",
            CredentialId = cred.Id,
            SshAutoSudo = null,
        };
        vm.LoadFrom(source);

        vm.SshAutoSudo = true; // explicit user enable
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.True(sink.SshAutoSudo);
    }

    [Fact]
    public async Task SelectingAzureAdCredential_AutoFlagsRdpUseExternalClient()
    {
        // Picking an AAD credential in the editor should tick the "Open with system Remote
        // Desktop" checkbox without user intervention. Without this, AAD targets crash the
        // embedded mstscax host on auth (SEH 0xC06D007F) before the user can save and route.
        var aad = new CredentialProfile
        {
            Name = "aad-prod",
            Domain = "AzureAD",
            Username = "alice@contoso.onmicrosoft.com",
            Protocol = ProtocolType.Rdp,
            Kind = CredentialKind.Password,
        };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(aad), EmptyTunnelRepo());
        vm.Protocol = ProtocolType.Rdp;
        await vm.LoadCredentialsAsync();

        Assert.False(vm.RdpUseExternalClient);

        vm.SelectedCredential = aad;

        Assert.True(vm.RdpUseExternalClient);
        Assert.True(vm.IsAzureAdCredential);
    }

    [Fact]
    public async Task SelectingNonAzureAdCredential_LeavesRdpUseExternalClientAlone()
    {
        // A non-AAD credential must not silently route the connection through mstsc.exe —
        // most users want the embedded experience and the heuristic must not have false
        // positives (e.g. on-prem AD users syncing UPNs to M365).
        var nonAad = new CredentialProfile
        {
            Name = "onprem",
            Domain = "CORP",
            Username = "alice",
            Protocol = ProtocolType.Rdp,
            Kind = CredentialKind.Password,
        };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(nonAad), EmptyTunnelRepo());
        vm.Protocol = ProtocolType.Rdp;
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = nonAad;

        Assert.False(vm.RdpUseExternalClient);
        Assert.False(vm.IsAzureAdCredential);
    }

    [Fact]
    public async Task LoadFrom_DoesNotAutoFlipExternalClientWhenUserPreviouslyDisabled()
    {
        // A user with an AAD profile may explicitly uncheck the external-client box (to try
        // the embedded path for any reason). On re-open, the editor must not silently re-tick
        // it back — otherwise the override is impossible to express across edit sessions.
        var aad = new CredentialProfile
        {
            Name = "aad-prod",
            Domain = "AzureAD",
            Username = "alice@contoso.onmicrosoft.com",
            Protocol = ProtocolType.Rdp,
            Kind = CredentialKind.Password,
        };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(aad), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();

        var node = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            CredentialId = aad.Id,
            RdpUseExternalClient = false, // user explicitly disabled the auto-flag earlier
        };

        vm.LoadFrom(node);

        Assert.False(vm.RdpUseExternalClient);
        Assert.True(vm.IsAzureAdCredential); // InfoBar still surfaces the detection
    }

    [Fact]
    public async Task TypingAzureAdIntoRdpDomain_AutoFlagsAndDisablesCheckbox()
    {
        // The "Prompt every time" workflow that broke production: user has no saved
        // credential, types "AzureAD" into Domain, and expects the editor to react. The
        // earlier credential-only heuristic missed this case entirely.
        var vm = await NewEditorAsync();
        vm.Protocol = ProtocolType.Rdp;

        Assert.False(vm.RdpUseExternalClient);
        Assert.True(vm.IsRdpUseExternalClientEditable);

        vm.RdpDomain = "AzureAD";

        Assert.True(vm.RdpUseExternalClient);
        Assert.True(vm.IsAzureAdCredential);
        Assert.False(vm.IsRdpUseExternalClientEditable);
    }

    [Theory]
    [InlineData("AzureAD")]
    [InlineData("azuread")]
    [InlineData("  AzureAD  ")] // editor strips whitespace via the detector
    public async Task RdpDomainAzureAdVariations_AllDetected(string domain)
    {
        var vm = await NewEditorAsync();
        vm.Protocol = ProtocolType.Rdp;

        vm.RdpDomain = domain;

        Assert.True(vm.IsAzureAdCredential);
    }

    [Fact]
    public async Task TypingAzureAdPrefixIntoUsername_AutoFlagsAndDisablesCheckbox()
    {
        var vm = await NewEditorAsync();
        vm.Protocol = ProtocolType.Rdp;

        vm.Username = "AzureAD\\alice@contoso.onmicrosoft.com";

        Assert.True(vm.RdpUseExternalClient);
        Assert.True(vm.IsAzureAdCredential);
        Assert.False(vm.IsRdpUseExternalClientEditable);
    }

    [Fact]
    public async Task ClearingAzureAdSignal_ReEnablesCheckbox()
    {
        // The checkbox is locked while ANY signal matches. Once the user clears all the
        // signals (e.g. typed AzureAD then re-typed CORP), the checkbox should regain its
        // editable state so they can opt in/out for non-AAD targets.
        var vm = await NewEditorAsync();
        vm.Protocol = ProtocolType.Rdp;
        vm.RdpDomain = "AzureAD";
        Assert.False(vm.IsRdpUseExternalClientEditable);

        vm.RdpDomain = "CORP";

        Assert.True(vm.IsRdpUseExternalClientEditable);
        Assert.False(vm.IsAzureAdCredential);
    }

    [Fact]
    public async Task ClearingAzureAdSignal_AutoUnticksWhenWeOwnTheFlag()
    {
        // Regression: pre-fix, typing AzureAD ticked the box and erasing AzureAD only
        // re-enabled the checkbox — the box stayed ticked. User had to manually untick.
        // Now we track auto-flag ownership and roll back our own writes when the signal
        // is cleared.
        var vm = await NewEditorAsync();
        vm.Protocol = ProtocolType.Rdp;
        Assert.False(vm.RdpUseExternalClient);

        vm.RdpDomain = "AzureAD";
        Assert.True(vm.RdpUseExternalClient);

        vm.RdpDomain = "CORP";

        Assert.False(vm.RdpUseExternalClient); // auto-flag rolled back
        Assert.True(vm.IsRdpUseExternalClientEditable);
    }

    [Fact]
    public async Task ClearingAzureAdSignal_LeavesUserTickAlone()
    {
        // If the user ticked the box themselves BEFORE typing AzureAD, the auto-flag
        // doesn't take ownership — we never set the true value, so we don't roll it back
        // when the AAD signal clears. The user's manual opt-in survives.
        var vm = await NewEditorAsync();
        vm.Protocol = ProtocolType.Rdp;
        vm.RdpUseExternalClient = true; // user opted in manually

        vm.RdpDomain = "AzureAD"; // signal detected but no-op (flag already true)
        Assert.True(vm.RdpUseExternalClient);

        vm.RdpDomain = "CORP";

        Assert.True(vm.RdpUseExternalClient); // user's tick survives
    }

    [Fact]
    public async Task LoadFrom_PersistedTrue_IsNotRolledBackOnSignalClear()
    {
        // A profile loaded with RdpUseExternalClient=true (persisted user choice) must
        // not be treated as auto-flagged: _autoFlagAppliedByAad starts at false on every
        // LoadFrom, so subsequent signal clears don't roll back the persisted value.
        var vm = await NewEditorAsync();

        var node = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            RdpDomain = "AzureAD",
            RdpUseExternalClient = true,
        };
        vm.LoadFrom(node);
        Assert.True(vm.RdpUseExternalClient);
        Assert.True(vm.IsAzureAdCredential);

        vm.RdpDomain = "CORP";

        Assert.True(vm.RdpUseExternalClient);
    }

    [Fact]
    public async Task LoadFrom_AzureAdNodeFields_DoesNotAutoFlipUserDisabledState()
    {
        // Same suppress-during-load semantics for the node-side handlers as for the
        // credential one. Without this, a user who unchecked the box would see it re-tick
        // every editor open because LoadFrom assigns RdpDomain before restoring the flag.
        var vm = await NewEditorAsync();

        var node = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            RdpDomain = "AzureAD",
            Username = "AzureAD\\alice",
            RdpUseExternalClient = false, // user explicitly disabled
        };

        vm.LoadFrom(node);

        // The persisted false survives — IsRdpUseExternalClientEditable still goes false
        // (the checkbox is locked because the signals are still there), but the underlying
        // value didn't auto-flip during LoadFrom. The runtime guard catches the override
        // at connect time; we don't fight the user in the editor.
        Assert.False(vm.RdpUseExternalClient);
        Assert.True(vm.IsAzureAdCredential);
        Assert.False(vm.IsRdpUseExternalClientEditable);
    }

    [Fact]
    public async Task UncheckingExternalClient_SurvivesProtocolUnchangedSave()
    {
        // The override (uncheck after auto-flag) must persist across WriteTo round-trips —
        // WriteTo just copies the current bool, no editor-side mutation should sneak in.
        var aad = new CredentialProfile
        {
            Name = "aad-prod",
            Domain = "AzureAD",
            Username = "alice@contoso.onmicrosoft.com",
            Protocol = ProtocolType.Rdp,
            Kind = CredentialKind.Password,
        };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(aad), EmptyTunnelRepo());
        vm.Protocol = ProtocolType.Rdp;
        await vm.LoadCredentialsAsync();

        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = aad;
        Assert.True(vm.RdpUseExternalClient); // auto-flag fired

        vm.RdpUseExternalClient = false; // user override

        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.False(sink.RdpUseExternalClient);
    }

    [Fact]
    public async Task Tunnel_InheritSentinel_PersistsAsNullEnabledAndNullId()
    {
        // The default state for a new connection — let the inheritance resolver supply the
        // tunnel from the parent folder. Both backing fields must remain null on save.
        var vm = await NewEditorAsync();
        await vm.TunnelPicker.LoadAsync();

        vm.TunnelPicker.SelectedTunnel = vm.TunnelPicker.InheritTunnel;

        Assert.Same(vm.TunnelPicker.InheritTunnel, vm.TunnelPicker.SelectedTunnel);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);

        Assert.Null(sink.TunnelEnabled);
        Assert.Null(sink.TunnelConfigId);
    }

    [Fact]
    public async Task Tunnel_NoTunnelSentinel_PersistsAsFalseEnabledAndNullId()
    {
        // Explicit "no tunnel" — overrides any folder-inherited tunnel by setting Enabled=false.
        var vm = await NewEditorAsync();
        await vm.TunnelPicker.LoadAsync();

        vm.TunnelPicker.SelectedTunnel = TunnelPickerViewModel.NoTunnel;

        Assert.Same(TunnelPickerViewModel.NoTunnel, vm.TunnelPicker.SelectedTunnel);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);

        Assert.False(sink.TunnelEnabled);
        Assert.Null(sink.TunnelConfigId);
    }

    [Fact]
    public async Task Tunnel_PickingNamedTunnel_PersistsAsTrueEnabledAndConfigId()
    {
        var wg = new TunnelConfig { Id = Guid.NewGuid(), Name = "office-wg", Kind = TunnelKind.WireGuard };
        var vm = new ConnectionEditorViewModel(
            new EmptyCredentialRepository(),
            new MultiTunnelConfigRepository(wg));
        await vm.TunnelPicker.LoadAsync();

        vm.TunnelPicker.SelectedTunnel = wg;

        Assert.Same(wg, vm.TunnelPicker.SelectedTunnel);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);

        Assert.True(sink.TunnelEnabled);
        Assert.Equal(wg.Id, sink.TunnelConfigId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(false)]
    public async Task LoadFrom_TunnelSentinelStates_RoundTrip(bool? enabled)
    {
        var vm = await NewEditorAsync();
        await vm.TunnelPicker.LoadAsync();

        var node = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            TunnelEnabled = enabled,
            TunnelConfigId = null,
        };
        vm.LoadFrom(node);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);

        Assert.Equal(enabled, sink.TunnelEnabled);
        Assert.Null(sink.TunnelConfigId);
    }

    [Fact]
    public async Task LoadFrom_EnabledTunnelWithId_RoundTrip()
    {
        var wg = new TunnelConfig { Id = Guid.NewGuid(), Name = "office-wg", Kind = TunnelKind.WireGuard };
        var vm = new ConnectionEditorViewModel(
            new EmptyCredentialRepository(),
            new MultiTunnelConfigRepository(wg));
        await vm.TunnelPicker.LoadAsync();

        var node = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            TunnelEnabled = true,
            TunnelConfigId = wg.Id,
        };
        vm.LoadFrom(node);

        // Selection round-trips to the real TunnelConfig instance, not a sentinel.
        Assert.Same(wg, vm.TunnelPicker.SelectedTunnel);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);

        Assert.True(sink.TunnelEnabled);
        Assert.Equal(wg.Id, sink.TunnelConfigId);
    }

    [Fact]
    public async Task LoadFrom_StaleTunnelId_StillVisibleInPicker()
    {
        // A connection was bound to a TunnelConfig that has since been deleted (or the user
        // hasn't loaded the page yet). Reopening the editor must keep the binding visible so
        // saving doesn't silently drop the TunnelConfigId.
        var deletedId = Guid.NewGuid();
        var vm = await NewEditorAsync();
        await vm.TunnelPicker.LoadAsync();

        var node = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            TunnelEnabled = true,
            TunnelConfigId = deletedId,
        };
        vm.LoadFrom(node);

        Assert.Contains(vm.TunnelPicker.AvailableTunnelConfigs, t => t.Id == deletedId);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);

        Assert.True(sink.TunnelEnabled);
        Assert.Equal(deletedId, sink.TunnelConfigId);
    }

    [Fact]
    public async Task LoadFrom_NullEnableWithOverrideConfigId_ShowsOverrideNotInherit()
    {
        // Regression for codex review feedback: a node persisted with TunnelEnabled=null
        // (inherit enable from ancestor folder) AND TunnelConfigId=<override.Id> (pin a
        // specific config) is a legitimate state produced by the inheritance resolver
        // (see Resolve_ChildOverridesAncestorTunnelConfigId in InheritanceResolverTunnelTests).
        // The picker must surface the override config — not silently mask it as
        // "(Inherit from folder)" while WriteTo still persists the id.
        var wg = new TunnelConfig { Id = Guid.NewGuid(), Name = "child-override", Kind = TunnelKind.WireGuard };
        var vm = new ConnectionEditorViewModel(
            new EmptyCredentialRepository(),
            new MultiTunnelConfigRepository(wg));
        await vm.TunnelPicker.LoadAsync();

        var node = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            TunnelEnabled = null,   // inherit the enable bit from the parent folder
            TunnelConfigId = wg.Id, // but pin this specific config
        };
        vm.LoadFrom(node);

        Assert.Same(wg, vm.TunnelPicker.SelectedTunnel);

        // Round-trip preserves (null, guid) if the user doesn't touch the dropdown.
        // (Picking a different item in the combobox collapses to (true, newId) — a known
        // limitation of the single-combobox UI noted in the PR description.)
        var sink = new ConnectionNode();
        vm.WriteTo(sink);
        Assert.Null(sink.TunnelEnabled);
        Assert.Equal(wg.Id, sink.TunnelConfigId);
    }

    [Fact]
    public async Task LoadFrom_CorruptedNodeWithGuidEmptyTunnelId_ShowsAsStaleNotInherit()
    {
        // Regression for the sentinel-collision class of bug: an imported/corrupted node
        // bound to TunnelConfigId=Guid.Empty must NOT be silently displayed as
        // "(Inherit from folder)" — the user has to see that something is off so they can
        // pick a real value or No tunnel. The sentinel uses a distinct non-Empty id so
        // Guid.Empty falls through to the stale-placeholder path.
        var vm = await NewEditorAsync();
        await vm.TunnelPicker.LoadAsync();

        var node = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            TunnelEnabled = true,
            TunnelConfigId = Guid.Empty,
        };
        vm.LoadFrom(node);

        Assert.Contains(vm.TunnelPicker.AvailableTunnelConfigs, t => t.Id == Guid.Empty);
        Assert.NotSame(vm.TunnelPicker.InheritTunnel, vm.TunnelPicker.SelectedTunnel);
        Assert.Equal(Guid.Empty, vm.TunnelPicker.SelectedTunnel!.Id);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);
        Assert.True(sink.TunnelEnabled);
        Assert.Equal(Guid.Empty, sink.TunnelConfigId);
    }

    [Fact]
    public void SelectedTunnel_UnresolvedEnabledState_ReturnsNullNotInherit()
    {
        // Regression: when TunnelEnabled=true but SelectedTunnelConfigId can't resolve to an
        // entry in AvailableTunnelConfigs, the getter must return null (no selection) so the
        // UI surfaces the inconsistency. Falling back to InheritTunnel here would silently
        // mask a real "(true, id)" persisted state behind a misleading "(Inherit)" display.
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo());

        // Force the invalid intermediate state directly via the SelectedTunnel setter and
        // then yank the id via the public backing setter — simulating a race where the
        // collection rebuilt between the two field writes.
        vm.TunnelPicker.SelectedTunnel = vm.TunnelPicker.InheritTunnel;
        vm.TunnelPicker.TunnelEnabled = true;
        vm.TunnelPicker.SelectedTunnelConfigId = Guid.NewGuid(); // not in AvailableTunnelConfigs

        Assert.Null(vm.TunnelPicker.SelectedTunnel);
    }

    [Fact]
    public async Task LoadTunnelConfigs_LeadsWithBothSentinels()
    {
        var wg = new TunnelConfig { Id = Guid.NewGuid(), Name = "wg-1", Kind = TunnelKind.WireGuard };
        var vm = new ConnectionEditorViewModel(
            new EmptyCredentialRepository(),
            new MultiTunnelConfigRepository(wg));
        await vm.TunnelPicker.LoadAsync();

        Assert.Equal(3, vm.TunnelPicker.AvailableTunnelConfigs.Count);
        Assert.Same(vm.TunnelPicker.InheritTunnel, vm.TunnelPicker.AvailableTunnelConfigs[0]);
        Assert.Same(TunnelPickerViewModel.NoTunnel, vm.TunnelPicker.AvailableTunnelConfigs[1]);
        Assert.Equal("wg-1", vm.TunnelPicker.AvailableTunnelConfigs[2].Name);
    }

    private static async Task<ConnectionEditorViewModel> NewEditorAsync()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo());
        await vm.LoadCredentialsAsync();
        return vm;
    }

    private static EmptyTunnelConfigRepository EmptyTunnelRepo() => new();

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

    private sealed class EmptyTunnelConfigRepository : ITunnelConfigRepository
    {
        public Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<TunnelConfig>>(Array.Empty<TunnelConfig>());
        public Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult<TunnelConfig?>(null);
        public Task AddAsync(TunnelConfig config, CancellationToken ct = default) => throw new NotImplementedException();
        public Task UpdateAsync(TunnelConfig config, CancellationToken ct = default) => throw new NotImplementedException();
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => throw new NotImplementedException();
    }

    private sealed class MultiTunnelConfigRepository : ITunnelConfigRepository
    {
        private readonly TunnelConfig[] _configs;
        public MultiTunnelConfigRepository(params TunnelConfig[] configs) => _configs = configs;
        public Task<IReadOnlyList<TunnelConfig>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<TunnelConfig>>(_configs);
        public Task<TunnelConfig?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult<TunnelConfig?>(Array.Find(_configs, c => c.Id == id));
        public Task AddAsync(TunnelConfig config, CancellationToken ct = default) => throw new NotImplementedException();
        public Task UpdateAsync(TunnelConfig config, CancellationToken ct = default) => throw new NotImplementedException();
        public Task DeleteAsync(Guid id, CancellationToken ct = default) => throw new NotImplementedException();
    }
}
