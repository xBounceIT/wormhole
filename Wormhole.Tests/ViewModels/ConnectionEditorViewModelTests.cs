using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Data.Repositories;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Tests.Fakes;
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

    [Fact]
    public async Task DisplayChoices_StartWithFullConnectionContent()
    {
        var vm = await NewEditorAsync();

        Assert.Equal(RdpScreenSizes.FullConnectionContent, vm.ScreenSizeChoices[0]);
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

    [Theory]
    [InlineData(RdpScreenSizes.LegacyFullScreenSentinel)]
    [InlineData(RdpScreenSizes.MRemoteNgFitToWindowSentinel)]
    public async Task LoadFrom_LegacyDynamicRdpScreenSize_NormalizesToPickerValue(string legacyScreenSize)
    {
        var vm = await NewEditorAsync();
        var node = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "rdp-legacy",
            Protocol = ProtocolType.Rdp,
            Host = "h",
            RdpScreenSize = legacyScreenSize,
        };

        vm.LoadFrom(node);
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.Equal(RdpScreenSizes.FullConnectionContent, vm.RdpScreenSize);
        Assert.Equal(RdpScreenSizes.FullConnectionContent, sink.RdpScreenSize);
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
    public async Task Serial_IsCredentiallessLocalProtocol_WithNoNetworkPort()
    {
        var vm = await NewEditorAsync();
        vm.Name = "console";
        vm.Protocol = ProtocolType.Serial;
        vm.Host = "COM4";
        vm.Port = 0; // ignored for serial; baud lives in SerialBaudRate.

        Assert.True(vm.IsValid);
        Assert.True(vm.IsSerial);
        Assert.False(vm.ShowCredentialSection);
        Assert.False(vm.ShowTunnelSection);
        Assert.False(vm.ShowPortBox);
        Assert.Equal("Serial line", vm.HostHeader);
    }

    [Fact]
    public async Task Serial_WriteTo_PersistsPuttySerialSettings_AndClearsNetworkOnlyFields()
    {
        var vm = await NewEditorAsync();
        vm.Name = "switch-console";
        vm.Protocol = ProtocolType.Serial;
        vm.Host = "COM9";
        vm.Port = 22;
        vm.SerialBaudRate = 115200;
        vm.SerialDataBits = 7;
        vm.SerialStopBits = SerialStopBitsMode.Two;
        vm.SerialParity = SerialParityMode.Even;
        vm.SerialFlowControl = SerialFlowControlMode.DsrDtr;

        var node = new ConnectionNode
        {
            Username = "stale-user",
            CredentialId = Guid.NewGuid(),
            CredentialMode = CredentialBindingMode.Saved,
            UseInlinePassword = true,
            PendingInlinePassword = "stale-secret",
            SshAutoSudo = true,
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
        };
        vm.WriteTo(node);

        Assert.Equal(ProtocolType.Serial, node.Protocol);
        Assert.Equal("COM9", node.Host);
        Assert.Null(node.Port);
        Assert.Equal(115200, node.SerialBaudRate);
        Assert.Equal(7, node.SerialDataBits);
        Assert.Equal(SerialStopBitsMode.Two, node.SerialStopBits);
        Assert.Equal(SerialParityMode.Even, node.SerialParity);
        Assert.Equal(SerialFlowControlMode.DsrDtr, node.SerialFlowControl);
        Assert.Null(node.Username);
        Assert.Null(node.CredentialId);
        Assert.Null(node.CredentialMode);
        Assert.False(node.UseInlinePassword);
        Assert.Null(node.PendingInlinePassword);
        Assert.Null(node.SshAutoSudo);
        Assert.False(node.TunnelEnabled);
        Assert.Null(node.TunnelConfigId);
    }

    [Fact]
    public async Task Serial_LoadFrom_RoundTripsSettings()
    {
        var vm = await NewEditorAsync();
        var source = new ConnectionNode
        {
            Name = "console",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Serial,
            Host = "COM12",
            SerialBaudRate = 57600,
            SerialDataBits = 6,
            SerialStopBits = SerialStopBitsMode.OnePointFive,
            SerialParity = SerialParityMode.Mark,
            SerialFlowControl = SerialFlowControlMode.XonXoff,
        };

        vm.LoadFrom(source);

        Assert.Equal("COM12", vm.Host);
        Assert.Equal(57600, vm.SerialBaudRate);
        Assert.Equal(6, vm.SerialDataBits);
        Assert.Equal(SerialStopBitsMode.OnePointFive, vm.SerialStopBits);
        Assert.Equal(SerialParityMode.Mark, vm.SerialParity);
        Assert.Equal(SerialFlowControlMode.XonXoff, vm.SerialFlowControl);
    }

    [Fact]
    public async Task Serial_WriteTo_PreservesInheritedSettingsWhenUnchanged()
    {
        var vm = await NewEditorAsync();
        var source = new ConnectionNode
        {
            Name = "console",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Serial,
            Host = "COM12",
        };

        vm.LoadFrom(source);
        vm.Name = "renamed-console";
        var sink = new ConnectionNode();

        vm.WriteTo(sink);

        Assert.Null(sink.SerialBaudRate);
        Assert.Null(sink.SerialDataBits);
        Assert.Null(sink.SerialStopBits);
        Assert.Null(sink.SerialParity);
        Assert.Null(sink.SerialFlowControl);
    }

    [Fact]
    public async Task Serial_WriteTo_PersistsChangedInheritedSettingOnly()
    {
        var vm = await NewEditorAsync();
        var source = new ConnectionNode
        {
            Name = "console",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Serial,
            Host = "COM12",
        };

        vm.LoadFrom(source);
        vm.SerialBaudRateInherits = false;
        vm.SerialBaudRate = 115200;
        var sink = new ConnectionNode();

        vm.WriteTo(sink);

        Assert.Equal(115200, sink.SerialBaudRate);
        Assert.Null(sink.SerialDataBits);
        Assert.Null(sink.SerialStopBits);
        Assert.Null(sink.SerialParity);
        Assert.Null(sink.SerialFlowControl);
    }

    [Fact]
    public async Task Serial_WriteTo_PersistsDefaultOverrideWhenInherited()
    {
        var vm = await NewEditorAsync();
        var source = new ConnectionNode
        {
            Name = "console",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Serial,
            Host = "COM12",
        };

        vm.LoadFrom(source);
        Assert.True(vm.SerialBaudRateInherits);
        vm.SerialBaudRateInherits = false;
        var sink = new ConnectionNode();

        vm.WriteTo(sink);

        Assert.Equal(SerialDefaults.BaudRate, sink.SerialBaudRate);
        Assert.Null(sink.SerialDataBits);
        Assert.Null(sink.SerialStopBits);
        Assert.Null(sink.SerialParity);
        Assert.Null(sink.SerialFlowControl);
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        // AvailableCredentials leads with "(Inherit)" and "(None)" sentinels, followed by
        // the protocol-filtered repository entry.
        Assert.Equal(3, vm.AvailableCredentials.Count);
        Assert.Equal(ConnectionEditorViewModel.InheritCredential.Id, vm.AvailableCredentials[0].Id);
        Assert.Equal(Guid.Empty, vm.AvailableCredentials[1].Id);
        Assert.Equal("ssh", vm.AvailableCredentials[2].Name);

        vm.Protocol = ProtocolType.Rdp;

        Assert.Equal(3, vm.AvailableCredentials.Count);
        Assert.Equal(ConnectionEditorViewModel.InheritCredential.Id, vm.AvailableCredentials[0].Id);
        Assert.Equal(Guid.Empty, vm.AvailableCredentials[1].Id);
        Assert.Equal("rdp", vm.AvailableCredentials[2].Name);
    }

    [Fact]
    public async Task AvailableCredentials_ExcludesSshKeyCredsForRdpConnections()
    {
        // RDP login resolves the password secret only; offering a key-based credential
        // would funnel the user into a misleading prompt path.
        var rdpPwd = new CredentialProfile { Name = "rdp-pwd", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var rdpKey = new CredentialProfile { Name = "rdp-key", Protocol = ProtocolType.Rdp, Kind = CredentialKind.SshKey };
        var repo = new MultiCredentialRepository(rdpPwd, rdpKey);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        vm.Protocol = ProtocolType.Rdp;
        await vm.LoadCredentialsAsync();

        // Sentinels + the one password-kind credential, key-kind filtered out.
        Assert.Equal(3, vm.AvailableCredentials.Count);
        Assert.Equal(ConnectionEditorViewModel.InheritCredential.Id, vm.AvailableCredentials[0].Id);
        Assert.Equal(Guid.Empty, vm.AvailableCredentials[1].Id);
        Assert.Equal("rdp-pwd", vm.AvailableCredentials[2].Name);
    }

    [Fact]
    public async Task AvailableCredentials_FiltersVncToPasswordCredentials()
    {
        var sshCred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vncPwd = new CredentialProfile { Name = "vnc-pwd", Protocol = ProtocolType.Vnc, Kind = CredentialKind.Password };
        var vncKey = new CredentialProfile { Name = "vnc-key", Protocol = ProtocolType.Vnc, Kind = CredentialKind.SshKey };
        var repo = new MultiCredentialRepository(sshCred, vncPwd, vncKey);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        vm.Protocol = ProtocolType.Vnc;

        await vm.LoadCredentialsAsync();

        Assert.Equal(3, vm.AvailableCredentials.Count);
        Assert.Equal(ConnectionEditorViewModel.InheritCredential.Id, vm.AvailableCredentials[0].Id);
        Assert.Equal(Guid.Empty, vm.AvailableCredentials[1].Id);
        Assert.Equal("vnc-pwd", vm.AvailableCredentials[2].Name);
    }

    [Fact]
    public async Task VncEditor_ShowsOnlySharedConnectionFields()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        vm.Protocol = ProtocolType.Vnc;
        vm.UseSavedCredentials = false;

        Assert.True(vm.IsVnc);
        Assert.True(vm.ShowCredentialSection);
        Assert.False(vm.ShowConnectionUsername);
        Assert.False(vm.ShowInlinePassword);
        Assert.False(vm.ShowRdpDomain);
        Assert.False(vm.CanUseSshAutoSudo);
        Assert.False(vm.IsHttp);
        Assert.False(vm.IsHttps);
    }

    [Fact]
    public async Task WriteTo_Vnc_ClearsHiddenUsernameAndInlinePasswordState()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Name = "console";
        vm.Protocol = ProtocolType.Vnc;
        vm.Host = "kvm.example.com";
        vm.Username = "stale-user";
        vm.UseSavedCredentials = false;
        vm.InlinePassword = "stale-inline";

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.Null(node.Username);
        Assert.Equal(CredentialBindingMode.None, node.CredentialMode);
        Assert.Null(node.CredentialId);
        Assert.False(node.UseInlinePassword);
        Assert.Null(node.PendingInlinePassword);
    }

    [Fact]
    public async Task NoneSentinel_ClearsCredentialBindingBackToPromptEveryTime()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(cred);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = cred;
        Assert.Equal(cred.Id, vm.CredentialId);

        var none = vm.AvailableCredentials[1];
        Assert.Equal(Guid.Empty, none.Id);
        vm.SelectedCredential = none;

        // CredentialId reverts to null, but the getter returns the sentinel so the
        // ComboBox has an in-collection item to display.
        Assert.Null(vm.CredentialId);
        Assert.Equal(CredentialBindingMode.None, vm.CredentialMode);
        Assert.Equal(Guid.Empty, vm.SelectedCredential!.Id);
    }

    [Fact]
    public async Task ProtocolChange_ClearsIncompatibleCredentialSelection()
    {
        var sshCred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(sshCred, rdpCred);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = sshCred;
        Assert.Equal(sshCred.Id, vm.CredentialId);

        // Switch the connection to RDP. The SSH cred is no longer a valid pick — the editor
        // must drop it rather than leave a protocol-incompatible binding to be saved later.
        vm.Protocol = ProtocolType.Rdp;

        Assert.Null(vm.CredentialId);
        Assert.Equal(CredentialBindingMode.Inherit, vm.CredentialMode);
        Assert.Equal(ConnectionEditorViewModel.InheritCredential.Id, vm.SelectedCredential!.Id);
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
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
    public async Task FilterCredentials_EmptyQuery_ReturnsFullListIncludingSentinels()
    {
        var sshA = new CredentialProfile { Name = "alpha", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var sshB = new CredentialProfile { Name = "bravo", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(sshA, sshB);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        var all = vm.FilterCredentials("");

        // Mirrors AvailableCredentials: inherit/none sentinels lead, followed by the two matches.
        Assert.Equal(vm.AvailableCredentials.Count, all.Count);
        Assert.Equal(ConnectionEditorViewModel.InheritCredential.Id, all[0].Id);
        Assert.Equal(Guid.Empty, all[1].Id);
        Assert.Contains(all, c => c.Name == "alpha");
        Assert.Contains(all, c => c.Name == "bravo");
    }

    [Fact]
    public async Task FilterCredentials_MatchesNameUsernameAndDomain_CaseInsensitively()
    {
        var byName = new CredentialProfile { Name = "Prod-Web", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var byUser = new CredentialProfile { Name = "svc", Username = "deployer", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var byDomain = new CredentialProfile { Name = "corp", Domain = "EXAMPLE", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(byName, byUser, byDomain);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        Assert.Contains(vm.FilterCredentials("prod"), c => c.Name == "Prod-Web");
        Assert.Contains(vm.FilterCredentials("DEPLOY"), c => c.Name == "svc");
        Assert.Contains(vm.FilterCredentials("example"), c => c.Name == "corp");

        var none = vm.FilterCredentials("zzz-no-match");
        Assert.Empty(none);
    }

    [Fact]
    public async Task ResolveCredentialByText_ExactNameMatchesCaseInsensitively_OtherwiseNull()
    {
        var cred = new CredentialProfile { Name = "Prod-Web", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(cred);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        Assert.Same(cred, vm.ResolveCredentialByText("prod-web"));
        Assert.Same(cred, vm.ResolveCredentialByText("  Prod-Web  "));
        Assert.Null(vm.ResolveCredentialByText("prod")); // substring, not exact — no commit
        Assert.Null(vm.ResolveCredentialByText(""));
    }

    [Fact]
    public async Task ResolveCredentialForCommit_PrefersExactName_ThenUniqueFilterMatch()
    {
        // Commit-on-submit/blur: an exact Name wins even if the substring is ambiguous; a
        // non-exact query that uniquely matches by Username/Domain still commits; an ambiguous
        // substring commits nothing (caller keeps the current selection).
        var prod = new CredentialProfile { Name = "prod", Username = "root", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var prodWeb = new CredentialProfile { Name = "prod-web", Username = "deployer", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(prod, prodWeb);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        // Exact name beats the fact that "prod" is also a substring of "prod-web".
        Assert.Same(prod, vm.ResolveCredentialForCommit("prod"));
        // Unique match by Username (not an exact Name) commits.
        Assert.Same(prodWeb, vm.ResolveCredentialForCommit("deploy"));
        // Unique substring match by Name commits ("web" appears only in prod-web).
        Assert.Same(prodWeb, vm.ResolveCredentialForCommit("web"));
        // "roo" uniquely matches prod by Username.
        Assert.Same(prod, vm.ResolveCredentialForCommit("roo"));
        // No match and empty both yield null (keep current selection / handled as clear by caller).
        Assert.Null(vm.ResolveCredentialForCommit("zzz"));
        Assert.Null(vm.ResolveCredentialForCommit(""));
    }

    [Fact]
    public async Task ResolveCredentialForCommit_AmbiguousMatch_ReturnsNull()
    {
        var a = new CredentialProfile { Name = "web-a", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var b = new CredentialProfile { Name = "web-b", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(a, b);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        // "web" matches both — no unambiguous commit.
        Assert.Null(vm.ResolveCredentialForCommit("web"));
    }

    [Fact]
    public async Task SelectedCredential_SetToNull_ClearsBindingToInherit()
    {
        // The picker's "empty text clears the selection" path applies null to SelectedCredential;
        // the setter must map that back to inherited credentials.
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var repo = new MultiCredentialRepository(cred);
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = cred;
        Assert.Equal(cred.Id, vm.CredentialId);

        vm.SelectedCredential = null;

        Assert.Null(vm.CredentialId);
        Assert.Equal(CredentialBindingMode.Inherit, vm.CredentialMode);
        Assert.Equal(ConnectionEditorViewModel.InheritCredential.Id, vm.SelectedCredential!.Id);
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
        var vm = new ConnectionEditorViewModel(repo, EmptyTunnelRepo(), new FakeCredentialService());
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
    public async Task CanUseSshAutoSudo_ShownForSshIncludingPromptEveryTimeAndSavedPassword()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        // "Prompt every time" (no saved credential) still gets a password at runtime — and a
        // child may inherit one from a folder — so the control is shown for SSH regardless.
        Assert.Equal(ProtocolType.Ssh, vm.Protocol);
        Assert.True(vm.CanUseSshAutoSudo);

        vm.SelectedCredential = cred;
        Assert.True(vm.CanUseSshAutoSudo);
    }

    [Fact]
    public async Task CanUseSshAutoSudo_FalseForNonSshProtocol()
    {
        var sshCred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new MultiCredentialRepository(sshCred, rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        vm.SelectedCredential = sshCred;
        Assert.True(vm.CanUseSshAutoSudo);

        vm.Protocol = ProtocolType.Rdp;
        Assert.False(vm.CanUseSshAutoSudo);
    }

    [Fact]
    public async Task WriteTo_AutoSudo_PersistsOnForSshWithCredential_RevertsWhenKeyCredentialSelected()
    {
        var pwd = new CredentialProfile { Name = "ssh-pwd", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var key = new CredentialProfile { Name = "ssh-key", Protocol = ProtocolType.Ssh, Kind = CredentialKind.SshKey };
        var vm = new ConnectionEditorViewModel(new MultiCredentialRepository(pwd, key), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = pwd;
        vm.SshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoOn;

        var node = new ConnectionNode();
        vm.WriteTo(node);
        Assert.True(node.SshAutoSudo);

        // Switching to a key credential hides the control (no password to send); with nothing
        // loaded the persisted result reverts to null rather than a meaningless explicit on.
        vm.SelectedCredential = key;
        Assert.False(vm.CanUseSshAutoSudo);
        var node2 = new ConnectionNode();
        vm.WriteTo(node2);
        Assert.Null(node2.SshAutoSudo);
    }

    [Fact]
    public async Task LoadFrom_AutoSudo_RoundTripsOn()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo(), new FakeCredentialService());
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

        Assert.Equal(ConnectionEditorViewModel.SshAutoSudoOn, vm.SshAutoSudoMode);
        Assert.True(vm.CanUseSshAutoSudo);

        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);
        Assert.True(sink.SshAutoSudo);
    }

    [Fact]
    public async Task CanUseSshAutoSudo_FalseForSshKeyCredential()
    {
        // SSH-key credentials never yield a login password (the secret is a key passphrase),
        // so Auto sudo would be a silent no-op. The control must stay hidden, and with nothing
        // loaded WriteTo persists null.
        var keyCred = new CredentialProfile { Name = "ssh-key", Protocol = ProtocolType.Ssh, Kind = CredentialKind.SshKey };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(keyCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = keyCred;

        Assert.False(vm.CanUseSshAutoSudo);

        var node = new ConnectionNode();
        vm.WriteTo(node);
        Assert.Null(node.SshAutoSudo);
    }

    [Fact]
    public async Task WriteTo_AutoSudo_PreservesInheritWhenUnchanged()
    {
        // A child connection that inherits Auto sudo from its folder (own value null) must keep
        // inheriting after an unrelated edit such as a rename — saving must not bake in an
        // explicit value that severs inheritance from future folder changes.
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo(), new FakeCredentialService());
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
        Assert.Equal(ConnectionEditorViewModel.SshAutoSudoInherit, vm.SshAutoSudoMode);

        // User only renames; the Auto sudo selection is left on "Inherit".
        vm.Name = "box-renamed";
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.Null(sink.SshAutoSudo); // inheritance preserved
    }

    [Fact]
    public async Task WriteTo_AutoSudo_ExplicitOnOverridesInheritedNull()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo(), new FakeCredentialService());
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

        vm.SshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoOn; // explicit enable
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.True(sink.SshAutoSudo);
    }

    [Fact]
    public async Task WriteTo_AutoSudo_ExplicitOffOverridesInheritedOn()
    {
        // Regression: a child that inherits Auto sudo *on* from a folder must be able to turn it
        // off for just that connection. A plain checkbox couldn't express this (off was
        // indistinguishable from inherit); the tri-state writes an explicit false.
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        var source = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "box",
            Protocol = ProtocolType.Ssh,
            Host = "h",
            CredentialId = cred.Id,
            SshAutoSudo = null, // own value null → inherits the folder's "on"
        };
        vm.LoadFrom(source);
        Assert.Equal(ConnectionEditorViewModel.SshAutoSudoInherit, vm.SshAutoSudoMode);

        vm.SshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoOff; // explicit off override
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.False(sink.SshAutoSudo); // explicit false persisted, not null
    }

    [Fact]
    public async Task CanUseSshAutoSudo_ShownForInheritedCredential_AllowsExplicitOff()
    {
        // A connection that inherits its password credential from a folder has CredentialId == null
        // on the node, yet the runtime resolves a usable password. The control must stay visible in
        // that case so a folder/imported default can't force Auto sudo on with no way to opt out —
        // the user can select Off to write an explicit false.
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        var source = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "box",
            Protocol = ProtocolType.Ssh,
            Host = "h",
            CredentialId = null, // inherits the credential (and possibly Auto sudo on) from a folder
            SshAutoSudo = null,
        };
        vm.LoadFrom(source);
        Assert.True(vm.CanUseSshAutoSudo); // visible despite the inherited credential
        Assert.Equal(ConnectionEditorViewModel.SshAutoSudoInherit, vm.SshAutoSudoMode);

        vm.SshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoOff; // explicit opt-out
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.False(sink.SshAutoSudo); // explicit false persisted, overriding the inherited on
    }

    [Fact]
    public async Task WriteTo_AutoSudo_PreservesExplicitTrueWhenHiddenByOwnKeyCredential()
    {
        // A node with its own SSH-key credential hides the control (no password to send). An
        // explicit SshAutoSudo=true already on the node must be preserved on save, not clobbered —
        // it becomes effective again if the credential later changes to a password.
        var key = new CredentialProfile { Name = "ssh-key", Protocol = ProtocolType.Ssh, Kind = CredentialKind.SshKey };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(key), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();

        var source = new ConnectionNode
        {
            Kind = NodeKind.Connection,
            Name = "box",
            Protocol = ProtocolType.Ssh,
            Host = "h",
            CredentialId = key.Id, // own key credential → control hidden
            SshAutoSudo = true,
        };
        vm.LoadFrom(source);
        Assert.False(vm.CanUseSshAutoSudo);

        vm.Name = "box-renamed";
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.True(sink.SshAutoSudo); // preserved, not clobbered
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
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(aad), EmptyTunnelRepo(), new FakeCredentialService());
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
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(nonAad), EmptyTunnelRepo(), new FakeCredentialService());
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
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(aad), EmptyTunnelRepo(), new FakeCredentialService());
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
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(aad), EmptyTunnelRepo(), new FakeCredentialService());
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
            new MultiTunnelConfigRepository(wg), new FakeCredentialService());
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
            new MultiTunnelConfigRepository(wg), new FakeCredentialService());
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
            new MultiTunnelConfigRepository(wg), new FakeCredentialService());
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
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());

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
            new MultiTunnelConfigRepository(wg), new FakeCredentialService());
        await vm.TunnelPicker.LoadAsync();

        Assert.Equal(3, vm.TunnelPicker.AvailableTunnelConfigs.Count);
        Assert.Same(vm.TunnelPicker.InheritTunnel, vm.TunnelPicker.AvailableTunnelConfigs[0]);
        Assert.Same(TunnelPickerViewModel.NoTunnel, vm.TunnelPicker.AvailableTunnelConfigs[1]);
        Assert.Equal("wg-1", vm.TunnelPicker.AvailableTunnelConfigs[2].Name);
    }

    [Fact]
    public async Task WriteTo_InlinePassword_SetsFlagPendingAndNullsCredentialId()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Ssh;
        vm.Name = "n";
        vm.Host = "h";
        vm.UseSavedCredentials = false;
        vm.Username = "root";
        vm.InlinePassword = "hunter2";

        var node = new ConnectionNode();
        vm.WriteTo(node);

        // Inline mode: flag on, plaintext handed off via the transient property, saved
        // credential cleared (the two are mutually exclusive), inline username persisted.
        Assert.True(node.UseInlinePassword);
        Assert.Equal("hunter2", node.PendingInlinePassword);
        Assert.Null(node.CredentialId);
        Assert.Equal(CredentialBindingMode.None, node.CredentialMode);
        Assert.Equal("root", node.Username);
    }

    [Fact]
    public async Task WriteTo_SavedCredentials_KeepsCredentialIdAndLeavesInlineOff()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Ssh;
        vm.Name = "n";
        vm.Host = "h";
        vm.UseSavedCredentials = true;
        vm.SelectedCredential = cred;

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.False(node.UseInlinePassword);
        Assert.Null(node.PendingInlinePassword);
        Assert.Equal(cred.Id, node.CredentialId);
        Assert.Equal(CredentialBindingMode.Saved, node.CredentialMode);
    }

    [Fact]
    public async Task WriteTo_InheritCredential_WritesExplicitInheritMode()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Ssh;
        vm.Name = "n";
        vm.Host = "h";
        vm.UseSavedCredentials = true;
        vm.SelectedCredential = ConnectionEditorViewModel.InheritCredential;

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.False(node.UseInlinePassword);
        Assert.Null(node.PendingInlinePassword);
        Assert.Null(node.CredentialId);
        Assert.Equal(CredentialBindingMode.Inherit, node.CredentialMode);
    }

    [Fact]
    public async Task WriteTo_Rdp_UncheckedSavedCredentials_UsesInlineAndClearsCredential()
    {
        // RDP inline mode must drop the previously-picked saved credential (don't silently keep auth)
        // and hand the password off through the same transient path SSH uses.
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Rdp;
        vm.Name = "n";
        vm.Host = "h";
        vm.SelectedCredential = rdpCred;
        vm.UseSavedCredentials = false;
        vm.InlinePassword = "inline-rdp-secret";

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.True(node.UseInlinePassword);
        Assert.Equal("inline-rdp-secret", node.PendingInlinePassword);
        Assert.Null(node.CredentialId);
        Assert.Equal(CredentialBindingMode.None, node.CredentialMode);
        Assert.True(vm.ShowInlinePassword);
    }

    [Fact]
    public async Task LoadFrom_InlinePassword_SetsUseSavedCredentialsFalse()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            Kind = NodeKind.Connection,
            UseInlinePassword = true,
        };

        vm.LoadFrom(source);

        Assert.False(vm.UseSavedCredentials);
        Assert.True(vm.ShowInlinePassword);
    }

    [Fact]
    public async Task LoadFrom_LegacyNullModeWithCredential_LoadsAsSavedCredential()
    {
        var cred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(cred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            Kind = NodeKind.Connection,
            CredentialId = cred.Id,
            CredentialMode = null,
        };

        vm.LoadFrom(source);

        Assert.Equal(CredentialBindingMode.Saved, vm.CredentialMode);
        Assert.Equal(cred.Id, vm.SelectedCredential!.Id);
    }

    [Fact]
    public async Task LoadFrom_LegacyNullModeWithoutCredential_LoadsAsInherit()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            Kind = NodeKind.Connection,
            CredentialId = null,
            CredentialMode = null,
        };

        vm.LoadFrom(source);

        Assert.Equal(CredentialBindingMode.Inherit, vm.CredentialMode);
        Assert.Equal(ConnectionEditorViewModel.InheritCredential.Id, vm.SelectedCredential!.Id);
    }

    [Fact]
    public async Task LoadInlineSecretAsync_PopulatesInlinePasswordFromStore()
    {
        var nodeId = Guid.NewGuid();
        var creds = new FakeCredentialService();
        creds.Passwords[nodeId] = "stored-pw";
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), creds);
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Id = nodeId,
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            Kind = NodeKind.Connection,
            UseInlinePassword = true,
        };
        vm.LoadFrom(source);

        await vm.LoadInlineSecretAsync();

        Assert.Equal("stored-pw", vm.InlinePassword);
    }

    [Fact]
    public async Task LoadInlineSecretAsync_NoOp_WhenConnectionIsNotInline()
    {
        var nodeId = Guid.NewGuid();
        var creds = new FakeCredentialService();
        creds.Passwords[nodeId] = "should-not-load";
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), creds);
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Id = nodeId,
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Ssh,
            Kind = NodeKind.Connection,
        };
        vm.LoadFrom(source);

        await vm.LoadInlineSecretAsync();

        Assert.Equal(string.Empty, vm.InlinePassword);
    }

    [Fact]
    public async Task ShowInlinePassword_TrueForSshAndRdpWithoutSavedCredentials()
    {
        var vm = await NewEditorAsync();
        vm.Protocol = ProtocolType.Ssh;

        vm.UseSavedCredentials = true;
        Assert.False(vm.ShowInlinePassword);

        vm.UseSavedCredentials = false;
        Assert.True(vm.ShowInlinePassword);

        vm.Protocol = ProtocolType.Rdp;
        Assert.True(vm.ShowInlinePassword);

        vm.Protocol = ProtocolType.Http;
        Assert.False(vm.ShowInlinePassword);
    }

    [Fact]
    public async Task ShowRdpDomain_HiddenOnlyWhenRealSavedRdpCredentialSelected()
    {
        // The connection-level Domain field duplicates the saved RDP credential's (mandatory) domain,
        // so it hides once a real credential is picked — mirroring how the Username field hides under
        // a saved credential. It stays visible for the no-real-credential cases that still need a
        // place to type a domain: "(None) — prompt every time" (the AzureAD workflow) and inline mode.
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password, Domain = "CORP" };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Rdp;

        // Saved-credentials checked but "(None) — prompt every time" selected → still shown.
        vm.UseSavedCredentials = true;
        vm.SelectedCredential = ConnectionEditorViewModel.NoneCredential;
        Assert.True(vm.ShowRdpDomain);

        // A real saved RDP credential carries its own domain → node-level field redundant, hide it.
        vm.SelectedCredential = rdpCred;
        Assert.False(vm.ShowRdpDomain);

        // Inline / connect-time prompt (not using saved credentials) → shown again.
        vm.UseSavedCredentials = false;
        Assert.True(vm.ShowRdpDomain);

        // Never shown for SSH.
        vm.Protocol = ProtocolType.Ssh;
        Assert.False(vm.ShowRdpDomain);
    }

    [Fact]
    public async Task DistinctTypedDomainStaysVisibleAfterSelectingRdpCredential()
    {
        // A domain typed in "(None)" mode (here "AzureAD", which forces the external-client flag)
        // differs from the chosen credential's domain, so it stays a *visible* override once a real
        // RDP credential is selected — the value (and the latched flag it drives) never go invisible.
        // Clearing the now-visible field releases the flag and hides the redundant box.
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password, Domain = "CORP" };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Rdp;

        vm.SelectedCredential = ConnectionEditorViewModel.NoneCredential;
        vm.RdpDomain = "AzureAD";
        Assert.True(vm.RdpUseExternalClient);

        // Commit to a real saved credential → "AzureAD" differs from "CORP", so it stays visible.
        vm.SelectedCredential = rdpCred;
        Assert.Equal("AzureAD", vm.RdpDomain);
        Assert.True(vm.ShowRdpDomain);
        Assert.True(vm.RdpUseExternalClient); // latch persists, but its cause is on screen

        // Clearing the visible override releases the flag and hides the now-redundant field.
        vm.RdpDomain = string.Empty;
        Assert.False(vm.ShowRdpDomain);
        Assert.False(vm.RdpUseExternalClient);
    }

    [Fact]
    public async Task DomainVisibilityTracksWhetherItOverridesCredential_AcrossSavedCredentialToggle()
    {
        // With a real RDP credential selected, a node-level domain that differs from the credential's
        // stays visible/editable through a saved-credentials toggle (never an invisible override),
        // while one that merely duplicates the credential's domain is redundant and hides.
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password, Domain = "CORP" };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Rdp;
        vm.SelectedCredential = rdpCred;

        // Drop to inline mode, type a domain that differs from the credential's.
        vm.UseSavedCredentials = false;
        Assert.True(vm.ShowRdpDomain);
        vm.RdpDomain = "LEGACY";

        // Re-enable saved credentials → distinct override is kept and stays visible (not invisible).
        vm.UseSavedCredentials = true;
        Assert.Equal("LEGACY", vm.RdpDomain);
        Assert.True(vm.ShowRdpDomain);

        // A value equal to the credential's domain is redundant → hidden.
        vm.RdpDomain = "CORP";
        Assert.False(vm.ShowRdpDomain);
    }

    [Fact]
    public async Task LoadFrom_KeepsDistinctRdpDomainOverrideVisible()
    {
        // An existing connection with both a saved RDP credential and a node-level RdpDomain that
        // differs from the credential's domain keeps the Domain field VISIBLE — the value still wins
        // at connect, so hiding it would be an invisible override the user can't discover or clear.
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password, Domain = "CORP" };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            Kind = NodeKind.Connection,
            CredentialId = rdpCred.Id,
            RdpDomain = "LEGACY",
        };

        vm.LoadFrom(source);

        Assert.Equal("LEGACY", vm.RdpDomain);
        Assert.True(vm.ShowRdpDomain); // distinct override (LEGACY != CORP) stays visible/editable
    }

    [Fact]
    public async Task LoadFrom_HidesRedundantRdpDomainDuplicatingCredential()
    {
        // A node-level RdpDomain equal to the saved RDP credential's domain is redundant (it can't
        // change the connect-time result), so the Domain field is hidden — the decluttering goal.
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password, Domain = "CORP" };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            Kind = NodeKind.Connection,
            CredentialId = rdpCred.Id,
            RdpDomain = "CORP",
        };

        vm.LoadFrom(source);

        Assert.Equal("CORP", vm.RdpDomain);
        Assert.False(vm.ShowRdpDomain); // redundant duplicate hidden
    }

    [Fact]
    public async Task WriteTo_DropsRedundantRdpDomainDuplicatingCredential()
    {
        // A hidden redundant duplicate must NOT be persisted: if it lingered and the credential's
        // domain were later edited, the stale node value would still win at connect
        // (explicitDomain ?? credentialDomain). WriteTo stores null so the credential stays authoritative.
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password, Domain = "CORP" };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            Kind = NodeKind.Connection,
            CredentialId = rdpCred.Id,
            RdpDomain = "CORP",
        };
        vm.LoadFrom(source);
        Assert.False(vm.ShowRdpDomain);

        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.Null(sink.RdpDomain);           // redundant duplicate dropped
        Assert.Equal(rdpCred.Id, sink.CredentialId); // credential remains authoritative
    }

    [Fact]
    public async Task WriteTo_PersistsDistinctRdpDomainOverride()
    {
        // A distinct override is visible and meaningful (it wins at connect), so WriteTo keeps it.
        var rdpCred = new CredentialProfile { Name = "rdp", Protocol = ProtocolType.Rdp, Kind = CredentialKind.Password, Domain = "CORP" };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(rdpCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            Kind = NodeKind.Connection,
            CredentialId = rdpCred.Id,
            RdpDomain = "LEGACY",
        };
        vm.LoadFrom(source);
        Assert.True(vm.ShowRdpDomain);

        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.Equal("LEGACY", sink.RdpDomain);
    }

    [Fact]
    public async Task ShowRdpDomain_VisibleWhenCredentialIdDoesNotResolve()
    {
        // A non-null CredentialId pointing at a deleted/unrestored credential doesn't resolve
        // (SelectedCredential is null), so no credential can supply the domain. The Domain field must
        // stay visible — it's the only place left to see/fix the domain — and the value must survive a
        // saved-credentials toggle.
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            Kind = NodeKind.Connection,
            CredentialId = Guid.NewGuid(), // references a credential that no longer exists
            RdpDomain = "CORP",
        };

        vm.LoadFrom(source);

        Assert.Null(vm.SelectedCredential);   // dangling id doesn't resolve
        Assert.True(vm.ShowRdpDomain);         // field stays visible so the user can see/fix it
        Assert.Equal("CORP", vm.RdpDomain);

        // The domain survives a saved-credentials toggle (nothing clears it).
        vm.UseSavedCredentials = false;
        vm.UseSavedCredentials = true;
        Assert.Equal("CORP", vm.RdpDomain);
        Assert.True(vm.ShowRdpDomain);
    }

    [Fact]
    public async Task ShowRdpDomain_VisibleWhenSelectedCredentialIsProtocolMismatched()
    {
        // A stale, protocol-mismatched credential (an SSH credential saved on an RDP node) is kept by
        // AppendStaleSelection so the binding round-trips, making SelectedCredential non-null — but an
        // SSH credential carries no RDP domain (CredentialDialog stores domains only for RDP creds).
        // Only a real RDP credential is authoritative, so the Domain field stays visible/editable and
        // the value survives a saved-credentials toggle.
        var sshCred = new CredentialProfile { Name = "ssh", Protocol = ProtocolType.Ssh, Kind = CredentialKind.Password };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(sshCred), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        var source = new ConnectionNode
        {
            Name = "n",
            Host = "h",
            Protocol = ProtocolType.Rdp,
            Kind = NodeKind.Connection,
            CredentialId = sshCred.Id, // SSH credential bound to an RDP node (protocol mismatch)
            RdpDomain = "CORP",
        };

        vm.LoadFrom(source);

        Assert.NotNull(vm.SelectedCredential); // stale selection preserved for round-trip
        Assert.Equal(ProtocolType.Ssh, vm.SelectedCredential!.Protocol);
        Assert.True(vm.ShowRdpDomain);          // SSH cred has no RDP domain → field stays visible
        Assert.Equal("CORP", vm.RdpDomain);

        // The domain survives a saved-credentials toggle (nothing clears it).
        vm.UseSavedCredentials = false;
        vm.UseSavedCredentials = true;
        Assert.Equal("CORP", vm.RdpDomain);
        Assert.True(vm.ShowRdpDomain);
    }

    [Fact]
    public async Task ShowRdpDomain_VisibleForDomainlessBitwardenRdpCredential()
    {
        // Bitwarden virtual credentials project login metadata only. When the login username is just
        // "alice", the RDP connection still needs a node-level domain field for "ACME\alice".
        var bitwardenCred = new CredentialProfile
        {
            Name = "bw-rdp",
            Protocol = ProtocolType.Rdp,
            Kind = CredentialKind.Password,
            Username = "alice",
            SecretProvider = CredentialSecretProvider.Bitwarden,
            BitwardenItemId = "item-1",
            IsVirtualBitwarden = true,
        };
        var vm = new ConnectionEditorViewModel(
            new SingleCredentialRepository(bitwardenCred),
            EmptyTunnelRepo(),
            new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Rdp;
        vm.SelectedCredential = bitwardenCred;

        Assert.True(vm.ShowRdpDomain);

        vm.RdpDomain = "ACME";
        var sink = new ConnectionNode { Kind = NodeKind.Connection };
        vm.WriteTo(sink);

        Assert.Equal("ACME", sink.RdpDomain);
        Assert.Equal(bitwardenCred.Id, sink.CredentialId);
    }

    [Fact]
    public async Task CanUseSshAutoSudo_InlineMode_VisibleEvenWithSshKeyCredentialSelected()
    {
        var key = new CredentialProfile { Name = "ssh-key", Protocol = ProtocolType.Ssh, Kind = CredentialKind.SshKey };
        var vm = new ConnectionEditorViewModel(new SingleCredentialRepository(key), EmptyTunnelRepo(), new FakeCredentialService());
        await vm.LoadCredentialsAsync();
        vm.Protocol = ProtocolType.Ssh;
        vm.SelectedCredential = key;

        // Saved-credential mode with a key credential → no login password → Auto sudo hidden.
        vm.UseSavedCredentials = true;
        Assert.False(vm.CanUseSshAutoSudo);

        // Switching to inline-password mode supplies a password → Auto sudo becomes usable even
        // though the now-unused selected credential is still an SSH key (must not stay hidden).
        vm.UseSavedCredentials = false;
        Assert.True(vm.CanUseSshAutoSudo);
    }

    [Fact]
    public async Task SshAutoSudoDescription_VariesByMode()
    {
        var vm = await NewEditorAsync();

        vm.SshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoOn;
        var on = vm.SshAutoSudoDescription;
        vm.SshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoOff;
        var off = vm.SshAutoSudoDescription;
        vm.SshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoInherit;
        var inherit = vm.SshAutoSudoDescription;

        Assert.NotEqual(on, off);
        Assert.NotEqual(on, inherit);
        Assert.NotEqual(off, inherit);
        // The "on" copy must keep the load-bearing caveat about sudo.
        Assert.Contains("sudo", on, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("fw.local", "fw.local", null)]
    [InlineData("10.0.0.1:8443", "10.0.0.1", 8443)]
    [InlineData("https://fw.local:8443/admin?x=1", "fw.local", 8443)]
    [InlineData("http://fw.local", "fw.local", null)]
    [InlineData("[fd00::1]:8443", "fd00::1", 8443)]
    public void ParseHttpAddress_SplitsHostAndPort(string raw, string expectedHost, int? expectedPort)
    {
        var (host, port) = ConnectionEditorViewModel.ParseHttpAddress(raw);
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
    }

    [Fact]
    public async Task Https_WriteTo_ParsesHostPort_AndPersistsIgnoreCert()
    {
        var vm = await NewEditorAsync();
        vm.Name = "fw";
        vm.Protocol = ProtocolType.Https;
        vm.Host = "10.0.0.1:8443";
        vm.HttpIgnoreCertErrors = true;

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.Equal(ProtocolType.Https, node.Protocol);
        Assert.Equal("10.0.0.1", node.Host);
        Assert.Equal(8443, node.Port);
        Assert.True(node.HttpIgnoreCertErrors);
    }

    [Fact]
    public async Task Http_WriteTo_DoesNotPersistIgnoreCert()
    {
        var vm = await NewEditorAsync();
        vm.Name = "fw";
        vm.Protocol = ProtocolType.Http;
        vm.Host = "fw.local";
        vm.HttpIgnoreCertErrors = true; // irrelevant for plain HTTP — must not persist

        var node = new ConnectionNode();
        vm.WriteTo(node);

        Assert.Equal("fw.local", node.Host);
        Assert.Null(node.Port);
        Assert.Null(node.HttpIgnoreCertErrors);
    }

    [Fact]
    public async Task Https_LoadFrom_FoldsCustomPortIntoAddressField_AndHidesCredentials()
    {
        var vm = await NewEditorAsync();
        var node = new ConnectionNode
        {
            Name = "fw",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Https,
            Host = "10.0.0.1",
            Port = 8443,
        };

        vm.LoadFrom(node);

        Assert.Equal("10.0.0.1:8443", vm.Host);
        Assert.Null(vm.Port);
        Assert.True(vm.IsHttps);
        Assert.False(vm.ShowCredentialSection);
    }

    [Fact]
    public async Task Https_LoadFrom_DefaultPort_NotFoldedIntoAddress()
    {
        var vm = await NewEditorAsync();
        var node = new ConnectionNode
        {
            Name = "fw",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Https,
            Host = "fw.local",
            Port = 443,
        };

        vm.LoadFrom(node);

        Assert.Equal("fw.local", vm.Host);
    }

    [Fact]
    public async Task Https_IPv6Host_RoundTripsCustomPort()
    {
        var vm = await NewEditorAsync();
        var source = new ConnectionNode
        {
            Name = "fw6",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Https,
            Host = "fd00::1",
            Port = 8443,
        };
        vm.LoadFrom(source);
        Assert.Equal("[fd00::1]:8443", vm.Host); // IPv6 is bracketed so the folded host:port round-trips

        var sink = new ConnectionNode();
        vm.WriteTo(sink);
        Assert.Equal("fd00::1", sink.Host);
        Assert.Equal(8443, sink.Port); // port preserved, not corrupted into the host
    }

    [Theory]
    [InlineData(":8443", false)]      // no host
    [InlineData("host:99999", false)] // out-of-range port folds into the host
    [InlineData("10.0.0.1:8443", true)]
    [InlineData("fw.example.com", true)]
    public async Task Https_AddressValidation_GatesSave(string address, bool expectedValid)
    {
        var vm = await NewEditorAsync();
        vm.Name = "fw";
        vm.Protocol = ProtocolType.Https;
        vm.Host = address;

        Assert.Equal(expectedValid, vm.IsValid);
        Assert.Equal(!expectedValid, vm.IsHttpAddressErrorOpen);
    }

    [Fact]
    public async Task Https_RoundTrip_PreservesCustomPortAndIgnoreCert()
    {
        var vm = await NewEditorAsync();
        var source = new ConnectionNode
        {
            Name = "fw",
            Kind = NodeKind.Connection,
            Protocol = ProtocolType.Https,
            Host = "10.0.0.1",
            Port = 8443,
            HttpIgnoreCertErrors = true,
        };
        vm.LoadFrom(source);

        var sink = new ConnectionNode();
        vm.WriteTo(sink);

        Assert.Equal("10.0.0.1", sink.Host);
        Assert.Equal(8443, sink.Port);
        Assert.True(sink.HttpIgnoreCertErrors);
    }

    private static async Task<ConnectionEditorViewModel> NewEditorAsync()
    {
        var vm = new ConnectionEditorViewModel(new EmptyCredentialRepository(), EmptyTunnelRepo(), new FakeCredentialService());
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
