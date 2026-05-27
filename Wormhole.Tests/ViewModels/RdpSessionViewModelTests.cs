using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Rdp;
using Wormhole.Services.Tunneling;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class RdpSessionViewModelTests
{
    [Fact]
    public void Initialize_PutsVmInDisconnectedState_NoError()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Null(vm.ErrorMessage);
        Assert.False(vm.IsConnecting);
        Assert.False(vm.IsConnected);
        Assert.False(vm.IsFailed);
    }

    [Fact]
    public void AttachConnectedSessionForTesting_FakeRaisesConnected_StatusFlipsToConnected()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        // AttachConnectedSessionForTesting itself sets Status=Connected (mirrors the SSH
        // hook). Driving Connected again via the event is a no-op but should not regress
        // state.
        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.True(vm.IsConnected);
    }

    [Fact]
    public void Disconnected_CleanCode_TransitionsToDisconnected_NoError()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseDisconnected(new RdpDisconnectInfo(2, 0, "User-initiated disconnect.", IsClean: true));

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Null(vm.ErrorMessage);
        Assert.False(vm.FailedDueToCredentials);
    }

    [Fact]
    public void Disconnected_FaultCode_TransitionsToFailed_WithDescription()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseDisconnected(new RdpDisconnectInfo(516, 0, "Could not reach the server.", IsClean: false));

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Equal("Could not reach the server.", vm.ErrorMessage);
        Assert.False(vm.FailedDueToCredentials);
    }

    [Fact]
    public void LogonError_PreAuthFailed_SetsCredentialsFailureFlag()
    {
        // Per IMsTscAxEvents.OnLogonError docs, -3 = pre-authentication failed → the user
        // should be prompted to re-enter credentials on retry.
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseLogonError(-3);

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.True(vm.FailedDueToCredentials);
        Assert.Contains("Pre-authentication failed", vm.ErrorMessage);
    }

    [Fact]
    public void LogonError_UserCancelledCredentialsDialog_SilentDisconnect()
    {
        // -2 = user dismissed the OCX's credentials dialog. That's a user action, not an
        // auth failure — the VM should transition to Disconnected without surfacing the
        // failure overlay.
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseLogonError(-2);

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.False(vm.FailedDueToCredentials);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public void LogonError_InformationDialog_DoesNotMarkCredentialFailure()
    {
        // -5 = informational dialog displayed (e.g. "Lock Workstation Failed"). Not an auth
        // problem; surface the message but don't prompt for credentials on retry.
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseLogonError(-5);

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.False(vm.FailedDueToCredentials);
        Assert.Contains("information dialog", vm.ErrorMessage);
    }

    [Fact]
    public void FatalError_TransitionsToFailed()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseFatalError(7); // unspecified fatal

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Contains("RDP fatal error", vm.ErrorMessage);
    }

    [Fact]
    public void AutoReconnecting_BumpsReconnectAttempt_KeepsConnectingStatus()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseAutoReconnecting(new RdpReconnectInfo(3, 20, 0));

        Assert.Equal(3, vm.ReconnectAttempt);
        Assert.Equal(SessionStatus.Connecting, vm.Status);
    }

    [Fact]
    public void Connected_PushesWin32FocusIntoActiveXHwnd()
    {
        // First-keystroke-dropped fix: when the OCX fires OnLoginComplete (mapped to
        // IRdpSession.Connected) the VM must call _session.Focus() so the embedded ActiveX
        // HWND receives keyboard focus. Without this the user has to click the RDP surface
        // before the first keystroke (e.g. into the Windows logon screen) is captured.
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);
        // Attach itself doesn't push focus — it's the OCX's OnLoginComplete that does.
        Assert.Equal(0, fake.FocusCount);

        fake.RaiseConnected();

        Assert.Equal(1, fake.FocusCount);
    }

    [Fact]
    public void AutoReconnected_DoesNotPushFocus()
    {
        // Auto-reconnect is not user-initiated. If the user has moved focus to another
        // tab / search box / app during the reconnect banner, pulling focus back to the
        // RDP surface mid-typing is worse than the original problem. The OCX retains its
        // own Win32 focus across most auto-reconnect cycles, so leaving focus alone is
        // the right default. Cold connect (RaiseConnected) is the only path that pushes.
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);
        fake.RaiseAutoReconnecting(new RdpReconnectInfo(2, 20, 0));
        var beforeReconnect = fake.FocusCount;

        fake.RaiseAutoReconnected();

        Assert.Equal(beforeReconnect, fake.FocusCount);
    }

    [Fact]
    public async Task AttachAsync_OnRebindWithLiveSession_PushesFocus()
    {
        // Rebind path: Sessions↔Settings nav back to a connected RDP tab re-runs
        // RdpSurfaceHost.OnLoaded → AttachAsync. With _session already set, the rebind
        // branch SetBounds/Show/Focus the existing OCX so the first keystroke after
        // nav-back lands on the remote session without a click. Without this test the
        // contract is only enforced by manual verification — pin it so a future refactor
        // that moves the TryFocusSession call out of the rebind branch trips a failure.
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);
        var beforeRebind = fake.FocusCount;

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Empty);

        Assert.Equal(beforeRebind + 1, fake.FocusCount);
    }

    [Fact]
    public void AutoReconnected_RestoresConnectedStatusAndClearsReconnectBanner()
    {
        // Without forwarding OnAutoReconnected, AutoReconnecting drove Status to Connecting
        // and nothing transitioned back — a successful auto-reconnect after a transient drop
        // would leave the tab stuck on the "Reconnecting…" banner forever.
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseAutoReconnecting(new RdpReconnectInfo(2, 20, 0));
        Assert.Equal(SessionStatus.Connecting, vm.Status);

        fake.RaiseAutoReconnected();

        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.Equal(0, vm.ReconnectAttempt);
        Assert.Null(vm.ErrorMessage);
    }

    [Fact]
    public async Task CloseAsync_DisposesSessionAndStaysDisconnected()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        await vm.CloseAsync();

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.True(fake.Disposed);
    }

    [Fact]
    public async Task DisconnectAsync_DisposesAndStaysDisconnected()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        await vm.DisconnectAsync();

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.True(fake.Disposed);
    }

    // --- ShouldUseExternalClientAsync (runtime AAD guard) ---------------------------------
    //
    // The PR-22 production crash was: user has CredentialId=null ("Prompt every time") and
    // RdpUseExternalClient=0, and types AzureAD\... credentials at the OCX prompt. The
    // routing decision must NOT silently fall through to the embedded path when there are
    // node-level AAD signals — the embedded mstscax crash kills the process and the log
    // entry "RDP session opened" lies about success because it fires before the WAM
    // delay-load failure. These tests pin down every input combination explicitly.

    [Fact]
    public async Task ShouldUseExternalClient_OptInFlag_AlwaysTrue()
    {
        var (vm, _, _, _, _) = CreateVm();
        var profile = MakeProfile() with { RdpUseExternalClient = true };
        Assert.True(await vm.ShouldUseExternalClientAsync(profile));
    }

    [Fact]
    public async Task ShouldUseExternalClient_NodeRdpDomainAzureAD_RoutesExternal()
    {
        // The exact production scenario from the crash logs: user typed "AzureAD" into the
        // node's Domain field with no saved credential. Before the fix, this returned false
        // and the embedded host crashed mid-handshake.
        var (vm, _, _, _, _) = CreateVm();
        var profile = MakeProfile() with
        {
            RdpUseExternalClient = false,
            CredentialId = null,
            RdpDomain = "AzureAD",
        };
        Assert.True(await vm.ShouldUseExternalClientAsync(profile));
    }

    [Fact]
    public async Task ShouldUseExternalClient_NodeUsernameAzureAdPrefix_RoutesExternal()
    {
        var (vm, _, _, _, _) = CreateVm();
        var profile = MakeProfile() with
        {
            RdpUseExternalClient = false,
            CredentialId = null,
            Username = "AzureAD\\alice@tenant.com",
        };
        Assert.True(await vm.ShouldUseExternalClientAsync(profile));
    }

    [Fact]
    public async Task ShouldUseExternalClient_SavedCredentialIsAzureAd_RoutesExternal()
    {
        // Credential-side detection through the repository. The credential is fetched only
        // when the flag is false and no node-level signals fired — exercising the DB path.
        var credId = Guid.NewGuid();
        var aadCred = new CredentialProfile
        {
            Id = credId,
            Name = "aad",
            Domain = "AzureAD",
            Protocol = ProtocolType.Rdp,
        };
        var vm = CreateVmWith(new SingleCredentialRepository(aadCred));
        var profile = MakeProfile() with
        {
            RdpUseExternalClient = false,
            CredentialId = credId,
        };

        Assert.True(await vm.ShouldUseExternalClientAsync(profile));
    }

    [Fact]
    public async Task ShouldUseExternalClient_NoAadSignalsAnywhere_StaysEmbedded()
    {
        var credId = Guid.NewGuid();
        var nonAadCred = new CredentialProfile
        {
            Id = credId,
            Name = "onprem",
            Domain = "CORP",
            Username = "alice",
            Protocol = ProtocolType.Rdp,
        };
        var vm = CreateVmWith(new SingleCredentialRepository(nonAadCred));
        var profile = MakeProfile() with
        {
            RdpUseExternalClient = false,
            CredentialId = credId,
            RdpDomain = "CORP",
            Username = "alice",
        };

        Assert.False(await vm.ShouldUseExternalClientAsync(profile));
    }

    [Fact]
    public async Task ShouldUseExternalClient_CredentialLookupThrows_FailsSafeToEmbedded()
    {
        // A repository hiccup must surface as embedded-routing (per the implementation's
        // documented contract). The user can still manually set the flag if they hit issues.
        var vm = CreateVmWith(new ThrowingCredentialRepository());
        var profile = MakeProfile() with
        {
            RdpUseExternalClient = false,
            CredentialId = Guid.NewGuid(),
        };

        Assert.False(await vm.ShouldUseExternalClientAsync(profile));
    }

    [Fact]
    public async Task ShouldUseExternalClient_UncheckedFlagWithAadDomain_OverrideIgnored()
    {
        // The user-visible regression that motivated this whole branch: pre-fix, unchecking
        // the box would route embedded → crash. Post-fix, an AAD-flagged node ignores the
        // unchecked state because no managed handler can catch the native WAM crash.
        var (vm, _, _, _, _) = CreateVm();
        var profile = MakeProfile() with
        {
            RdpUseExternalClient = false, // user explicitly tried to override
            RdpDomain = "AzureAD",
        };

        Assert.True(await vm.ShouldUseExternalClientAsync(profile));
    }

    [Fact]
    public void CanUseExternalClient_IsFalseForTunneledProfiles()
    {
        var (vm, _, _, _, _) = CreateVm();

        vm.Initialize(MakeProfile() with { TunnelEnabled = true, TunnelConfigId = Guid.NewGuid() });

        Assert.False(vm.CanUseExternalClient);
        Assert.False(vm.UseExternalClientCommand.CanExecute(null));
    }

    [Fact]
    public async Task UseExternalClient_TunnelEnabled_DoesNotTearDownConnectedSession()
    {
        var (vm, _, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile() with { TunnelEnabled = true, TunnelConfigId = Guid.NewGuid() });
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        await vm.UseExternalClient();

        Assert.Equal(SessionStatus.Connected, vm.Status);
        Assert.False(fake.Disposed);
    }

    [Fact]
    public async Task AttachAsync_NoUsernameOnProfile_PromptsForCredentialsAndForwardsTypedUsername()
    {
        // Profiles created without a username used to fall through to a password-only
        // prompt, which let the OCX silently use the current Windows user as the implicit
        // username. The fix routes the empty-username case through PromptCredentialsAsync
        // and threads the typed username into the profile that reaches the OCX.
        var (vm, svc, _, dlg, _) = CreateVm();
        dlg.CredentialsPromptResult = ("typed-user", "typed-password");
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with { Username = null });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(1, dlg.CredentialsPromptCount);
        Assert.Equal(0, dlg.PasswordPromptCount);
        Assert.Equal("typed-user", svc.LastProfile?.Username);
    }

    [Fact]
    public async Task AttachAsync_NoUsernameOnProfile_UserCancelsCredentialsPrompt_TransitionsToDisconnected()
    {
        // Cancelling the new credentials prompt must mirror the existing password-prompt
        // cancel path: silent return to Disconnected, no error overlay, no OCX session.
        var (vm, svc, _, dlg, _) = CreateVm();
        dlg.CredentialsPromptResult = null;

        vm.Initialize(MakeProfile() with { Username = null });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(1, dlg.CredentialsPromptCount);
        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Equal(0, svc.ConnectCount);
    }

    [Fact]
    public async Task AttachAsync_PromptedUsernameIsAzureAd_TunnelEnabled_FailsClosedAtExternalClientGuard()
    {
        // The external-client guard at the top of ConnectAsync runs BEFORE the credentials
        // prompt, so a profile with empty Username slips past it even when the user is
        // about to type an AAD identity. The fix re-evaluates the guard after the prompt
        // returns: combined with a tunnel, it should land on the same
        // TunnelExternalClientUnsupportedMessage as a profile that started with the AAD
        // username — proving we'd have refused embedded mstscax routing in the non-tunnel
        // case too (where the late re-check would have redirected to mstsc.exe instead of
        // crashing on WAM broker DLL load).
        var provider = new FakeTunnelProvider();
        var (vm, svc, _, dlg, _) = CreateVm(tunnelProviders: new ITunnelProvider[] { provider });
        dlg.CredentialsPromptResult = ("AzureAD\\alice@tenant.com", "pwd");
        vm.Initialize(MakeProfile() with
        {
            Username = null,
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
        });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Contains("host network", vm.ErrorMessage);
        Assert.Equal(0, svc.ConnectCount);
        Assert.Equal(0, provider.EstablishCount);
        Assert.Equal(1, dlg.CredentialsPromptCount);
    }

    [Fact]
    public async Task AttachAsync_SavedCredentialUsernameDomainPassword_ConnectsWithoutPrompt()
    {
        var credId = Guid.NewGuid();
        var credential = new CredentialProfile
        {
            Id = credId,
            Name = "corp-rdp",
            Username = "svc-rdp",
            Domain = "CORP",
            Protocol = ProtocolType.Rdp,
        };
        var secrets = new FakeCredentialService(new Dictionary<Guid, string> { [credId] = "saved-secret" });
        var (vm, svc, _, dlg, _) = CreateVm(
            credentialRepository: new SingleCredentialRepository(credential),
            creds: secrets);
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with { Username = null, RdpDomain = null, CredentialId = credId });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(0, dlg.PasswordPromptCount);
        Assert.Equal(0, dlg.CredentialsPromptCount);
        Assert.Equal("svc-rdp", svc.LastProfile?.Username);
        Assert.Equal("CORP", svc.LastProfile?.RdpDomain);
        Assert.Equal("saved-secret", svc.LastPassword);
    }

    [Fact]
    public async Task AttachAsync_ExplicitUsernameAndDomainOverrideCredentialIdentity()
    {
        var credId = Guid.NewGuid();
        var credential = new CredentialProfile
        {
            Id = credId,
            Name = "corp-rdp",
            Username = "svc-rdp",
            Domain = "CORP",
            Protocol = ProtocolType.Rdp,
        };
        var secrets = new FakeCredentialService(new Dictionary<Guid, string> { [credId] = "saved-secret" });
        var (vm, svc, _, _, _) = CreateVm(
            credentialRepository: new SingleCredentialRepository(credential),
            creds: secrets);
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with
        {
            Username = "local-user",
            RdpDomain = "LOCAL",
            CredentialId = credId,
        });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal("local-user", svc.LastProfile?.Username);
        Assert.Equal("LOCAL", svc.LastProfile?.RdpDomain);
        Assert.Equal("saved-secret", svc.LastPassword);
    }

    [Fact]
    public async Task AttachAsync_LinkedCredentialDomainUsedWhenProfileDomainBlank()
    {
        var credId = Guid.NewGuid();
        var credential = new CredentialProfile
        {
            Id = credId,
            Name = "corp-rdp",
            Username = "ignored-by-explicit-profile",
            Domain = "CORP",
            Protocol = ProtocolType.Rdp,
        };
        var secrets = new FakeCredentialService(new Dictionary<Guid, string> { [credId] = "saved-secret" });
        var (vm, svc, _, _, _) = CreateVm(
            credentialRepository: new SingleCredentialRepository(credential),
            creds: secrets);
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with
        {
            Username = "node-user",
            RdpDomain = null,
            CredentialId = credId,
        });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal("node-user", svc.LastProfile?.Username);
        Assert.Equal("CORP", svc.LastProfile?.RdpDomain);
    }

    [Fact]
    public async Task AttachAsync_LinkedCredentialDomainPreservesDomainSlashUsername()
    {
        var credId = Guid.NewGuid();
        var credential = new CredentialProfile
        {
            Id = credId,
            Name = "corp-rdp",
            Username = "OTHER\\svc-rdp",
            Domain = "CORP",
            Protocol = ProtocolType.Rdp,
        };
        var secrets = new FakeCredentialService(new Dictionary<Guid, string> { [credId] = "saved-secret" });
        var (vm, svc, _, _, _) = CreateVm(
            credentialRepository: new SingleCredentialRepository(credential),
            creds: secrets);
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with { Username = null, RdpDomain = null, CredentialId = credId });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal("OTHER\\svc-rdp", svc.LastProfile?.Username);
        Assert.Equal("CORP", svc.LastProfile?.RdpDomain);
    }

    [Fact]
    public async Task AttachAsync_EmptySavedPassword_IsPassedWithoutPrompt()
    {
        var credId = Guid.NewGuid();
        var credential = new CredentialProfile
        {
            Id = credId,
            Name = "empty-password",
            Username = "svc-rdp",
            Protocol = ProtocolType.Rdp,
        };
        var secrets = new FakeCredentialService(new Dictionary<Guid, string> { [credId] = string.Empty });
        var (vm, svc, _, dlg, _) = CreateVm(
            credentialRepository: new SingleCredentialRepository(credential),
            creds: secrets);
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with { Username = null, CredentialId = credId });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(0, dlg.PasswordPromptCount);
        Assert.Equal(0, dlg.CredentialsPromptCount);
        Assert.Equal(string.Empty, svc.LastPassword);
    }

    [Fact]
    public async Task AttachAsync_MissingSavedSecret_UserCancelsPrompt_TransitionsToDisconnected()
    {
        var credId = Guid.NewGuid();
        var credential = new CredentialProfile
        {
            Id = credId,
            Name = "missing-secret",
            Username = "svc-rdp",
            Protocol = ProtocolType.Rdp,
        };
        var (vm, svc, _, dlg, _) = CreateVm(
            credentialRepository: new SingleCredentialRepository(credential));
        dlg.PasswordPromptResult = null;

        vm.Initialize(MakeProfile() with { Username = null, CredentialId = credId });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(1, dlg.PasswordPromptCount);
        Assert.Equal(0, svc.ConnectCount);
        Assert.Equal(SessionStatus.Disconnected, vm.Status);
    }

    [Fact]
    public async Task AttachAsync_PromptedDomainSlashUsername_IsNormalizedBeforeConnect()
    {
        var (vm, svc, _, dlg, _) = CreateVm();
        dlg.CredentialsPromptResult = ("CORP\\alice", "typed-password");
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with { Username = null, RdpDomain = null });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal("alice", svc.LastProfile?.Username);
        Assert.Equal("CORP", svc.LastProfile?.RdpDomain);
        Assert.Equal("typed-password", svc.LastPassword);
    }

    [Fact]
    public async Task AttachAsync_PromptedDomainSlashUsername_WithExplicitDomainPreservesUsername()
    {
        var (vm, svc, _, dlg, _) = CreateVm();
        dlg.CredentialsPromptResult = ("CORP\\alice", "typed-password");
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with { Username = null, RdpDomain = "EXPLICIT" });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal("CORP\\alice", svc.LastProfile?.Username);
        Assert.Equal("EXPLICIT", svc.LastProfile?.RdpDomain);
    }

    [Fact]
    public async Task AttachAsync_PromptedDomainSlashUsername_WithCredentialDomainPreservesUsername()
    {
        var credId = Guid.NewGuid();
        var credential = new CredentialProfile
        {
            Id = credId,
            Name = "domain-only",
            Domain = "CORP",
            Protocol = ProtocolType.Rdp,
        };
        var (vm, svc, _, dlg, _) = CreateVm(
            credentialRepository: new SingleCredentialRepository(credential));
        dlg.CredentialsPromptResult = ("OTHER\\alice", "typed-password");
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with { Username = null, RdpDomain = null, CredentialId = credId });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal("OTHER\\alice", svc.LastProfile?.Username);
        Assert.Equal("CORP", svc.LastProfile?.RdpDomain);
        Assert.Equal("typed-password", svc.LastPassword);
    }

    // --- Per-connection VPN routing -------------------------------------------------------

    [Fact]
    public async Task AttachAsync_TunnelEnabled_RoutesEmbeddedRdpThroughLoopbackForwarder()
    {
        var configId = Guid.NewGuid();
        var tunnelRepo = new FakeTunnelConfigRepository();
        var provider = new FakeTunnelProvider();
        tunnelRepo.Configs[configId] = new TunnelConfig { Id = configId, Name = "corp", Kind = TunnelKind.WireGuard };

        var (vm, svc, creds, dlg, _) = CreateVm(
            tunnelRepo: tunnelRepo,
            tunnelProviders: new ITunnelProvider[] { provider });
        creds.TunnelConfigs[configId] = new byte[] { 1, 2, 3 };
        dlg.PasswordPromptResult = "password";
        svc.NextSession = new FakeRdpSession();

        vm.Initialize(MakeProfile() with { TunnelEnabled = true, TunnelConfigId = configId });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(1, provider.EstablishCount);
        Assert.NotNull(provider.LastInstance);
        Assert.Equal("host", provider.LastInstance!.LastForwardHost);
        Assert.Equal(3389, provider.LastInstance.LastForwardPort);
        Assert.Equal(IPAddress.Loopback.ToString(), svc.LastProfile?.Host);
        Assert.Equal(provider.LastInstance.BoundPort, svc.LastProfile?.Port);

        await vm.DisconnectAsync();
        Assert.Equal(1, provider.LastInstance.DisposeCount);
    }

    [Fact]
    public async Task AttachAsync_TunnelEnabled_ExternalClientFailsClosed()
    {
        var provider = new FakeTunnelProvider();
        var (vm, svc, _, _, _) = CreateVm(tunnelProviders: new ITunnelProvider[] { provider });
        vm.Initialize(MakeProfile() with
        {
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
            RdpUseExternalClient = true,
        });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Contains("host network", vm.ErrorMessage);
        Assert.Equal(0, svc.ConnectCount);
        Assert.Equal(0, provider.EstablishCount);
    }

    [Fact]
    public async Task AttachAsync_TunnelEnabled_RdGatewayFailsClosed()
    {
        var provider = new FakeTunnelProvider();
        var (vm, svc, _, _, _) = CreateVm(tunnelProviders: new ITunnelProvider[] { provider });
        vm.Initialize(MakeProfile() with
        {
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
            RdpGatewayUsageMethod = 1,
        });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Contains("RD Gateway", vm.ErrorMessage);
        Assert.Equal(0, svc.ConnectCount);
        Assert.Equal(0, provider.EstablishCount);
    }

    [Fact]
    public async Task AttachAsync_TunnelEnabled_StrictServerAuthenticationFailsClosed()
    {
        var provider = new FakeTunnelProvider();
        var (vm, svc, _, _, _) = CreateVm(tunnelProviders: new ITunnelProvider[] { provider });
        vm.Initialize(MakeProfile() with
        {
            TunnelEnabled = true,
            TunnelConfigId = Guid.NewGuid(),
            RdpServerAuthentication = 1,
        });

        await vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Contains("server authentication", vm.ErrorMessage);
        Assert.Equal(0, svc.ConnectCount);
        Assert.Equal(0, provider.EstablishCount);
    }

    [Fact]
    public async Task DisconnectAsync_DuringTunnelEstablish_DisposesLateTunnelAndStaysDisconnected()
    {
        var configId = Guid.NewGuid();
        var tunnelRepo = new FakeTunnelConfigRepository();
        var provider = new BlockingTunnelProvider();
        tunnelRepo.Configs[configId] = new TunnelConfig { Id = configId, Name = "corp", Kind = TunnelKind.WireGuard };

        var (vm, svc, creds, dlg, _) = CreateVm(
            tunnelRepo: tunnelRepo,
            tunnelProviders: new ITunnelProvider[] { provider });
        creds.TunnelConfigs[configId] = new byte[] { 1, 2, 3 };
        dlg.PasswordPromptResult = "password";
        svc.NextSession = new FakeRdpSession();
        vm.Initialize(MakeProfile() with { TunnelEnabled = true, TunnelConfigId = configId });

        var attachTask = vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);
        await provider.EstablishStarted.Task;

        await vm.DisconnectAsync();
        provider.ReleaseEstablish.SetResult(null);
        await attachTask;

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Equal(0, svc.ConnectCount);
        Assert.NotNull(provider.LastInstance);
        Assert.Equal(1, provider.LastInstance!.DisposeCount);
    }

    [Fact]
    public async Task DisconnectAsync_DuringTunnelForwarderBind_DisposesTunnelAndStaysDisconnected()
    {
        var configId = Guid.NewGuid();
        var tunnelRepo = new FakeTunnelConfigRepository();
        var instance = new FakeTunnelInstance();
        var provider = new FakeTunnelProvider(instance);
        tunnelRepo.Configs[configId] = new TunnelConfig { Id = configId, Name = "corp", Kind = TunnelKind.WireGuard };

        var (vm, svc, creds, dlg, _) = CreateVm(
            tunnelRepo: tunnelRepo,
            tunnelProviders: new ITunnelProvider[] { provider });
        creds.TunnelConfigs[configId] = new byte[] { 1, 2, 3 };
        dlg.PasswordPromptResult = "password";
        svc.NextSession = new FakeRdpSession();
        instance.ReleaseBind = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        vm.Initialize(MakeProfile() with { TunnelEnabled = true, TunnelConfigId = configId });

        var attachTask = vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);
        await instance.BindStarted.Task;

        await vm.DisconnectAsync();
        instance.ReleaseBind.SetResult(null);
        await attachTask;

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Equal(0, svc.ConnectCount);
        Assert.Equal(1, instance.DisposeCount);
    }

    [Fact]
    public async Task DisconnectAsync_DuringRdpServiceConnect_DisposesLateSessionAndStaysDisconnected()
    {
        var (vm, svc, _, dlg, _) = CreateVm();
        dlg.PasswordPromptResult = "password";
        var session = new FakeRdpSession();
        svc.NextSession = session;
        svc.ReleaseConnect = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        vm.Initialize(MakeProfile());

        var attachTask = vm.AttachAsync(IntPtr.Zero, HostBounds.Seed);
        await svc.ConnectStarted.Task;

        await vm.DisconnectAsync();
        svc.ReleaseConnect.SetResult(null);
        await attachTask;

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.True(session.Disposed);
    }

    // --- Crash sentinel + Status hook ownership -------------------------------------------

    [Fact]
    public void StatusHook_OnStatusChangeWithoutOurMark_DoesNotClearSentinel()
    {
        // The multi-tab race: an external-client tab whose Status flips through
        // Connecting → Connected → Disconnected must NOT clear a sentinel some other VM
        // wrote for an embedded attempt. _ownsCrashSentinel gates the clear so unowned
        // transitions are no-ops.
        var (vm, _, _, _, sentinel) = CreateVm();
        vm.Initialize(MakeProfile());

        // Drive Status transitions without going through ConnectAsync, so _ownsCrashSentinel
        // stays false. This mirrors the external-client path which sets Status directly.
        vm.Status = SessionStatus.Connecting;
        vm.Status = SessionStatus.Connected;
        vm.Status = SessionStatus.Disconnected;

        Assert.Equal(0, sentinel.ClearCount);
    }

    private static ConnectionProfile MakeProfile(bool fullScreen = false)
        => new()
        {
            NodeId = Guid.NewGuid(),
            Name = "rdp-test",
            Protocol = ProtocolType.Rdp,
            Host = "host",
            Port = 3389,
            // Default to a non-empty username so the credential-resolution path stays on
            // the password-only prompt branch; tests that exercise the missing-username
            // branch override this with `MakeProfile() with { Username = null }`.
            Username = "rdp-user",
            RdpFullScreen = fullScreen,
        };

    private static (RdpSessionViewModel vm, FakeRdpSessionService svc, FakeCredentialService creds, FakeDialogService dlg, FakeRdpCrashSentinelService sentinel) CreateVm(
        ICredentialRepository? credentialRepository = null,
        FakeCredentialService? creds = null,
        FakeDialogService? dlg = null,
        FakeRdpCrashSentinelService? sentinel = null,
        FakeTunnelConfigRepository? tunnelRepo = null,
        IEnumerable<ITunnelProvider>? tunnelProviders = null)
    {
        var svc = new FakeRdpSessionService();
        creds ??= new FakeCredentialService();
        dlg ??= new FakeDialogService();
        var repo = credentialRepository ?? new EmptyCredentialRepository();
        sentinel ??= new FakeRdpCrashSentinelService();
        var vm = new RdpSessionViewModel(
            svc,
            creds,
            repo,
            BuildTunnelManager(creds, tunnelRepo, tunnelProviders),
            dlg,
            sentinel,
            NullLoggerFactory.Instance);
        return (vm, svc, creds, dlg, sentinel);
    }

    internal static RdpSessionViewModel CreateVmWith(
        ICredentialRepository credentialRepository,
        IRdpCrashSentinelService? sentinel = null)
    {
        var creds = new FakeCredentialService();
        return new RdpSessionViewModel(
            new FakeRdpSessionService(),
            creds,
            credentialRepository,
            BuildTunnelManager(creds),
            new FakeDialogService(),
            sentinel ?? new FakeRdpCrashSentinelService(),
            NullLoggerFactory.Instance);
    }

    private static TunnelManager BuildTunnelManager(
        FakeCredentialService credentials,
        FakeTunnelConfigRepository? repo = null,
        IEnumerable<ITunnelProvider>? providers = null)
        => new(
            providers ?? Array.Empty<ITunnelProvider>(),
            repo ?? new FakeTunnelConfigRepository(),
            credentials,
            NullLoggerFactory.Instance.CreateLogger<TunnelManager>());

    private sealed class FakeRdpSessionService : IRdpSessionService
    {
        public IRdpSession? NextSession { get; set; }
        public ConnectionProfile? LastProfile { get; private set; }
        public string? LastPassword { get; private set; }
        public int ConnectCount { get; private set; }
        public TaskCompletionSource<object?> ConnectStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<object?>? ReleaseConnect { get; set; }

        public async Task<IRdpSession> ConnectAsync(
            ConnectionProfile profile,
            string? password,
            IntPtr ownerHwnd,
            string? gatewayUsername = null,
            string? gatewayPassword = null,
            Action<IRdpSession>? onSessionReady = null,
            CancellationToken cancellationToken = default)
        {
            ConnectCount++;
            LastProfile = profile;
            LastPassword = password;
            if (NextSession is null) throw new InvalidOperationException("FakeRdpSessionService.NextSession not assigned.");
            // Mirror the real service: subscribe-via-callback runs before the handshake starts.
            onSessionReady?.Invoke(NextSession);
            ConnectStarted.TrySetResult(null);
            if (ReleaseConnect is not null)
            {
                await ReleaseConnect.Task.ConfigureAwait(false);
            }
            return NextSession;
        }
    }

    private sealed class FakeTunnelProvider : ITunnelProvider
    {
        public int EstablishCount { get; private set; }
        public FakeTunnelInstance? LastInstance { get; private set; }
        public TunnelKind Kind => TunnelKind.WireGuard;
        private readonly FakeTunnelInstance? _instance;

        public FakeTunnelProvider(FakeTunnelInstance? instance = null)
        {
            _instance = instance;
        }

        public Task<ITunnelInstance> EstablishAsync(TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken)
        {
            EstablishCount++;
            LastInstance = _instance ?? new FakeTunnelInstance();
            return Task.FromResult<ITunnelInstance>(LastInstance);
        }
    }

    private sealed class BlockingTunnelProvider : ITunnelProvider
    {
        public TaskCompletionSource<object?> EstablishStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<object?> ReleaseEstablish { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public FakeTunnelInstance? LastInstance { get; private set; }
        public TunnelKind Kind => TunnelKind.WireGuard;

        public async Task<ITunnelInstance> EstablishAsync(TunnelConfig config, byte[] secretBlob, CancellationToken cancellationToken)
        {
            EstablishStarted.TrySetResult(null);
            await ReleaseEstablish.Task.ConfigureAwait(false);
            LastInstance = new FakeTunnelInstance();
            return LastInstance;
        }
    }

    private sealed class FakeTunnelInstance : ITunnelInstance
    {
        public int BoundPort { get; } = 49152;
        public string? LastForwardHost { get; private set; }
        public int? LastForwardPort { get; private set; }
        public int DisposeCount { get; private set; }
        public TaskCompletionSource<object?> BindStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<object?>? ReleaseBind { get; set; }
        public TunnelState State { get; private set; } = TunnelState.Up;
        public event EventHandler<TunnelStateChangedEventArgs>? StateChanged;
        public IPEndPoint? Socks5Endpoint => null;

        public Task<Stream> DialAsync(string host, int port, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public async Task<int> BindLocalForwarderAsync(string host, int port, CancellationToken cancellationToken)
        {
            BindStarted.TrySetResult(null);
            if (ReleaseBind is not null)
            {
                await ReleaseBind.Task.ConfigureAwait(false);
            }
            LastForwardHost = host;
            LastForwardPort = port;
            return BoundPort;
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            State = TunnelState.Closed;
            StateChanged?.Invoke(this, new TunnelStateChangedEventArgs(TunnelState.Closed));
            return ValueTask.CompletedTask;
        }
    }

    private sealed class EmptyCredentialRepository : Wormhole.Data.Repositories.ICredentialRepository
    {
        public Task<System.Collections.Generic.IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<System.Collections.Generic.IReadOnlyList<CredentialProfile>>(System.Array.Empty<CredentialProfile>());
        public Task<CredentialProfile?> GetByIdAsync(System.Guid id, CancellationToken ct = default) => Task.FromResult<CredentialProfile?>(null);
        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default) => Task.CompletedTask;
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default) => Task.CompletedTask;
        public Task DeleteAsync(System.Guid id, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class SingleCredentialRepository : Wormhole.Data.Repositories.ICredentialRepository
    {
        private readonly CredentialProfile _credential;
        public SingleCredentialRepository(CredentialProfile credential) => _credential = credential;
        public Task<System.Collections.Generic.IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => Task.FromResult<System.Collections.Generic.IReadOnlyList<CredentialProfile>>(new[] { _credential });
        public Task<CredentialProfile?> GetByIdAsync(System.Guid id, CancellationToken ct = default)
            => Task.FromResult<CredentialProfile?>(id == _credential.Id ? _credential : null);
        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default) => Task.CompletedTask;
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default) => Task.CompletedTask;
        public Task DeleteAsync(System.Guid id, CancellationToken ct = default) => Task.CompletedTask;
    }

    private sealed class ThrowingCredentialRepository : Wormhole.Data.Repositories.ICredentialRepository
    {
        public Task<System.Collections.Generic.IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => throw new InvalidOperationException("simulated repository fault");
        public Task<CredentialProfile?> GetByIdAsync(System.Guid id, CancellationToken ct = default)
            => throw new InvalidOperationException("simulated repository fault");
        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default) => Task.CompletedTask;
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default) => Task.CompletedTask;
        public Task DeleteAsync(System.Guid id, CancellationToken ct = default) => Task.CompletedTask;
    }
}
