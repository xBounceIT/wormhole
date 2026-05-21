using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class RdpSessionViewModelTests
{
    [Fact]
    public void Initialize_PutsVmInDisconnectedState_NoError()
    {
        var (vm, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.Null(vm.ErrorMessage);
        Assert.False(vm.IsConnecting);
        Assert.False(vm.IsConnected);
        Assert.False(vm.IsFailed);
    }

    [Fact]
    public void Initialize_FromProfileWithRdpFullScreen_SeedsIsMaximized()
    {
        var (vm, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile(fullScreen: true));

        Assert.True(vm.IsMaximized);
    }

    [Fact]
    public void AttachConnectedSessionForTesting_FakeRaisesConnected_StatusFlipsToConnected()
    {
        var (vm, _, _, _) = CreateVm();
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
        var (vm, _, _, _) = CreateVm();
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
        var (vm, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseDisconnected(new RdpDisconnectInfo(516, 0, "Could not reach the server.", IsClean: false));

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.Equal("Could not reach the server.", vm.ErrorMessage);
        Assert.False(vm.FailedDueToCredentials);
    }

    [Fact]
    public void LogonError_BadPassword_SetsCredentialsFailureFlag()
    {
        var (vm, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseLogonError(-2);

        Assert.Equal(SessionStatus.Failed, vm.Status);
        Assert.True(vm.FailedDueToCredentials);
        Assert.Contains("Bad username or password", vm.ErrorMessage);
    }

    [Fact]
    public void FatalError_TransitionsToFailed()
    {
        var (vm, _, _, _) = CreateVm();
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
        var (vm, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        fake.RaiseAutoReconnecting(new RdpReconnectInfo(3, 20, 0));

        Assert.Equal(3, vm.ReconnectAttempt);
        Assert.Equal(SessionStatus.Connecting, vm.Status);
    }

    [Fact]
    public async Task CloseAsync_DisposesSessionAndStaysDisconnected()
    {
        var (vm, _, _, _) = CreateVm();
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
        var (vm, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile());
        var fake = new FakeRdpSession();
        vm.AttachConnectedSessionForTesting(fake);

        await vm.DisconnectAsync();

        Assert.Equal(SessionStatus.Disconnected, vm.Status);
        Assert.True(fake.Disposed);
    }

    [Fact]
    public void ToggleMaximize_FlipsIsMaximized()
    {
        var (vm, _, _, _) = CreateVm();
        vm.Initialize(MakeProfile(fullScreen: false));
        Assert.False(vm.IsMaximized);

        vm.ToggleMaximizeCommand.Execute(null);
        Assert.True(vm.IsMaximized);

        vm.ToggleMaximizeCommand.Execute(null);
        Assert.False(vm.IsMaximized);
    }

    private static ConnectionProfile MakeProfile(bool fullScreen = false)
        => new()
        {
            NodeId = Guid.NewGuid(),
            Name = "rdp-test",
            Protocol = ProtocolType.Rdp,
            Host = "host",
            Port = 3389,
            RdpFullScreen = fullScreen,
        };

    private static (RdpSessionViewModel vm, FakeRdpSessionService svc, FakeCredentialService creds, FakeDialogService dlg) CreateVm()
    {
        var svc = new FakeRdpSessionService();
        var creds = new FakeCredentialService();
        var dlg = new FakeDialogService();
        var vm = new RdpSessionViewModel(svc, creds, dlg, NullLoggerFactory.Instance);
        return (vm, svc, creds, dlg);
    }

    private sealed class FakeRdpSessionService : IRdpSessionService
    {
        public IRdpSession? NextSession { get; set; }

        public Task<IRdpSession> ConnectAsync(ConnectionProfile profile, string? password, IntPtr ownerHwnd, CancellationToken cancellationToken = default)
        {
            if (NextSession is null) throw new InvalidOperationException("FakeRdpSessionService.NextSession not assigned.");
            return Task.FromResult(NextSession);
        }
    }
}
