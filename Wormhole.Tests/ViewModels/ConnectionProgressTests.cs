using System.Linq;
using Wormhole.Models;
using Wormhole.ViewModels.Sessions;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class ConnectionProgressTests
{
    private static readonly (ConnectionPhase Phase, string Label)[] TunnelSteps =
    {
        (ConnectionPhase.Credentials, "Credentials"),
        (ConnectionPhase.Tunnel, "VPN tunnel"),
        (ConnectionPhase.Connect, "Connect"),
    };

    private static ConnectionProgress TunneledProgress()
    {
        var p = new ConnectionProgress();
        p.Initialize(TunnelSteps);
        return p;
    }

    [Fact]
    public void Initialize_NumbersStepsInOrder_AllPending_LastFlagged_Active()
    {
        var p = TunneledProgress();

        Assert.True(p.IsActive);
        Assert.Equal(3, p.Steps.Count);
        Assert.Equal("1,2,3", string.Join(",", p.Steps.Select(s => s.Number)));
        Assert.All(p.Steps, s => Assert.Equal(ConnectionStepState.Pending, s.State));
        Assert.False(p.Steps[0].IsLast);
        Assert.False(p.Steps[1].IsLast);
        Assert.True(p.Steps[2].IsLast);
    }

    [Fact]
    public void Begin_MarksEarlierStepsCompleted_TargetActive_LaterPending()
    {
        var p = TunneledProgress();

        p.Begin(ConnectionPhase.Tunnel);

        Assert.Equal(ConnectionStepState.Completed, p.Steps[0].State);
        Assert.Equal(ConnectionStepState.Active, p.Steps[1].State);
        Assert.Equal(ConnectionStepState.Pending, p.Steps[2].State);
    }

    [Fact]
    public void Begin_ClearsStaleDetailFromPreviousStep()
    {
        var p = TunneledProgress();
        p.Begin(ConnectionPhase.Tunnel);
        p.Detail = "Bringing up the VPN tunnel…";

        p.Begin(ConnectionPhase.Connect);

        Assert.Null(p.Detail);
        Assert.Equal(ConnectionStepState.Completed, p.Steps[1].State);
        Assert.Equal(ConnectionStepState.Active, p.Steps[2].State);
    }

    [Fact]
    public void Begin_UnknownPhase_OnEmptyProgress_IsNoOp()
    {
        var p = new ConnectionProgress(); // no steps (direct connection)

        p.Begin(ConnectionPhase.Tunnel);

        Assert.False(p.IsActive);
        Assert.Empty(p.Steps);
    }

    [Fact]
    public void CompleteAll_MarksEveryStepCompleted_AndClearsDetail()
    {
        var p = TunneledProgress();
        p.Begin(ConnectionPhase.Tunnel);
        p.Detail = "x";

        p.CompleteAll();

        Assert.All(p.Steps, s => Assert.Equal(ConnectionStepState.Completed, s.State));
        Assert.Null(p.Detail);
    }

    [Fact]
    public void Fail_MarksActiveStepFailed_LeavesCompletedAndPendingUntouched()
    {
        var p = TunneledProgress();
        p.Begin(ConnectionPhase.Tunnel); // step 0 completed, step 1 active, step 2 pending
        p.Detail = "Bringing up the VPN tunnel…";

        p.Fail();

        Assert.Equal(ConnectionStepState.Completed, p.Steps[0].State);
        Assert.Equal(ConnectionStepState.Failed, p.Steps[1].State);
        Assert.Equal(ConnectionStepState.Pending, p.Steps[2].State);
        // A genuine mid-step failure surfaces the stepper in the failure overlay and drops the
        // now-misleading progressive detail line.
        Assert.True(p.HasFailedStep);
        Assert.Null(p.Detail);
    }

    [Fact]
    public void Fail_AfterCompleteAll_DoesNotFlagFailedStep()
    {
        // A drop after the connection had fully completed (all steps green) must NOT surface the
        // stepper in the failure overlay — there's no active step to fail, so the plain error shows.
        var p = TunneledProgress();
        p.CompleteAll();

        p.Fail();

        Assert.False(p.HasFailedStep);
        Assert.All(p.Steps, s => Assert.Equal(ConnectionStepState.Completed, s.State));
    }

    [Fact]
    public void CompleteAll_And_Reset_ClearHasFailedStep()
    {
        var p = TunneledProgress();
        p.Begin(ConnectionPhase.Tunnel);
        p.Fail();
        Assert.True(p.HasFailedStep);

        p.CompleteAll();
        Assert.False(p.HasFailedStep);

        p.Begin(ConnectionPhase.Tunnel);
        p.Fail();
        Assert.True(p.HasFailedStep);

        p.Reset();
        Assert.False(p.HasFailedStep);
    }

    [Fact]
    public void Begin_DoesNotOverwriteAFailedEarlierStep()
    {
        // Defensive: a re-Begin after a failure must not flip a Failed step to Completed.
        var p = TunneledProgress();
        p.Begin(ConnectionPhase.Credentials);
        p.Fail(); // credentials failed

        p.Begin(ConnectionPhase.Connect);

        Assert.Equal(ConnectionStepState.Failed, p.Steps[0].State);
        Assert.Equal(ConnectionStepState.Active, p.Steps[2].State);
    }

    [Fact]
    public void Reset_ClearsStepsDetailAndActiveFlag()
    {
        var p = TunneledProgress();
        p.Begin(ConnectionPhase.Tunnel);
        p.Detail = "x";

        p.Reset();

        Assert.False(p.IsActive);
        Assert.Empty(p.Steps);
        Assert.Null(p.Detail);
    }

    [Fact]
    public void Step_StateChange_RaisesDerivedFlagNotifications()
    {
        var step = new ConnectionStep(ConnectionPhase.Tunnel, 2, "VPN tunnel", isLast: false);
        var raised = new System.Collections.Generic.List<string>();
        step.PropertyChanged += (_, e) => raised.Add(e.PropertyName!);

        step.State = ConnectionStepState.Active;

        Assert.Contains(nameof(ConnectionStep.IsActive), raised);
        Assert.Contains(nameof(ConnectionStep.IsPending), raised);
        Assert.Contains(nameof(ConnectionStep.IsCompleted), raised);
        Assert.Contains(nameof(ConnectionStep.IsFailed), raised);
        Assert.True(step.IsActive);
        Assert.False(step.IsPending);
    }

    [Theory]
    [InlineData(TunnelPhase.Preparing)]
    [InlineData(TunnelPhase.Authenticating)]
    [InlineData(TunnelPhase.DownloadingConfiguration)]
    [InlineData(TunnelPhase.StartingTunnel)]
    public void DescribeTunnelPhase_ReturnsNonEmptyDefault_PerPhase(TunnelPhase phase)
    {
        var text = ConnectionProgress.DescribeTunnelPhase(new TunnelProgress(phase));

        Assert.False(string.IsNullOrWhiteSpace(text));
    }

    [Fact]
    public void DescribeTunnelPhase_PrefersProviderSuppliedDetail()
    {
        var text = ConnectionProgress.DescribeTunnelPhase(
            new TunnelProgress(TunnelPhase.StartingTunnel, "Custom provider detail"));

        Assert.Equal("Custom provider detail", text);
    }
}
