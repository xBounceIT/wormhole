using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Models;

namespace Wormhole.ViewModels.Sessions;

/// <summary>Visual state of a single step in the connecting stepper.</summary>
public enum ConnectionStepState
{
    /// <summary>Not started yet — shows a muted number.</summary>
    Pending,

    /// <summary>Currently running — shows a spinner.</summary>
    Active,

    /// <summary>Finished successfully — shows a check mark.</summary>
    Completed,

    /// <summary>The connection failed while this step was active — shows an error glyph.</summary>
    Failed,
}

/// <summary>
/// The well-known ordered phases a tunneled connection passes through. Kept abstract from any one
/// protocol so both <see cref="SshSessionViewModel"/> and <see cref="RdpSessionViewModel"/> drive
/// the same stepper.
/// </summary>
public enum ConnectionPhase
{
    /// <summary>Resolving the credentials needed for the connection.</summary>
    Credentials,

    /// <summary>Bringing up the per-connection VPN tunnel and routing through it.</summary>
    Tunnel,

    /// <summary>The protocol handshake to the target host.</summary>
    Connect,
}

/// <summary>One numbered step in the connecting stepper.</summary>
public sealed partial class ConnectionStep : ObservableObject
{
    public ConnectionStep(ConnectionPhase phase, int number, string label, bool isLast)
    {
        Phase = phase;
        Number = number;
        Label = label;
        IsLast = isLast;
    }

    public ConnectionPhase Phase { get; }

    /// <summary>1-based position shown inside the step's circle while pending.</summary>
    public int Number { get; }

    /// <summary>String form of <see cref="Number"/> for binding to <c>TextBlock.Text</c> (x:Bind does not implicitly stringify an int).</summary>
    public string NumberText => Number.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public string Label { get; }

    /// <summary>True for the final step, so the trailing connector line is hidden.</summary>
    public bool IsLast { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsPending))]
    [NotifyPropertyChangedFor(nameof(IsActive))]
    [NotifyPropertyChangedFor(nameof(IsCompleted))]
    [NotifyPropertyChangedFor(nameof(IsFailed))]
    private ConnectionStepState state;

    public bool IsPending => State == ConnectionStepState.Pending;
    public bool IsActive => State == ConnectionStepState.Active;
    public bool IsCompleted => State == ConnectionStepState.Completed;
    public bool IsFailed => State == ConnectionStepState.Failed;
}

/// <summary>
/// Drives the numbered, phased progress stepper shown in the connecting overlay for tunneled
/// connections. The session view-models build the step list at connect time and walk it phase by
/// phase (<see cref="Begin"/>), while the live tunnel sub-status flows into <see cref="Detail"/>.
/// All mutation happens on the UI thread (the session connect path, and tunnel-progress callbacks
/// marshalled there via <see cref="SessionTabViewModel"/>).
/// </summary>
public sealed partial class ConnectionProgress : ObservableObject
{
    public ObservableCollection<ConnectionStep> Steps { get; } = new();

    /// <summary>True when there are steps to show — the overlay shows the stepper, else a plain spinner.</summary>
    [ObservableProperty]
    private bool isActive;

    /// <summary>
    /// True once <see cref="Fail"/> has marked a step failed. The failure overlay shows the stepper
    /// only in this case, so it pinpoints which numbered phase broke — while a post-connect drop
    /// (all steps already Completed) or a direct connection (no steps) keeps the plain error view.
    /// </summary>
    [ObservableProperty]
    private bool hasFailedStep;

    /// <summary>Live sub-status for the active step (currently only the VPN-tunnel phase populates it).</summary>
    [ObservableProperty]
    private string? detail;

    /// <summary>Clear all steps and detail — returns the overlay to its plain-spinner state.</summary>
    public void Reset()
    {
        Steps.Clear();
        Detail = null;
        IsActive = false;
        HasFailedStep = false;
    }

    /// <summary>
    /// Replace the step list with the given ordered phases (each step starts <see
    /// cref="ConnectionStepState.Pending"/>). Numbering is 1-based in declaration order.
    /// </summary>
    public void Initialize(IReadOnlyList<(ConnectionPhase Phase, string Label)> steps)
    {
        Steps.Clear();
        Detail = null;
        HasFailedStep = false;
        for (var i = 0; i < steps.Count; i++)
        {
            Steps.Add(new ConnectionStep(steps[i].Phase, i + 1, steps[i].Label, isLast: i == steps.Count - 1)
            {
                State = ConnectionStepState.Pending,
            });
        }
        IsActive = Steps.Count > 0;
    }

    /// <summary>
    /// Mark <paramref name="phase"/> as the active step: every step before it becomes
    /// <see cref="ConnectionStepState.Completed"/>, this one becomes
    /// <see cref="ConnectionStepState.Active"/>, later steps are left as-is. Clears the stale
    /// <see cref="Detail"/> from the previous step. A no-op when the phase isn't in the list
    /// (e.g. a direct, non-tunneled connection with no steps).
    /// </summary>
    public void Begin(ConnectionPhase phase)
    {
        var reached = false;
        foreach (var step in Steps)
        {
            if (step.Phase == phase)
            {
                step.State = ConnectionStepState.Active;
                reached = true;
            }
            else if (!reached && step.State != ConnectionStepState.Failed)
            {
                step.State = ConnectionStepState.Completed;
            }
        }

        if (reached) Detail = null;
    }

    /// <summary>Mark every non-failed step <see cref="ConnectionStepState.Completed"/> (connection succeeded).</summary>
    public void CompleteAll()
    {
        foreach (var step in Steps)
        {
            if (step.State != ConnectionStepState.Failed)
            {
                step.State = ConnectionStepState.Completed;
            }
        }
        Detail = null;
        HasFailedStep = false;
    }

    /// <summary>
    /// Mark the currently-active step as failed (the connection errored mid-step). Sets
    /// <see cref="HasFailedStep"/> so the failure overlay surfaces the stepper. A no-op when no step
    /// is active (e.g. a drop after the connection had already fully completed), which deliberately
    /// leaves <see cref="HasFailedStep"/> false so the plain error view is shown instead.
    /// </summary>
    public void Fail()
    {
        var failedAny = false;
        foreach (var step in Steps)
        {
            if (step.State == ConnectionStepState.Active)
            {
                step.State = ConnectionStepState.Failed;
                failedAny = true;
            }
        }
        if (failedAny)
        {
            // Drop the live sub-status: its progressive wording ("Bringing up the VPN tunnel…")
            // would read as still-in-progress under a failed step. The error message carries the why.
            Detail = null;
            HasFailedStep = true;
        }
    }

    /// <summary>
    /// Map a <see cref="TunnelProgress"/> report to the human-readable line shown beneath the
    /// "VPN tunnel" step. A provider-supplied <see cref="TunnelProgress.Detail"/> wins; otherwise a
    /// sensible default per phase is used.
    /// </summary>
    public static string DescribeTunnelPhase(TunnelProgress progress)
    {
        if (!string.IsNullOrWhiteSpace(progress.Detail)) return progress.Detail!;
        return progress.Phase switch
        {
            TunnelPhase.Preparing => "Preparing VPN configuration…",
            TunnelPhase.Authenticating => "Authenticating with the VPN gateway…",
            TunnelPhase.DownloadingConfiguration => "Downloading VPN configuration…",
            TunnelPhase.StartingTunnel => "Bringing up the VPN tunnel…",
            _ => "Establishing the VPN tunnel…",
        };
    }
}
