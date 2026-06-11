using System;
using Wormhole.Models;

namespace Wormhole.Tests.Fakes;

/// <summary>An <see cref="IProgress{T}"/> over <see cref="TunnelProgress"/> that synchronously
/// forwards each report to a callback, for asserting tunnel progress sequences.</summary>
public sealed class RecordingProgress : IProgress<TunnelProgress>
{
    private readonly Action<TunnelProgress> _onReport;
    public RecordingProgress(Action<TunnelProgress> onReport) => _onReport = onReport;
    public void Report(TunnelProgress value) => _onReport(value);
}
