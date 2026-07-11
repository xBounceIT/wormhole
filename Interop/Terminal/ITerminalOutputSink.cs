namespace Wormhole.Interop.Terminal;

internal readonly record struct TerminalOutputRetirement(
    byte[] UnpostedOutput,
    bool HadUnacknowledgedOutput,
    bool HadUncertainGeometry = false)
{
    public static TerminalOutputRetirement Empty =>
        new(
            Array.Empty<byte>(),
            HadUnacknowledgedOutput: false,
            HadUncertainGeometry: false);
}

/// <summary>
/// Minimal terminal-output surface owned by a session view model. Keeping this boundary separate
/// from WebView2 makes output-routing synchronization testable without constructing a UI control.
/// </summary>
internal interface ITerminalOutputSink : IDisposable
{
    bool TryAppendOutput(ReadOnlyMemory<byte> data);
    void Replay(ReadOnlyMemory<byte> data, bool suppressTerminalResponses);
    Task<bool> FlushOutputAsync(TimeSpan timeout, CancellationToken cancellationToken = default);
    Task RequestFocusAsync();

    /// <summary>
    /// Stops accepting new output, keeps the input/ACK listener alive while already accepted
    /// frames finish parsing, then disposes the sink and returns any bytes still unposted.
    /// </summary>
    Task<TerminalOutputRetirement> RetireAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(DisposeAndTakePendingOutput());
    }

    TerminalOutputRetirement DisposeAndTakePendingOutput();
}
