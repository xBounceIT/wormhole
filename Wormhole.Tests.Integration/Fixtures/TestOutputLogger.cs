using System;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace Wormhole.Tests.Integration.Fixtures;

/// <summary>
/// Pipes ILogger output to xUnit's ITestOutputHelper so the sidecar's stderr
/// (which {WireGuard,OpenVpn}ProcessHost stream via LogInformation) appears in
/// the .trx file and in the `--logger console` test output. Without this the
/// tests fall back to NullLogger.Instance and the only failure surface on CI
/// is "sidecar exited before becoming ready" with no clue *why*.
/// </summary>
internal sealed class TestOutputLogger : ILogger
{
    private readonly ITestOutputHelper _output;
    private readonly ConcurrentQueue<string> _lines = new();

    public TestOutputLogger(ITestOutputHelper output) => _output = output;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public string[] Lines => _lines.ToArray();

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var message = formatter(state, exception);
        _lines.Enqueue(message);

        // try/catch because ITestOutputHelper throws if called after the test
        // method returned (the stderr pump task can outlive the test on a slow
        // teardown). Better to swallow than break test reporting.
        try
        {
            _output.WriteLine($"[{logLevel}] {message}");
            if (exception is not null)
                _output.WriteLine(exception.ToString());
        }
        catch
        {
            /* test scope already ended — drop the line */
        }
    }
}
