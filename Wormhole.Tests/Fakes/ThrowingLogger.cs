using Microsoft.Extensions.Logging;

namespace Wormhole.Tests.Fakes;

internal class ThrowingLogger : ILogger
{
    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull =>
        throw new InvalidOperationException("simulated logging provider failure");

    public bool IsEnabled(LogLevel logLevel) =>
        throw new InvalidOperationException("simulated logging provider failure");

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter) =>
        throw new InvalidOperationException("simulated logging provider failure");
}

internal sealed class ThrowingLogger<T> : ThrowingLogger, ILogger<T>
{
}

internal sealed class ThrowingLoggerFactory : ILoggerFactory
{
    public void AddProvider(ILoggerProvider provider)
    {
    }

    public ILogger CreateLogger(string categoryName) => new ThrowingLogger();

    public void Dispose()
    {
    }
}
