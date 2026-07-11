using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Wormhole.Helpers;

/// <summary>
/// Keeps diagnostics strictly observational on terminal runtime paths. A broken logging
/// provider must never suppress transport shutdown, recovery, input, or later subscribers.
/// </summary>
internal class NonThrowingLogger : ILogger
{
    private readonly ILogger _inner;

    public NonThrowingLogger(ILogger inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull
    {
        try
        {
            return _inner.BeginScope(state) ?? EmptyScope.Instance;
        }
        catch
        {
            return EmptyScope.Instance;
        }
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        try
        {
            return _inner.IsEnabled(logLevel);
        }
        catch
        {
            return false;
        }
    }

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        try
        {
            _inner.Log(logLevel, eventId, state, exception, formatter);
        }
        catch
        {
            // Diagnostics are best-effort on terminal lifecycle paths.
        }
    }

    private sealed class EmptyScope : IDisposable
    {
        public static EmptyScope Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}

internal sealed class NonThrowingLogger<T> : NonThrowingLogger, ILogger<T>
{
    public NonThrowingLogger(ILogger<T> inner)
        : base(inner)
    {
    }
}

/// <summary>
/// Produces non-throwing loggers without taking ownership of the injected application factory.
/// </summary>
internal sealed class NonThrowingLoggerFactory : ILoggerFactory
{
    private readonly ILoggerFactory _inner;

    public NonThrowingLoggerFactory(ILoggerFactory inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public void AddProvider(ILoggerProvider provider)
    {
        try
        {
            _inner.AddProvider(provider);
        }
        catch
        {
            // Provider registration is diagnostics-only for this borrowed wrapper.
        }
    }

    public ILogger CreateLogger(string categoryName)
    {
        try
        {
            return new NonThrowingLogger(_inner.CreateLogger(categoryName));
        }
        catch
        {
            return NullLogger.Instance;
        }
    }

    public void Dispose()
    {
        // The application owns the injected factory; this wrapper must not dispose it.
    }
}
