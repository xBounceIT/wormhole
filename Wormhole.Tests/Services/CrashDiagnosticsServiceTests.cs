using Microsoft.Extensions.Logging;
using Wormhole.Services;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class CrashDiagnosticsServiceTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "wormhole-crashdiag-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public void Initialize_CreatesCrashDumpDirectory()
    {
        var dumpDir = Path.Combine(_root, "crashdumps");
        var service = CreateService(dumpDir, Path.Combine(_root, "reported.json"));

        service.Initialize();

        Assert.True(Directory.Exists(dumpDir));
    }

    [Fact]
    public void LogNewCrashDumps_ReportsEachDumpOnce()
    {
        var dumpDir = Path.Combine(_root, "crashdumps");
        Directory.CreateDirectory(dumpDir);
        var statePath = Path.Combine(_root, "reported.json");
        var logger = new RecordingLogger<CrashDiagnosticsService>();
        var service = new CrashDiagnosticsService(logger, dumpDir, statePath);
        var dumpPath = Path.Combine(dumpDir, "Wormhole.exe.1234.dmp");
        File.WriteAllBytes(dumpPath, new byte[] { 1, 2, 3 });

        service.LogNewCrashDumps();
        service.LogNewCrashDumps();

        var reports = logger.Entries
            .Where(e => e.Level == LogLevel.Critical &&
                        e.Message.Contains("Crash dump found", StringComparison.Ordinal))
            .ToList();
        Assert.Single(reports);
        Assert.Contains(dumpPath, reports.Single().Message);
        Assert.True(File.Exists(statePath));
    }

    private static CrashDiagnosticsService CreateService(string dumpDir, string statePath) =>
        new(new RecordingLogger<CrashDiagnosticsService>(), dumpDir, statePath);

    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception), exception));
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        public void Dispose()
        {
        }
    }
}
