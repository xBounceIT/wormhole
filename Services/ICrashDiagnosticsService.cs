namespace Wormhole.Services;

internal interface ICrashDiagnosticsService
{
    void Initialize();
    void LogStartupContext();
    void LogNewCrashDumps();
}
