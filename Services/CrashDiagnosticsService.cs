using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;

namespace Wormhole.Services;

internal sealed class CrashDiagnosticsService : ICrashDiagnosticsService
{
    private const string ReportStateFileName = "crashdumps-reported.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
    };

    private readonly ILogger<CrashDiagnosticsService> _logger;
    private readonly string _dumpDirectory;
    private readonly string _statePath;

    public CrashDiagnosticsService(ILogger<CrashDiagnosticsService> logger)
        : this(
            logger,
            AppPaths.GetCrashDumpsDirectory(),
            Path.Combine(AppPaths.GetAppDataDirectory(), ReportStateFileName))
    {
    }

    internal CrashDiagnosticsService(
        ILogger<CrashDiagnosticsService> logger,
        string dumpDirectory,
        string statePath)
    {
        _logger = logger;
        _dumpDirectory = dumpDirectory;
        _statePath = statePath;
    }

    public void Initialize()
    {
        try
        {
            Directory.CreateDirectory(_dumpDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Could not create crash dump directory {CrashDumpDirectory}.", _dumpDirectory);
        }
    }

    public void LogStartupContext()
    {
        var assembly = typeof(CrashDiagnosticsService).Assembly;
        var assemblyName = assembly.GetName();
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        _logger.LogInformation(
            "Wormhole starting: version={Version}, assemblyVersion={AssemblyVersion}, os={OS}, processArchitecture={ProcessArchitecture}, framework={Framework}, processId={ProcessId}, baseDirectory={BaseDirectory}, crashDumpDirectory={CrashDumpDirectory}.",
            informationalVersion ?? assemblyName.Version?.ToString() ?? "unknown",
            assemblyName.Version?.ToString() ?? "unknown",
            RuntimeInformation.OSDescription,
            RuntimeInformation.ProcessArchitecture,
            RuntimeInformation.FrameworkDescription,
            Environment.ProcessId,
            AppContext.BaseDirectory,
            _dumpDirectory);
    }

    public void LogNewCrashDumps()
    {
        try
        {
            Directory.CreateDirectory(_dumpDirectory);
            var reported = LoadReportedDumpKeys();
            var changed = false;

            foreach (var dump in EnumerateDumpFiles())
            {
                var key = GetDumpKey(dump);
                if (!reported.Add(key)) continue;

                _logger.LogCritical(
                    "Crash dump found from a previous Wormhole crash: {DumpPath} (createdUtc={CreatedUtc:o}, lastWriteUtc={LastWriteUtc:o}, sizeBytes={SizeBytes}).",
                    dump.FullName,
                    dump.CreationTimeUtc,
                    dump.LastWriteTimeUtc,
                    dump.Length);
                changed = true;
            }

            if (changed)
            {
                SaveReportedDumpKeys(reported);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            _logger.LogWarning(ex, "Could not scan crash dump directory {CrashDumpDirectory}.", _dumpDirectory);
        }
    }

    private List<FileInfo> EnumerateDumpFiles()
    {
        var dumps = new List<FileInfo>();
        foreach (var path in Directory.EnumerateFiles(_dumpDirectory, "*.dmp", SearchOption.TopDirectoryOnly))
        {
            var info = new FileInfo(path);
            if (info.Exists)
            {
                dumps.Add(info);
            }
        }

        dumps.Sort(static (left, right) =>
        {
            var byTime = left.LastWriteTimeUtc.CompareTo(right.LastWriteTimeUtc);
            return byTime != 0
                ? byTime
                : string.Compare(left.FullName, right.FullName, StringComparison.OrdinalIgnoreCase);
        });
        return dumps;
    }

    private HashSet<string> LoadReportedDumpKeys()
    {
        if (!File.Exists(_statePath))
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        try
        {
            var json = File.ReadAllText(_statePath);
            var state = JsonSerializer.Deserialize<CrashDumpReportState>(json, JsonOptions);
            return new HashSet<string>(
                state?.ReportedDumpKeys ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            _logger.LogWarning(ex, "Could not read crash dump report state {StatePath}; existing dumps may be reported again.", _statePath);
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private void SaveReportedDumpKeys(HashSet<string> reported)
    {
        var state = new CrashDumpReportState
        {
            ReportedDumpKeys = reported.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
        };

        var dir = Path.GetDirectoryName(_statePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var tmp = _statePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(state, JsonOptions));
        File.Move(tmp, _statePath, overwrite: true);
    }

    private static string GetDumpKey(FileInfo dump) =>
        string.Join('|', dump.FullName, dump.LastWriteTimeUtc.Ticks, dump.Length);

    private sealed class CrashDumpReportState
    {
        public string[] ReportedDumpKeys { get; set; } = Array.Empty<string>();
    }
}
