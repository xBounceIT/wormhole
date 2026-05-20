using System;
using System.IO;
using System.Text.Json;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services;

public sealed class AppSettingsService : IAppSettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    private readonly object _writeLock = new();

    public AppSettings Current { get; private set; }

    public event EventHandler? SettingsChanged;

    public AppSettingsService()
    {
        Current = Load();
    }

    public void Save()
    {
        // Serialize the read of Current + the file write so concurrent callers (e.g. the
        // UI thread toggling a setting and the background update check stamping
        // LastUpdateCheck) cannot collide on File.WriteAllText and surface an IOException.
        lock (_writeLock)
        {
            Directory.CreateDirectory(AppPaths.GetAppDataDirectory());
            File.WriteAllText(AppPaths.GetSettingsFilePath(), JsonSerializer.Serialize(Current, JsonOptions));
        }
        SettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    private static AppSettings Load()
    {
        var path = AppPaths.GetSettingsFilePath();
        if (!File.Exists(path)) return new AppSettings();
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }
}
