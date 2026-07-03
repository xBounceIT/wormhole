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
    private readonly string _settingsFilePath;

    public AppSettings Current { get; private set; }

    public event EventHandler? SettingsChanged;

    public AppSettingsService()
        : this(AppPaths.GetSettingsFilePath())
    {
    }

    internal AppSettingsService(string settingsFilePath)
    {
        _settingsFilePath = settingsFilePath;
        Current = Load(settingsFilePath, out var migrated);
        if (migrated)
        {
            TryPersistMigratedSettings();
        }
    }

    public void Save()
    {
        Persist(raiseChanged: true);
    }

    private void Persist(bool raiseChanged)
    {
        // Serialize the read of Current + the file write so concurrent callers (e.g. the
        // UI thread toggling a setting and the background update check stamping
        // LastUpdateCheck) cannot collide on File.WriteAllText and surface an IOException.
        lock (_writeLock)
        {
            var directory = Path.GetDirectoryName(_settingsFilePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }
            File.WriteAllBytes(_settingsFilePath, JsonSerializer.SerializeToUtf8Bytes(Current, JsonOptions));
        }
        if (raiseChanged)
        {
            SettingsChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private void TryPersistMigratedSettings()
    {
        try
        {
            Persist(raiseChanged: false);
        }
        catch
        {
            // Loading must remain tolerant of settings-file problems; a failed best-effort
            // migration write should not stop startup with an otherwise usable in-memory default.
        }
    }

    private static AppSettings Load(string path, out bool migrated)
    {
        migrated = false;
        try
        {
            var json = File.ReadAllBytes(path);
            var schemaVersion = ReadSchemaVersion(json);
            var settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            if (schemaVersion < AppSettings.CurrentSchemaVersion)
            {
                if (schemaVersion < 1)
                {
                    settings.PromptBeforeTunnelConnect = true;
                }
                if (schemaVersion < 2 && string.IsNullOrWhiteSpace(settings.BitwardenCliPath))
                {
                    settings.BitwardenCliPath = "bw";
                }
                if (schemaVersion < 3 && string.IsNullOrWhiteSpace(settings.BitwardenBrowserExtensionReleasesUrl))
                {
                    settings.BitwardenBrowserExtensionReleasesUrl = "repos/bitwarden/clients/releases?per_page=20";
                }
                if (schemaVersion < 4)
                {
                    settings.BitwardenBrowserExtensionSource = InferBitwardenBrowserExtensionSource(settings);
                }
                if (schemaVersion < 5 && string.IsNullOrWhiteSpace(settings.BitwardenCliReleasesUrl))
                {
                    settings.BitwardenCliReleasesUrl = "repos/bitwarden/clients/releases?per_page=20";
                }
                if (schemaVersion < AppSettings.BitwardenOnboardingIntroducedSchemaVersion)
                {
                    settings.BitwardenOnboardingNoticePendingVersion = 1;
                }
                settings.SettingsSchemaVersion = AppSettings.CurrentSchemaVersion;
                migrated = true;
            }
            return settings;
        }
        catch (FileNotFoundException)
        {
            return new AppSettings();
        }
        catch (DirectoryNotFoundException)
        {
            return new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    private static BitwardenBrowserExtensionSource InferBitwardenBrowserExtensionSource(AppSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.BitwardenBrowserExtensionPath))
        {
            return BitwardenBrowserExtensionSource.OfficialGitHub;
        }

        if (!string.IsNullOrWhiteSpace(settings.BitwardenBrowserExtensionDownloadUrl))
        {
            return BitwardenBrowserExtensionSource.OfficialGitHub;
        }

        return string.IsNullOrWhiteSpace(settings.BitwardenBrowserExtensionAssetName)
            ? BitwardenBrowserExtensionSource.ManualFolder
            : BitwardenBrowserExtensionSource.ManualZip;
    }

    private static int ReadSchemaVersion(byte[] json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.ValueKind == JsonValueKind.Object &&
            document.RootElement.TryGetProperty(nameof(AppSettings.SettingsSchemaVersion), out var value) &&
            value.TryGetInt32(out var version)
                ? version
                : 0;
    }
}
