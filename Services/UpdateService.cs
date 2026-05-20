using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services;

public sealed class UpdateService : IUpdateService, IDisposable
{
    public const string HttpClientName = "github";
    private const string InstallerArguments = "/SILENT /RESTARTAPP";

    private static readonly Regex GithubUrlPattern = new(
        @"^https?://github\.com/(?<owner>[^/]+)/(?<repo>[^/]+?)(?:\.git)?/?$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IAppSettingsService _settingsService;
    private readonly ILogger<UpdateService> _logger;
    private readonly IInstallerLauncher _installerLauncher;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly CancellationTokenSource _serviceCts = new();

    public UpdateCheckResult? LatestKnown { get; private set; }

    public event EventHandler<UpdateCheckResult>? UpdateAvailable;

    public UpdateService(
        IHttpClientFactory httpClientFactory,
        IAppSettingsService settingsService,
        ILogger<UpdateService> logger,
        IInstallerLauncher installerLauncher)
    {
        _httpClientFactory = httpClientFactory;
        _settingsService = settingsService;
        _logger = logger;
        _installerLauncher = installerLauncher;
        TryCleanupPartialDownloads();
    }

    public async Task<UpdateCheckResult> CheckAsync(CancellationToken cancellationToken = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _serviceCts.Token);
        await _gate.WaitAsync(linkedCts.Token).ConfigureAwait(false);
        try
        {
            var currentVersion = GetCurrentVersion();

            if (!TryResolveRepository(out var owner, out var repo))
            {
                _logger.LogWarning("Repository URL is not configured; skipping update check.");
                return RememberResult(UpdateCheckResult.NoUpdate(currentVersion));
            }

            if (!TryGetTargetArchitecture(out var arch))
            {
                _logger.LogInformation(
                    "OS architecture {Arch} is not a supported update target.",
                    RuntimeInformation.OSArchitecture);
                return RememberResult(UpdateCheckResult.NoUpdate(currentVersion));
            }

            var http = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await http.GetAsync(
                $"repos/{owner}/{repo}/releases/latest",
                HttpCompletionOption.ResponseHeadersRead,
                linkedCts.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "GitHub releases/latest returned {StatusCode} for {Owner}/{Repo}.",
                    (int)response.StatusCode, owner, repo);
                return RememberResult(UpdateCheckResult.Failed(currentVersion));
            }

            // Persist the throttle marker only when GitHub gave us a real answer. Transient
            // 403/5xx or transport failures should not suppress the next startup check.
            _settingsService.Current.LastUpdateCheck = DateTimeOffset.UtcNow;
            _settingsService.Save();

            await using var stream = await response.Content.ReadAsStreamAsync(linkedCts.Token).ConfigureAwait(false);
            var release = await JsonSerializer.DeserializeAsync<GitHubRelease>(stream, JsonOptions, linkedCts.Token).ConfigureAwait(false);

            if (release is null || release.Draft || release.Prerelease)
            {
                _logger.LogInformation("Latest release is missing, draft, or prerelease; treating as no update.");
                return RememberResult(UpdateCheckResult.NoUpdate(currentVersion));
            }

            if (!TryParseTagVersion(release.TagName, out var latestVersion))
            {
                _logger.LogWarning("Unable to parse version from tag '{Tag}'.", release.TagName);
                return RememberResult(UpdateCheckResult.NoUpdate(currentVersion));
            }

            if (latestVersion <= currentVersion)
            {
                return RememberResult(UpdateCheckResult.NoUpdate(currentVersion, latestVersion));
            }

            var asset = FindInstallerAsset(release, arch);
            if (asset is null || string.IsNullOrEmpty(asset.BrowserDownloadUrl))
            {
                _logger.LogWarning(
                    "Release {Tag} has no installer asset matching arch {Arch}; skipping update.",
                    release.TagName, arch);
                return RememberResult(UpdateCheckResult.NoUpdate(currentVersion, latestVersion));
            }

            var sha256 = await TryFetchSha256SidecarAsync(http, release, asset, linkedCts.Token).ConfigureAwait(false);

            var result = new UpdateCheckResult(
                CurrentVersion: currentVersion,
                LatestVersion: latestVersion,
                IsUpdateAvailable: true,
                CheckFailed: false,
                ReleaseTag: release.TagName,
                ReleaseName: release.Name,
                ReleaseUrl: release.HtmlUrl,
                ReleaseNotes: release.Body,
                InstallerUrl: asset.BrowserDownloadUrl,
                InstallerFileName: asset.Name,
                InstallerSize: asset.Size > 0 ? asset.Size : null,
                InstallerSha256: sha256);

            return RememberResult(result);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Update check failed.");
            return RememberResult(UpdateCheckResult.Failed(GetCurrentVersion()));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<string> DownloadInstallerAsync(
        UpdateCheckResult update,
        IProgress<double>? progress,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(update.InstallerUrl) || string.IsNullOrWhiteSpace(update.InstallerFileName))
            throw new InvalidOperationException("Update has no installer asset to download.");

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _serviceCts.Token);
        await _gate.WaitAsync(linkedCts.Token).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(AppPaths.GetUpdateCacheDirectory());
            var finalPath = Path.Combine(AppPaths.GetUpdateCacheDirectory(), update.InstallerFileName);
            var partPath = finalPath + ".part";
            File.Delete(partPath);

            var http = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await http.GetAsync(
                update.InstallerUrl,
                HttpCompletionOption.ResponseHeadersRead,
                linkedCts.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var total = response.Content.Headers.ContentLength ?? update.InstallerSize ?? -1L;
            long downloaded = 0;
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            {
                await using var network = await response.Content.ReadAsStreamAsync(linkedCts.Token).ConfigureAwait(false);
                await using var file = new FileStream(partPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true);
                var buffer = new byte[81920];
                int read;
                while ((read = await network.ReadAsync(buffer, linkedCts.Token).ConfigureAwait(false)) > 0)
                {
                    await file.WriteAsync(buffer.AsMemory(0, read), linkedCts.Token).ConfigureAwait(false);
                    sha.AppendData(buffer, 0, read);
                    downloaded += read;
                    if (total > 0) progress?.Report((double)downloaded / total);
                }
            }

            var computed = Convert.ToHexStringLower(sha.GetHashAndReset());
            if (!string.IsNullOrWhiteSpace(update.InstallerSha256))
            {
                var expected = update.InstallerSha256.Trim().ToLowerInvariant();
                if (!string.Equals(computed, expected, StringComparison.Ordinal))
                {
                    File.Delete(partPath);
                    throw new InvalidDataException(
                        $"SHA-256 mismatch for {update.InstallerFileName}. Expected {expected}, got {computed}.");
                }
            }
            else
            {
                _logger.LogWarning(
                    "No SHA-256 sidecar available for {File}; proceeding without verification (sha={Computed}).",
                    update.InstallerFileName, computed);
            }

            File.Move(partPath, finalPath, overwrite: true);

            StripMarkOfTheWeb(finalPath);
            return finalPath;
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task LaunchInstallerAndExitAsync(string installerPath)
    {
        if (!File.Exists(installerPath))
        {
            _logger.LogError("Installer not found at {Path}; cannot launch.", installerPath);
            return Task.CompletedTask;
        }

        _logger.LogInformation("Launching installer {Path} silently and exiting.", installerPath);
        _installerLauncher.Launch(installerPath, InstallerArguments);
        _installerLauncher.ExitApp();
        return Task.CompletedTask;
    }

    // ---- internal helpers (internal for unit tests) ----

    internal static Version GetCurrentVersion() =>
        typeof(UpdateService).Assembly.GetName().Version ?? new Version(0, 0, 0, 0);

    internal static bool TryParseTagVersion(string? tag, out Version version)
    {
        version = new Version(0, 0, 0, 0);
        if (string.IsNullOrWhiteSpace(tag)) return false;
        var trimmed = tag.Trim();
        if (trimmed.Length > 0 && (trimmed[0] == 'v' || trimmed[0] == 'V'))
            trimmed = trimmed[1..];
        return Version.TryParse(trimmed, out version!);
    }

    internal static bool TryParseRepoUrl(string? url, out string owner, out string repo)
    {
        owner = repo = string.Empty;
        if (string.IsNullOrWhiteSpace(url)) return false;
        var m = GithubUrlPattern.Match(url.Trim());
        if (!m.Success) return false;
        owner = m.Groups["owner"].Value;
        repo = m.Groups["repo"].Value;
        return true;
    }

    internal static bool TryGetTargetArchitecture(out string arch)
    {
        arch = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => string.Empty,
        };
        return !string.IsNullOrEmpty(arch);
    }

    internal static GitHubReleaseAsset? FindInstallerAsset(GitHubRelease release, string arch)
    {
        var suffix = $"-win-{arch}-setup.exe";
        foreach (var asset in release.Assets)
        {
            if (asset.Name is null) continue;
            if (asset.Name.StartsWith("Wormhole-", StringComparison.OrdinalIgnoreCase)
                && asset.Name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return asset;
        }
        return null;
    }

    internal static string? ParseShaSidecar(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var first = raw.Split('\n', '\r').FirstOrDefault(s => !string.IsNullOrWhiteSpace(s))?.Trim();
        if (string.IsNullOrEmpty(first)) return null;
        var token = first.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries)[0];
        return token.Length == 64 && token.All(IsHexChar) ? token.ToLowerInvariant() : null;
    }

    private static bool TryResolveRepository(out string owner, out string repo)
    {
        var attr = typeof(UpdateService).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "RepositoryUrl");
        return TryParseRepoUrl(attr?.Value, out owner, out repo);
    }

    private async Task<string?> TryFetchSha256SidecarAsync(
        HttpClient http,
        GitHubRelease release,
        GitHubReleaseAsset installerAsset,
        CancellationToken ct)
    {
        var sidecarName = installerAsset.Name + ".sha256";
        var sidecar = release.Assets.FirstOrDefault(a =>
            string.Equals(a.Name, sidecarName, StringComparison.OrdinalIgnoreCase));
        if (sidecar?.BrowserDownloadUrl is null) return null;
        try
        {
            using var response = await http.GetAsync(sidecar.BrowserDownloadUrl, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return null;
            var raw = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return ParseShaSidecar(raw);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to fetch SHA-256 sidecar {Url}.", sidecar.BrowserDownloadUrl);
            return null;
        }
    }

    private static bool IsHexChar(char c) =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

    private void StripMarkOfTheWeb(string path)
    {
        try { File.Delete(path + ":Zone.Identifier"); }
        catch (FileNotFoundException) { }
        catch (Exception ex) { _logger.LogDebug(ex, "Could not strip MOTW from {Path}.", path); }
    }

    private void TryCleanupPartialDownloads()
    {
        try
        {
            var dir = AppPaths.GetUpdateCacheDirectory();
            if (!Directory.Exists(dir)) return;
            var cutoff = DateTime.UtcNow - TimeSpan.FromHours(24);
            foreach (var file in Directory.EnumerateFiles(dir, "*.part"))
            {
                if (File.GetLastWriteTimeUtc(file) < cutoff)
                {
                    try { File.Delete(file); }
                    catch (Exception ex) { _logger.LogDebug(ex, "Failed to clean partial {File}.", file); }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Update cache cleanup failed.");
        }
    }

    private UpdateCheckResult RememberResult(UpdateCheckResult result)
    {
        LatestKnown = result;
        if (result.IsUpdateAvailable)
        {
            try { UpdateAvailable?.Invoke(this, result); }
            catch (Exception ex) { _logger.LogWarning(ex, "UpdateAvailable handler threw."); }
        }
        return result;
    }

    public void Dispose()
    {
        try { _serviceCts.Cancel(); } catch { }
        _serviceCts.Dispose();
        _gate.Dispose();
    }
}

public sealed class DefaultInstallerLauncher : IInstallerLauncher
{
    private readonly ILogger<DefaultInstallerLauncher> _logger;

    public DefaultInstallerLauncher(ILogger<DefaultInstallerLauncher> logger)
    {
        _logger = logger;
    }

    public void Launch(string installerPath, string arguments)
    {
        var info = new System.Diagnostics.ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = arguments,
            UseShellExecute = true,
        };
        try
        {
            System.Diagnostics.Process.Start(info);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to launch installer {Path}.", installerPath);
            throw;
        }
    }

    public void ExitApp()
    {
        Environment.Exit(0);
    }
}
