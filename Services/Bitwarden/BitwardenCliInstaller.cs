using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.Bitwarden;

public sealed class BitwardenCliInstaller : IBitwardenCliInstaller, IDisposable
{
    public const string ReleaseHttpClientName = "bitwarden-cli-release";
    public const string DownloadHttpClientName = "bitwarden-cli-download";

    private const int DownloadBufferSize = 81920;
    private const string DefaultReleasesPath = "repos/bitwarden/clients/releases?per_page=20";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<BitwardenCliInstaller> _logger;
    private readonly string _installRoot;
    private readonly string _downloadRoot;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public BitwardenCliInstaller(
        IHttpClientFactory httpClientFactory,
        IAppSettingsService settings,
        ILogger<BitwardenCliInstaller> logger)
        : this(
            httpClientFactory,
            settings,
            logger,
            AppPaths.GetBitwardenCliRootDirectory(),
            AppPaths.GetBitwardenCliDownloadDirectory())
    {
    }

    internal BitwardenCliInstaller(
        IHttpClientFactory httpClientFactory,
        IAppSettingsService settings,
        ILogger<BitwardenCliInstaller> logger,
        string installRoot,
        string downloadRoot)
    {
        _httpClientFactory = httpClientFactory;
        _settings = settings;
        _logger = logger;
        _installRoot = installRoot;
        _downloadRoot = downloadRoot;
    }

    public BitwardenCliInstall? GetConfiguredInstall()
    {
        var path = ResolveExecutablePath(_settings.Current.BitwardenCliPath);
        if (path is null) return null;

        return new BitwardenCliInstall(
            string.IsNullOrWhiteSpace(_settings.Current.BitwardenCliDownloadUrl)
                ? "external"
                : string.IsNullOrWhiteSpace(_settings.Current.BitwardenCliVersion) ? "official" : _settings.Current.BitwardenCliVersion!,
            path,
            _settings.Current.BitwardenCliSha256,
            _settings.Current.BitwardenCliAssetName,
            _settings.Current.BitwardenCliDownloadUrl);
    }

    public async Task<BitwardenCliInstall> EnsureInstalledAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (GetConfiguredInstall() is { } existing) return existing;
            return await InstallLatestCoreAsync(progress, cancellationToken).ConfigureAwait(false);
        }
        catch (BitwardenCliInstallException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new BitwardenCliInstallException("Could not install the Bitwarden CLI.", ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<BitwardenCliInstall> InstallLatestAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await InstallLatestCoreAsync(progress, cancellationToken).ConfigureAwait(false);
        }
        catch (BitwardenCliInstallException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new BitwardenCliInstallException("Could not install the Bitwarden CLI.", ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    private async Task<BitwardenCliInstall> InstallLatestCoreAsync(
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        progress?.Report("Checking Bitwarden CLI releases...");
        var latest = await ResolveLatestReleaseAsync(cancellationToken).ConfigureAwait(false);
        progress?.Report("Downloading Bitwarden CLI...");
        return await InstallReleaseAssetAsync(
            latest.Version,
            latest.Asset.Name!,
            latest.Asset.BrowserDownloadUrl!,
            latest.ExpectedSha256,
            progress,
            cancellationToken).ConfigureAwait(false);
    }

    internal static bool IsCliRelease(GitHubRelease release) =>
        !release.Draft
        && !release.Prerelease
        && release.TagName?.StartsWith("cli-v", StringComparison.OrdinalIgnoreCase) == true;

    internal static GitHubReleaseAsset? FindWindowsAsset(GitHubRelease release) =>
        release.Assets.FirstOrDefault(asset =>
            !string.IsNullOrWhiteSpace(asset.Name)
            && !string.IsNullOrWhiteSpace(asset.BrowserDownloadUrl)
            && asset.Name.StartsWith("bw-windows-", StringComparison.OrdinalIgnoreCase)
            && asset.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase));

    internal static string? ParseCliVersion(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var text = value.Trim();
        var marker = text.IndexOf("cli-v", StringComparison.OrdinalIgnoreCase);
        if (marker >= 0) text = text[(marker + "cli-v".Length)..];
        if (text.StartsWith("bw-windows-", StringComparison.OrdinalIgnoreCase)) text = text["bw-windows-".Length..];
        if (text.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) text = text[..^4];
        return string.IsNullOrWhiteSpace(text) ? null : SanitizeVersion(text);
    }

    internal static string? ParseGitHubSha256(string? digest)
    {
        if (string.IsNullOrWhiteSpace(digest)) return null;
        const string prefix = "sha256:";
        var value = digest.Trim();
        if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) value = value[prefix.Length..];
        return value.Length == 64 && value.All(Uri.IsHexDigit) ? value.ToLowerInvariant() : null;
    }

    internal static string? ResolveExecutablePath(string? configuredPath)
    {
        var path = string.IsNullOrWhiteSpace(configuredPath) ? "bw" : configuredPath.Trim();
        if (Path.IsPathRooted(path) || path.Contains(Path.DirectorySeparatorChar) || path.Contains(Path.AltDirectorySeparatorChar))
        {
            return File.Exists(path) ? Path.GetFullPath(path) : null;
        }

        var candidates = path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? new[] { path }
            : new[] { path, path + ".exe" };
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var candidate in candidates)
            {
                try
                {
                    var fullPath = Path.Combine(directory, candidate);
                    if (File.Exists(fullPath)) return Path.GetFullPath(fullPath);
                }
                catch
                {
                    // Ignore malformed PATH entries.
                }
            }
        }

        return null;
    }

    private async Task<ResolvedCliRelease> ResolveLatestReleaseAsync(CancellationToken cancellationToken)
    {
        var releaseClient = _httpClientFactory.CreateClient(ReleaseHttpClientName);
        var releasesPath = string.IsNullOrWhiteSpace(_settings.Current.BitwardenCliReleasesUrl)
            ? DefaultReleasesPath
            : _settings.Current.BitwardenCliReleasesUrl.Trim();

        using var response = await releaseClient.GetAsync(
            releasesPath,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var releaseStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var releases = await JsonSerializer.DeserializeAsync<List<GitHubRelease>>(
            releaseStream,
            JsonOptions,
            cancellationToken).ConfigureAwait(false) ?? new List<GitHubRelease>();

        var release = releases.FirstOrDefault(IsCliRelease)
            ?? throw new BitwardenCliInstallException("No Bitwarden CLI release was found.");
        var asset = FindWindowsAsset(release)
            ?? throw new BitwardenCliInstallException("The latest Bitwarden CLI release has no Windows ZIP asset.");
        if (string.IsNullOrWhiteSpace(asset.BrowserDownloadUrl))
            throw new BitwardenCliInstallException("The Bitwarden CLI asset has no download URL.");

        var version = ParseCliVersion(release.TagName) ?? ParseCliVersion(asset.Name) ?? "latest";
        return new ResolvedCliRelease(version, asset, ParseGitHubSha256(asset.Digest));
    }

    private async Task<BitwardenCliInstall> InstallReleaseAssetAsync(
        string version,
        string assetName,
        string downloadUrl,
        string? expectedSha256,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_downloadRoot);
        var zipPath = Path.Combine(_downloadRoot, $"bitwarden-cli-{version}-{Guid.NewGuid():N}.zip");
        try
        {
            var actualSha256 = await DownloadAsync(downloadUrl, zipPath, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(expectedSha256)
                && !string.Equals(expectedSha256, actualSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new BitwardenCliInstallException("The downloaded Bitwarden CLI checksum does not match the GitHub release metadata.");
            }

            progress?.Report("Installing Bitwarden CLI...");
            return InstallZipFile(zipPath, version, actualSha256, assetName, downloadUrl, cancellationToken);
        }
        finally
        {
            TryDeleteFile(zipPath);
        }
    }

    private BitwardenCliInstall InstallZipFile(
        string zipPath,
        string version,
        string sha256,
        string assetName,
        string downloadUrl,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_installRoot);
        var staging = Path.Combine(_installRoot, ".staging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);

        try
        {
            ExtractZipSafely(zipPath, staging);
            cancellationToken.ThrowIfCancellationRequested();

            var executable = FindBwExecutable(staging);
            var finalPath = GetUniqueInstallPath(SanitizeVersion(version));
            Directory.CreateDirectory(finalPath);
            var finalExecutable = Path.Combine(finalPath, "bw.exe");
            File.Copy(executable, finalExecutable, overwrite: false);
            TryDeleteDirectory(staging);
            return PersistInstall(version, finalExecutable, sha256, assetName, downloadUrl);
        }
        catch
        {
            TryDeleteDirectory(staging);
            throw;
        }
    }

    private BitwardenCliInstall PersistInstall(
        string version,
        string executablePath,
        string sha256,
        string assetName,
        string downloadUrl)
    {
        _settings.Current.BitwardenCliPath = executablePath;
        _settings.Current.BitwardenCliVersion = version;
        _settings.Current.BitwardenCliSha256 = sha256;
        _settings.Current.BitwardenCliAssetName = assetName;
        _settings.Current.BitwardenCliDownloadUrl = downloadUrl;
        _settings.Current.BitwardenCliInstallStatus = $"Installed official Bitwarden CLI {version}.";
        _settings.Current.BitwardenCliInstallError = null;
        _settings.Save();
        return new BitwardenCliInstall(version, executablePath, sha256, assetName, downloadUrl);
    }

    private string GetUniqueInstallPath(string version)
    {
        var basePath = Path.Combine(_installRoot, version);
        if (!Directory.Exists(basePath)) return basePath;

        for (var i = 2; i < 1000; i++)
        {
            var candidate = basePath + "-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (!Directory.Exists(candidate)) return candidate;
        }

        return basePath + "-" + Guid.NewGuid().ToString("N");
    }

    private async Task<string> DownloadAsync(string downloadUrl, string outputPath, CancellationToken cancellationToken)
    {
        var downloadClient = _httpClientFactory.CreateClient(DownloadHttpClientName);
        using var response = await downloadClient.GetAsync(
            downloadUrl,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var network = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var file = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, DownloadBufferSize, useAsync: true);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[DownloadBufferSize];
        int read;
        while ((read = await network.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
        {
            await file.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            sha.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    private static void ExtractZipSafely(string zipPath, string destinationRoot)
    {
        var fullRoot = Path.GetFullPath(destinationRoot);
        var fullRootWithSeparator = fullRoot.EndsWith(Path.DirectorySeparatorChar)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;

        using var archive = ZipFile.OpenRead(zipPath);
        foreach (var entry in archive.Entries)
        {
            var destinationPath = Path.GetFullPath(Path.Combine(fullRoot, entry.FullName));
            if (!destinationPath.StartsWith(fullRootWithSeparator, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(destinationPath, fullRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new BitwardenCliInstallException("The Bitwarden CLI ZIP contains an unsafe path.");
            }

            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(destinationPath);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            entry.ExtractToFile(destinationPath, overwrite: false);
        }
    }

    private static string FindBwExecutable(string root)
    {
        var matches = Directory.GetFiles(root, "bw.exe", SearchOption.AllDirectories);
        if (matches.Length == 0)
            throw new BitwardenCliInstallException("The Bitwarden CLI ZIP does not contain bw.exe.");
        return matches[0];
    }

    private static string SanitizeVersion(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value.Trim())
        {
            builder.Append(char.IsLetterOrDigit(ch) || ch is '.' or '-' or '_' ? ch : '-');
        }
        return builder.Length == 0 ? "latest" : builder.ToString();
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { }
    }

    private static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
        catch { }
    }

    private sealed record ResolvedCliRelease(string Version, GitHubReleaseAsset Asset, string? ExpectedSha256);
}
