using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;

namespace Wormhole.Services.BitwardenBrowser;

public sealed class BitwardenBrowserExtensionInstaller : IBitwardenBrowserExtensionInstaller, IDisposable
{
    public const string ReleaseHttpClientName = "bitwarden-browser-release";
    public const string DownloadHttpClientName = "bitwarden-browser-download";

    private const int DownloadBufferSize = 81920;
    private const string DefaultReleasesPath = "repos/bitwarden/clients/releases?per_page=20";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<BitwardenBrowserExtensionInstaller> _logger;
    private readonly string _installRoot;
    private readonly string _downloadRoot;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public BitwardenBrowserExtensionInstaller(
        IHttpClientFactory httpClientFactory,
        IAppSettingsService settings,
        ILogger<BitwardenBrowserExtensionInstaller> logger)
        : this(
            httpClientFactory,
            settings,
            logger,
            AppPaths.GetBitwardenBrowserExtensionRootDirectory(),
            AppPaths.GetBitwardenBrowserExtensionDownloadDirectory())
    {
    }

    internal BitwardenBrowserExtensionInstaller(
        IHttpClientFactory httpClientFactory,
        IAppSettingsService settings,
        ILogger<BitwardenBrowserExtensionInstaller> logger,
        string installRoot,
        string downloadRoot)
    {
        _httpClientFactory = httpClientFactory;
        _settings = settings;
        _logger = logger;
        _installRoot = installRoot;
        _downloadRoot = downloadRoot;
    }

    public BitwardenBrowserExtensionInstall? GetConfiguredInstall()
    {
        var path = _settings.Current.BitwardenBrowserExtensionPath;
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path)) return null;

        try
        {
            var manifest = BitwardenBrowserExtensionManifest.Read(path);
            var version = string.IsNullOrWhiteSpace(_settings.Current.BitwardenBrowserExtensionVersion)
                ? manifest.Version ?? "manual"
                : _settings.Current.BitwardenBrowserExtensionVersion!;
            return new BitwardenBrowserExtensionInstall(
                version,
                path,
                _settings.Current.BitwardenBrowserExtensionSha256,
                _settings.Current.BitwardenBrowserExtensionAssetName,
                _settings.Current.BitwardenBrowserExtensionDownloadUrl);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Configured Bitwarden browser extension path is not usable: {Path}", path);
            return null;
        }
    }

    public async Task<BitwardenBrowserExtensionUpdateCheck> CheckForUpdateAsync(
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await CheckForUpdateCoreAsync(GetConfiguredInstall()?.Version, cancellationToken).ConfigureAwait(false);
        }
        catch (BitwardenBrowserExtensionException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new BitwardenBrowserExtensionException("Could not check for Bitwarden browser extension updates.", ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<BitwardenBrowserExtensionUpdateResult> UpdateIfAvailableAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_settings.Current.BitwardenBrowserExtensionSource != BitwardenBrowserExtensionSource.OfficialGitHub)
            {
                throw new BitwardenBrowserExtensionException("Manual Bitwarden browser extension installations are pinned and cannot be auto-updated.");
            }

            var current = GetConfiguredInstall();
            var check = await CheckForUpdateCoreAsync(current?.Version, cancellationToken).ConfigureAwait(false);
            if (!check.IsUpdateAvailable)
            {
                return new BitwardenBrowserExtensionUpdateResult(check, Install: null, WasUpdated: false);
            }

            progress?.Report("Downloading Bitwarden browser extension update...");
            var install = await InstallReleaseAssetAsync(
                check.LatestVersion,
                check.AssetName,
                check.DownloadUrl,
                check.ExpectedSha256,
                progress,
                cancellationToken).ConfigureAwait(false);
            return new BitwardenBrowserExtensionUpdateResult(check, install, WasUpdated: true);
        }
        catch (BitwardenBrowserExtensionException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new BitwardenBrowserExtensionException("Could not update the Bitwarden browser extension.", ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<BitwardenBrowserExtensionInstall> InstallLatestAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            progress?.Report("Checking Bitwarden browser releases...");
            var latest = await ResolveLatestReleaseAsync(cancellationToken).ConfigureAwait(false);
            progress?.Report("Downloading Bitwarden browser extension...");
            return await InstallReleaseAssetAsync(
                latest.Version,
                latest.Asset.Name!,
                latest.Asset.BrowserDownloadUrl!,
                latest.ExpectedSha256,
                progress,
                cancellationToken).ConfigureAwait(false);
        }
        catch (BitwardenBrowserExtensionException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new BitwardenBrowserExtensionException("Could not install the Bitwarden browser extension.", ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<BitwardenBrowserExtensionInstall> ImportZipAsync(
        string zipPath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(zipPath))
            throw new BitwardenBrowserExtensionException("Select a Bitwarden browser extension ZIP file.");
        if (!File.Exists(zipPath))
            throw new BitwardenBrowserExtensionException("The selected ZIP file does not exist.");

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var sha256 = await ComputeFileSha256Async(zipPath, cancellationToken).ConfigureAwait(false);
            return await InstallZipFileAsync(
                zipPath,
                forcedVersion: null,
                sha256,
                Path.GetFileName(zipPath),
                downloadUrl: null,
                BitwardenBrowserExtensionSource.ManualZip,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<BitwardenBrowserExtensionInstall> ImportUnpackedAsync(
        string extensionFolderPath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(extensionFolderPath))
            throw new BitwardenBrowserExtensionException("Select an unpacked Bitwarden browser extension folder.");
        if (!Directory.Exists(extensionFolderPath))
            throw new BitwardenBrowserExtensionException("The selected extension folder does not exist.");

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var manifest = BitwardenBrowserExtensionManifest.Read(extensionFolderPath);
            var version = SanitizeVersion(manifest.Version ?? "manual");
            var finalPath = GetUniqueInstallPath(version);
            CopyDirectory(extensionFolderPath, finalPath, cancellationToken);
            var sha256 = await ComputeDirectorySha256Async(finalPath, cancellationToken).ConfigureAwait(false);
            return PersistInstall(version, finalPath, sha256, assetName: null, downloadUrl: null, BitwardenBrowserExtensionSource.ManualFolder);
        }
        finally
        {
            _gate.Release();
        }
    }

    internal static bool IsBrowserRelease(GitHubRelease release) =>
        !release.Draft
        && !release.Prerelease
        && release.TagName?.StartsWith("browser-v", StringComparison.OrdinalIgnoreCase) == true;

    internal static GitHubReleaseAsset? FindPreferredAsset(GitHubRelease release) =>
        FindAsset(release, "dist-edge-") ?? FindAsset(release, "dist-chrome-");

    internal static string? ParseGitHubSha256(string? digest)
    {
        if (string.IsNullOrWhiteSpace(digest)) return null;
        const string prefix = "sha256:";
        var value = digest.Trim();
        if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) value = value[prefix.Length..];
        return value.Length == 64 && value.All(Uri.IsHexDigit) ? value.ToLowerInvariant() : null;
    }

    internal static string? ParseBrowserVersion(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var text = value.Trim();
        var marker = text.IndexOf("browser-v", StringComparison.OrdinalIgnoreCase);
        if (marker >= 0) text = text[(marker + "browser-v".Length)..];
        if (text.StartsWith("dist-edge-", StringComparison.OrdinalIgnoreCase)) text = text["dist-edge-".Length..];
        if (text.StartsWith("dist-chrome-", StringComparison.OrdinalIgnoreCase)) text = text["dist-chrome-".Length..];
        if (text.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) text = text[..^4];
        return string.IsNullOrWhiteSpace(text) ? null : SanitizeVersion(text);
    }

    internal static int CompareBrowserVersions(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left)) return string.IsNullOrWhiteSpace(right) ? 0 : -1;
        if (string.IsNullOrWhiteSpace(right)) return 1;

        var leftParts = SplitVersion(left);
        var rightParts = SplitVersion(right);
        var count = Math.Max(leftParts.Length, rightParts.Length);
        for (var i = 0; i < count; i++)
        {
            var leftPart = i < leftParts.Length ? leftParts[i] : "0";
            var rightPart = i < rightParts.Length ? rightParts[i] : "0";
            var comparison = CompareVersionPart(leftPart, rightPart);
            if (comparison != 0) return comparison;
        }

        return 0;
    }

    public void Dispose() => _gate.Dispose();

    private async Task<BitwardenBrowserExtensionUpdateCheck> CheckForUpdateCoreAsync(
        string? currentVersion,
        CancellationToken cancellationToken)
    {
        var latest = await ResolveLatestReleaseAsync(cancellationToken).ConfigureAwait(false);
        var isUpdateAvailable = CompareBrowserVersions(latest.Version, currentVersion) > 0;
        return new BitwardenBrowserExtensionUpdateCheck(
            currentVersion,
            latest.Version,
            isUpdateAvailable,
            latest.Asset.Name!,
            latest.Asset.BrowserDownloadUrl!,
            latest.ExpectedSha256);
    }

    private async Task<ResolvedBrowserRelease> ResolveLatestReleaseAsync(CancellationToken cancellationToken)
    {
        var releaseClient = _httpClientFactory.CreateClient(ReleaseHttpClientName);
        var releasesPath = string.IsNullOrWhiteSpace(_settings.Current.BitwardenBrowserExtensionReleasesUrl)
            ? DefaultReleasesPath
            : _settings.Current.BitwardenBrowserExtensionReleasesUrl.Trim();

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

        var release = releases.FirstOrDefault(IsBrowserRelease)
            ?? throw new BitwardenBrowserExtensionException("No Bitwarden browser extension release was found.");
        var asset = FindPreferredAsset(release)
            ?? throw new BitwardenBrowserExtensionException("The latest Bitwarden browser release has no Edge or Chrome extension ZIP asset.");
        if (string.IsNullOrWhiteSpace(asset.BrowserDownloadUrl))
            throw new BitwardenBrowserExtensionException("The Bitwarden extension asset has no download URL.");

        var version = ParseBrowserVersion(release.TagName) ?? ParseBrowserVersion(asset.Name) ?? "latest";
        return new ResolvedBrowserRelease(version, asset, ParseGitHubSha256(asset.Digest));
    }

    private async Task<BitwardenBrowserExtensionInstall> InstallReleaseAssetAsync(
        string version,
        string assetName,
        string downloadUrl,
        string? expectedSha256,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_downloadRoot);
        var zipPath = Path.Combine(_downloadRoot, $"bitwarden-browser-{version}-{Guid.NewGuid():N}.zip");
        try
        {
            var actualSha256 = await DownloadAsync(downloadUrl, zipPath, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(expectedSha256)
                && !string.Equals(expectedSha256, actualSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new BitwardenBrowserExtensionException("The downloaded Bitwarden extension checksum does not match the GitHub release metadata.");
            }

            progress?.Report("Installing Bitwarden browser extension...");
            return await InstallZipFileAsync(
                zipPath,
                version,
                actualSha256,
                assetName,
                downloadUrl,
                BitwardenBrowserExtensionSource.OfficialGitHub,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            TryDeleteFile(zipPath);
        }
    }

    private async Task<BitwardenBrowserExtensionInstall> InstallZipFileAsync(
        string zipPath,
        string? forcedVersion,
        string? sha256,
        string? assetName,
        string? downloadUrl,
        BitwardenBrowserExtensionSource source,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_installRoot);
        var staging = Path.Combine(_installRoot, ".staging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);

        try
        {
            ExtractZipSafely(zipPath, staging);
            cancellationToken.ThrowIfCancellationRequested();

            var extensionRoot = FindExtensionRoot(staging);
            var manifest = BitwardenBrowserExtensionManifest.Read(extensionRoot);
            var version = SanitizeVersion(forcedVersion ?? manifest.Version ?? "manual");
            var finalPath = GetUniqueInstallPath(version);
            Directory.Move(extensionRoot, finalPath);
            if (Directory.Exists(staging)) Directory.Delete(staging, recursive: true);
            return PersistInstall(version, finalPath, sha256, assetName, downloadUrl, source);
        }
        catch
        {
            TryDeleteDirectory(staging);
            throw;
        }
    }

    private BitwardenBrowserExtensionInstall PersistInstall(
        string version,
        string extensionPath,
        string? sha256,
        string? assetName,
        string? downloadUrl,
        BitwardenBrowserExtensionSource source)
    {
        _settings.Current.BitwardenBrowserExtensionSource = source;
        _settings.Current.BitwardenBrowserExtensionVersion = version;
        _settings.Current.BitwardenBrowserExtensionPath = extensionPath;
        _settings.Current.BitwardenBrowserExtensionSha256 = sha256;
        _settings.Current.BitwardenBrowserExtensionAssetName = assetName;
        _settings.Current.BitwardenBrowserExtensionDownloadUrl = downloadUrl;
        _settings.Current.BitwardenBrowserExtensionAvailableVersion = null;
        _settings.Current.BitwardenBrowserExtensionLastUpdateError = null;
        _settings.Current.BitwardenBrowserExtensionLastUpdateStatus = source switch
        {
            BitwardenBrowserExtensionSource.OfficialGitHub => $"Installed official release {version}.",
            BitwardenBrowserExtensionSource.ManualZip => "Manual ZIP install is pinned; auto-update disabled.",
            BitwardenBrowserExtensionSource.ManualFolder => "Manual folder install is pinned; auto-update disabled.",
            _ => null,
        };
        if (source == BitwardenBrowserExtensionSource.OfficialGitHub)
        {
            _settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = DateTimeOffset.UtcNow;
        }
        else
        {
            _settings.Current.BitwardenBrowserExtensionLastUpdateCheckUtc = null;
        }
        _settings.Save();
        return new BitwardenBrowserExtensionInstall(version, extensionPath, sha256, assetName, downloadUrl);
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

    private static GitHubReleaseAsset? FindAsset(GitHubRelease release, string prefix) =>
        release.Assets.FirstOrDefault(asset =>
            !string.IsNullOrWhiteSpace(asset.Name)
            && !string.IsNullOrWhiteSpace(asset.BrowserDownloadUrl)
            && asset.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            && asset.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase));

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
                throw new BitwardenBrowserExtensionException("The extension ZIP contains an unsafe path.");
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

    private static string FindExtensionRoot(string stagingRoot)
    {
        if (File.Exists(Path.Combine(stagingRoot, "manifest.json"))) return stagingRoot;

        var manifests = Directory.GetFiles(stagingRoot, "manifest.json", SearchOption.AllDirectories);
        if (manifests.Length == 0)
            throw new BitwardenBrowserExtensionException("The extension ZIP does not contain manifest.json.");
        if (manifests.Length == 1) return Path.GetDirectoryName(manifests[0])!;

        foreach (var manifest in manifests)
        {
            var directory = Path.GetDirectoryName(manifest)!;
            try
            {
                var parsed = BitwardenBrowserExtensionManifest.Read(directory);
                if (parsed.Name.Contains("bitwarden", StringComparison.OrdinalIgnoreCase)) return directory;
            }
            catch
            {
                // Keep looking for a usable manifest.
            }
        }

        throw new BitwardenBrowserExtensionException("The extension ZIP contains multiple manifests and none could be identified as Bitwarden.");
    }

    private static string SanitizeVersion(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value.Trim())
        {
            builder.Append(char.IsLetterOrDigit(ch) || ch is '.' or '-' or '_' ? ch : '-');
        }
        return builder.Length == 0 ? "manual" : builder.ToString();
    }

    private static string[] SplitVersion(string value) =>
        (ParseBrowserVersion(value) ?? value)
            .Split(['.', '-', '_'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static int CompareVersionPart(string left, string right)
    {
        var leftIsNumber = long.TryParse(left, out var leftNumber);
        var rightIsNumber = long.TryParse(right, out var rightNumber);
        if (leftIsNumber && rightIsNumber) return leftNumber.CompareTo(rightNumber);
        return string.Compare(left, right, StringComparison.OrdinalIgnoreCase);
    }

    private static void CopyDirectory(string source, string destination, CancellationToken cancellationToken)
    {
        var sourceRoot = Path.GetFullPath(source);
        Directory.CreateDirectory(destination);
        foreach (var directory in Directory.GetDirectories(sourceRoot, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(sourceRoot, directory)));
        }
        foreach (var file in Directory.GetFiles(sourceRoot, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = Path.Combine(destination, Path.GetRelativePath(sourceRoot, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: false);
        }
    }

    private static async Task<string> ComputeFileSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task<string> ComputeDirectorySha256Async(string directory, CancellationToken cancellationToken)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var files = Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relative = Path.GetRelativePath(directory, file).Replace(Path.DirectorySeparatorChar, '/');
            sha.AppendData(Encoding.UTF8.GetBytes(relative));
            sha.AppendData(new byte[] { 0 });
            await using var stream = File.OpenRead(file);
            var buffer = new byte[DownloadBufferSize];
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                sha.AppendData(buffer, 0, read);
            }
        }
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
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

    private sealed record ResolvedBrowserRelease(string Version, GitHubReleaseAsset Asset, string? ExpectedSha256);
}
