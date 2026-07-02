using Wormhole.Services.BitwardenBrowser;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenBrowserExtensionMarkerTests
{
    [Fact]
    public async Task WriteAndRead_RoundTripsExtensionIdForMatchingPath()
    {
        using var temp = TempDirectory.Create();
        var extensionPath = Path.Combine(temp.Path, "extension");
        Directory.CreateDirectory(extensionPath);
        var markerPath = BitwardenBrowserExtensionMarker.GetPath(Path.Combine(temp.Path, "profile"));

        await BitwardenBrowserExtensionMarker.WriteAsync(markerPath, extensionPath, "abc123");

        var matches = BitwardenBrowserExtensionMarker.TryReadInstalledExtensionId(markerPath, extensionPath, out var extensionId);

        Assert.True(matches);
        Assert.Equal("abc123", extensionId);
    }

    [Fact]
    public async Task TryReadInstalledExtensionId_ReturnsFalseForDifferentPathOrLegacyMarker()
    {
        using var temp = TempDirectory.Create();
        var profile = Path.Combine(temp.Path, "profile");
        var markerPath = BitwardenBrowserExtensionMarker.GetPath(profile);
        var extensionPath = Path.Combine(temp.Path, "extension");
        var otherPath = Path.Combine(temp.Path, "other");
        Directory.CreateDirectory(extensionPath);
        Directory.CreateDirectory(otherPath);

        await BitwardenBrowserExtensionMarker.WriteAsync(markerPath, extensionPath, "abc123");
        Assert.False(BitwardenBrowserExtensionMarker.TryReadInstalledExtensionId(markerPath, otherPath, out _));

        await File.WriteAllTextAsync(markerPath, extensionPath);
        Assert.False(BitwardenBrowserExtensionMarker.TryReadInstalledExtensionId(markerPath, extensionPath, out _));
    }

    private sealed class TempDirectory : IDisposable
    {
        private TempDirectory(string path) => Path = path;

        public string Path { get; }

        public static TempDirectory Create()
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "Wormhole.Tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return new TempDirectory(path);
        }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
