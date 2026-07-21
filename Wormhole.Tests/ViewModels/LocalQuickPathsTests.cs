using Wormhole.ViewModels.Sessions.Transfer;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public sealed class LocalQuickPathsTests
{
    private static string Folder(Environment.SpecialFolder folder) => folder switch
    {
        Environment.SpecialFolder.Desktop => @"C:\Users\test\Desktop",
        Environment.SpecialFolder.MyDocuments => @"C:\Users\test\Documents",
        Environment.SpecialFolder.MyPictures => @"C:\Users\test\Pictures",
        Environment.SpecialFolder.MyMusic => @"C:\Users\test\Music",
        Environment.SpecialFolder.MyVideos => @"C:\Users\test\Videos",
        Environment.SpecialFolder.UserProfile => @"C:\Users\test",
        _ => string.Empty,
    };

    [Fact]
    public void Build_IncludesKnownFolders_InWinScpOrder()
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Users\test",
            @"C:\Users\test\Desktop",
            @"C:\Users\test\Documents",
            @"C:\Users\test\Downloads",
            @"C:\Users\test\Pictures",
            @"C:\Users\test\Music",
            @"C:\Users\test\Videos",
            @"C:\",
        };

        var items = LocalQuickPaths.Build(
            getFolderPath: Folder,
            getDrives: () => [new LocalQuickPaths.DriveRoot(@"C:\", IsReady: true)],
            directoryExists: existing.Contains);

        Assert.Equal(
            [
                "Desktop",
                "Documents",
                "Downloads",
                "Pictures",
                "Music",
                "Videos",
                "Home",
            ],
            items.TakeWhile(i => !i.IsSeparator).Select(i => i.DisplayName));

        Assert.Contains(items, i => i.IsSeparator);
        Assert.Contains(items, i => i.DisplayName == @"C:\" && i.Path == @"C:\");
    }

    [Fact]
    public void Build_SkipsMissingFolders()
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Users\test",
            @"C:\Users\test\Documents",
            // Desktop / Downloads / Pictures / Music / Videos intentionally absent
            @"C:\",
        };

        var items = LocalQuickPaths.Build(
            getFolderPath: Folder,
            getDrives: () => [new LocalQuickPaths.DriveRoot(@"C:\", IsReady: true)],
            directoryExists: existing.Contains);

        Assert.DoesNotContain(items, i => i.DisplayName is "Desktop" or "Downloads" or "Pictures" or "Music" or "Videos");
        Assert.Contains(items, i => i.DisplayName == "Documents");
        Assert.Contains(items, i => i.DisplayName == "Home");
    }

    [Fact]
    public void Build_FiltersUnreadyDrives_AndDedupesRoots()
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Users\test",
            @"C:\Users\test\Documents",
            @"C:\",
            @"D:\",
        };

        var items = LocalQuickPaths.Build(
            getFolderPath: folder => folder == Environment.SpecialFolder.UserProfile
                ? @"C:\Users\test"
                : folder == Environment.SpecialFolder.MyDocuments
                    ? @"C:\Users\test\Documents"
                    : string.Empty,
            getDrives: () =>
            [
                new LocalQuickPaths.DriveRoot(@"C:\", IsReady: true),
                new LocalQuickPaths.DriveRoot(@"D:\", IsReady: false),
                new LocalQuickPaths.DriveRoot(@"E:\", IsReady: true), // not existing
            ],
            directoryExists: existing.Contains);

        Assert.Contains(items, i => i.Path == @"C:\");
        Assert.DoesNotContain(items, i => i.Path.StartsWith(@"D:\", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(items, i => i.Path.StartsWith(@"E:\", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, items.Count(i => !i.IsSeparator && i.Path.Length <= 3));
    }

    [Fact]
    public void Build_IgnoresInvalidPaths_WithoutThrowing()
    {
        var items = LocalQuickPaths.Build(
            getFolderPath: folder => folder == Environment.SpecialFolder.UserProfile
                ? @"C:\Users\test"
                : "not|*a|valid|path",
            getDrives: () =>
            [
                new LocalQuickPaths.DriveRoot("also|invalid", IsReady: true),
                new LocalQuickPaths.DriveRoot(@"C:\", IsReady: true),
            ],
            directoryExists: path => path is @"C:\Users\test" or @"C:\");

        Assert.Contains(items, i => i.DisplayName == "Home");
        Assert.Contains(items, i => i.Path == @"C:\");
        Assert.DoesNotContain(items, i => i.DisplayName is "Desktop" or "Documents");
    }

    [Fact]
    public void Build_IncludesUncPaths_WithoutDirectoryExistsProbe()
    {
        var uncDocuments = @"\\fileserver\users\test\Documents";
        var probed = new List<string>();
        var items = LocalQuickPaths.Build(
            getFolderPath: folder => folder == Environment.SpecialFolder.MyDocuments ? uncDocuments : string.Empty,
            getDrives: () => [],
            directoryExists: path =>
            {
                probed.Add(path);
                return false;
            });

        Assert.Contains(items, i => i.DisplayName == "Documents" && i.Path == uncDocuments);
        Assert.Empty(probed);
    }

    [Fact]
    public void EnumerateLocalDriveRoots_DoesNotThrow_OnRealMachine()
    {
        var ex = Record.Exception(() => LocalQuickPaths.EnumerateLocalDriveRoots());
        Assert.Null(ex);
    }

    [Fact]
    public void LocalFilePaneViewModel_ExposesQuickPaths()
    {
        var pane = new LocalFilePaneViewModel();
        Assert.NotEmpty(pane.QuickPaths);
        Assert.Contains(pane.QuickPaths, i => !i.IsSeparator && !string.IsNullOrEmpty(i.Path));
    }
}
