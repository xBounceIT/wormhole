using System.IO;
using Wormhole.Models;
using Wormhole.Services.Sftp;
using Xunit;

namespace Wormhole.Tests.Services.Sftp;

public sealed class TransferDropTargetTests : IDisposable
{
    private readonly string _root;

    public TransferDropTargetTests()
    {
        _root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "wormhole-drop-" + Guid.NewGuid().ToString("N"))).FullName;
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void ResolveDestinationDirectory_UsesHoveredFolderPath()
    {
        var folder = Path.Combine(_root, "subdir");
        Assert.Equal(folder, TransferDropTarget.ResolveDestinationDirectory(_root, folder, hoveredIsDirectory: true));
    }

    [Fact]
    public void ResolveDestinationDirectory_FallsBackToCurrentPath_ForFileHover()
    {
        var file = Path.Combine(_root, "a.txt");
        Assert.Equal(_root, TransferDropTarget.ResolveDestinationDirectory(_root, file, hoveredIsDirectory: false));
    }

    [Fact]
    public void ResolveDestinationDirectory_FallsBackToCurrentPath_WhenNothingHovered()
    {
        Assert.Equal(_root, TransferDropTarget.ResolveDestinationDirectory(_root, hoveredFullPath: null, hoveredIsDirectory: false));
    }

    [Fact]
    public void IsInvalidLocalDropDestination_RejectsFolderIntoItself()
    {
        var folder = Directory.CreateDirectory(Path.Combine(_root, "src")).FullName;
        var items = new[] { new TransferItem(folder, "src", IsDirectory: true) };

        Assert.True(TransferDropTarget.IsInvalidLocalDropDestination(folder, items));
    }

    [Fact]
    public void IsInvalidLocalDropDestination_RejectsFolderIntoDescendant()
    {
        var parent = Directory.CreateDirectory(Path.Combine(_root, "parent")).FullName;
        var child = Directory.CreateDirectory(Path.Combine(parent, "child")).FullName;
        var items = new[] { new TransferItem(parent, "parent", IsDirectory: true) };

        Assert.True(TransferDropTarget.IsInvalidLocalDropDestination(child, items));
    }

    [Fact]
    public void IsInvalidLocalDropDestination_AllowsSiblingFolderDrop()
    {
        var src = Directory.CreateDirectory(Path.Combine(_root, "src")).FullName;
        var dest = Directory.CreateDirectory(Path.Combine(_root, "dest")).FullName;
        var items = new[] { new TransferItem(src, "src", IsDirectory: true) };

        Assert.False(TransferDropTarget.IsInvalidLocalDropDestination(dest, items));
    }

    [Fact]
    public void IsInvalidLocalDropDestination_RejectsFolderDroppedOntoParentRow()
    {
        var parent = Directory.CreateDirectory(Path.Combine(_root, "parent")).FullName;
        var child = Directory.CreateDirectory(Path.Combine(parent, "child")).FullName;
        var items = new[] { new TransferItem(child, "child", IsDirectory: true) };

        Assert.True(TransferDropTarget.IsInvalidLocalDropDestination(parent, items));
    }

    [Fact]
    public void IsInvalidLocalDropDestination_RejectsFileDroppedOntoCurrentDirectory()
    {
        var file = Path.Combine(_root, "a.txt");
        File.WriteAllText(file, "x");
        var items = new[] { new TransferItem(file, "a.txt", IsDirectory: false) };

        Assert.True(TransferDropTarget.IsInvalidLocalDropDestination(_root, items));
    }

    [Fact]
    public void IsInvalidLocalDropDestination_IgnoresRemoteSourcePaths()
    {
        var dest = Directory.CreateDirectory(Path.Combine(_root, "dest")).FullName;
        var items = new[] { new TransferItem("/home/user/src", "src", IsDirectory: true) };

        Assert.False(TransferDropTarget.IsInvalidLocalDropDestination(dest, items));
    }
}
