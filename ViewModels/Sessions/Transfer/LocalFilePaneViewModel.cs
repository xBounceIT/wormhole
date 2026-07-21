namespace Wormhole.ViewModels.Sessions.Transfer;

public class LocalFilePaneViewModel : FilePaneViewModel
{
    public override bool IsLocal => true;
    public override string Title => "Local";

    /// <summary>
    /// WinSCP-style preset folders for the path-bar dropdown. Built once per pane
    /// instance from the current machine's special folders and ready drives.
    /// </summary>
    public IReadOnlyList<QuickPathItem> QuickPaths { get; } = LocalQuickPaths.Build();

    protected override Task<IReadOnlyList<FileEntryViewModel>> ListAsync(string path, CancellationToken cancellationToken) =>
        Task.Run<IReadOnlyList<FileEntryViewModel>>(() =>
        {
            var entries = new List<FileEntryViewModel>();
            // Directory.EnumerateFileSystemInfos surfaces both files and folders in one
            // call and gives us mtime/length without a second stat per entry.
            foreach (var info in new DirectoryInfo(path).EnumerateFileSystemInfos())
            {
                cancellationToken.ThrowIfCancellationRequested();
                bool isDir = (info.Attributes & FileAttributes.Directory) == FileAttributes.Directory;
                bool isLink = (info.Attributes & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint;
                long size = isDir ? 0 : (info is FileInfo fi ? fi.Length : 0);
                entries.Add(new FileEntryViewModel(
                    name: info.Name,
                    fullPath: info.FullName,
                    isDirectory: isDir,
                    isSymbolicLink: isLink,
                    size: size,
                    lastModifiedUtc: info.LastWriteTimeUtc));
            }
            return entries;
        }, cancellationToken);

    protected override Task CreateFolderCoreAsync(string fullPath, CancellationToken cancellationToken) =>
        Task.Run(() => Directory.CreateDirectory(fullPath), cancellationToken);

    protected override Task CreateFileCoreAsync(string fullPath, CancellationToken cancellationToken) =>
        Task.Run(() =>
        {
            // Open with CreateNew so we error rather than truncate when a file already
            // exists at the target — the conflict belongs to the user, not silent.
            using var s = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        }, cancellationToken);

    protected override Task DeleteCoreAsync(FileEntryViewModel entry, CancellationToken cancellationToken) =>
        Task.Run(() =>
        {
            if (entry.IsDirectory)
            {
                Directory.Delete(entry.FullPath, recursive: true);
            }
            else
            {
                File.Delete(entry.FullPath);
            }
        }, cancellationToken);

    protected override Task RenameCoreAsync(FileEntryViewModel entry, string newName, CancellationToken cancellationToken) =>
        Task.Run(() =>
        {
            var dir = Path.GetDirectoryName(entry.FullPath) ?? string.Empty;
            var target = Path.Combine(dir, newName);
            if (entry.IsDirectory) Directory.Move(entry.FullPath, target);
            else File.Move(entry.FullPath, target);
        }, cancellationToken);

    protected override string ParentOf(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        var parent = Path.GetDirectoryName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return string.IsNullOrEmpty(parent) ? path : parent;
    }

    protected override string Join(string parent, string name) => Path.Combine(parent, name);
}
