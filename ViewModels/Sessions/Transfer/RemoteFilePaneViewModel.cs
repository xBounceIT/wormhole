using Wormhole.Services;
using Wormhole.Services.Sftp;

namespace Wormhole.ViewModels.Sessions.Transfer;

public sealed class RemoteFilePaneViewModel : FilePaneViewModel
{
    private readonly ISftpSession _session;
    private readonly Func<Func<Task>, Task> _serialize;

    /// <param name="session">Connected SFTP session — owned by the dialog, not this VM.</param>
    /// <param name="serialize">
    /// Wrap every SFTP call so the orchestrator's <c>SemaphoreSlim(1,1)</c> covers
    /// pane operations (list/create/delete/rename) as well as transfers — SSH.NET's
    /// SftpClient is not safe for concurrent calls and a refresh interleaved with an
    /// in-flight upload corrupts the session state.
    /// </param>
    public RemoteFilePaneViewModel(ISftpSession session, Func<Func<Task>, Task> serialize)
    {
        _session = session;
        _serialize = serialize;
    }

    public override bool IsLocal => false;
    public override string Title => "Remote";

    protected override Task<IReadOnlyList<FileEntryViewModel>> ListAsync(string path, CancellationToken cancellationToken)
    {
        return SerializeAsync(async () =>
        {
            var entries = await _session.ListDirectoryAsync(path, cancellationToken).ConfigureAwait(false);
            var viewEntries = new List<FileEntryViewModel>(entries.Count);
            foreach (var entry in entries)
            {
                viewEntries.Add(new FileEntryViewModel(
                    name: entry.Name,
                    fullPath: entry.FullPath,
                    isDirectory: entry.IsDirectory,
                    isSymbolicLink: entry.IsSymbolicLink,
                    size: entry.Size,
                    lastModifiedUtc: entry.LastModifiedUtc));
            }
            return (IReadOnlyList<FileEntryViewModel>)viewEntries;
        });
    }

    protected override Task CreateFolderCoreAsync(string fullPath, CancellationToken cancellationToken) =>
        SerializeAsync(() => _session.CreateDirectoryAsync(fullPath, cancellationToken));

    protected override Task CreateFileCoreAsync(string fullPath, CancellationToken cancellationToken) =>
        SerializeAsync(() => _session.CreateEmptyFileAsync(fullPath, cancellationToken));

    protected override Task DeleteCoreAsync(FileEntryViewModel entry, CancellationToken cancellationToken) =>
        SerializeAsync(() => entry.IsDirectory
            ? _session.DeleteDirectoryAsync(entry.FullPath, recursive: true, cancellationToken)
            : _session.DeleteFileAsync(entry.FullPath, cancellationToken));

    protected override Task RenameCoreAsync(FileEntryViewModel entry, string newName, CancellationToken cancellationToken)
    {
        var parent = RemotePath.Parent(entry.FullPath);
        var target = RemotePath.Join(parent, newName);
        return SerializeAsync(() => _session.RenameAsync(entry.FullPath, target, cancellationToken));
    }

    protected override string ParentOf(string path) => RemotePath.Parent(path);
    protected override string Join(string parent, string name) => RemotePath.Join(parent, name);

    private Task SerializeAsync(Func<Task> action) => _serialize(action);

    private async Task<T> SerializeAsync<T>(Func<Task<T>> action)
    {
        T result = default!;
        await _serialize(async () => { result = await action().ConfigureAwait(false); }).ConfigureAwait(false);
        return result;
    }
}
