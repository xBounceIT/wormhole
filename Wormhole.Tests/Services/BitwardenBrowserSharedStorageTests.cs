using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Services.BitwardenBrowser;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class BitwardenBrowserSharedStorageTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(), "wormhole-bitwarden-storage-tests-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Capture_SharesLocalAndLiveSessionStorageAcrossProfiles()
    {
        var store = CreateStore();
        var firstProfile = Profile("first");
        var secondProfile = Profile("second");

        await store.CaptureAsync(
            firstProfile,
            new BitwardenBrowserStorageSnapshot(
                """{"accounts":{"active":"one"},"token":"encrypted"}""",
                """{"unlocked":true}"""));

        var restore = await store.GetRestoreAsync(secondProfile);

        Assert.NotNull(restore);
        Assert.Contains("\"token\":\"encrypted\"", restore.LocalJson, StringComparison.Ordinal);
        Assert.Equal("""{"unlocked":true}""", restore.SessionJson);
    }

    [Fact]
    public async Task Reload_PersistsLocalStorageButNotMemoryOnlySessionStorage()
    {
        var path = Path.Combine(_directory, "shared.dpapi");
        var first = CreateStore(path);
        await first.CaptureAsync(
            Profile("source"),
            new BitwardenBrowserStorageSnapshot("""{"token":"encrypted"}""", """{"unlocked":true}"""));

        var restarted = CreateStore(path);
        var restore = await restarted.GetRestoreAsync(Profile("destination"));

        Assert.NotNull(restore);
        Assert.Equal("""{"token":"encrypted"}""", restore.LocalJson);
        Assert.Equal("{}", restore.SessionJson);
    }

    [Fact]
    public async Task Capture_PropagatesNewerRevisionBackToAnOlderProfile()
    {
        var store = CreateStore();
        var firstProfile = Profile("first");
        var secondProfile = Profile("second");
        await store.CaptureAsync(
            firstProfile,
            new BitwardenBrowserStorageSnapshot("""{"account":"one"}""", "{}"));

        var firstRestore = await store.GetRestoreAsync(secondProfile);
        Assert.NotNull(firstRestore);
        await store.MarkRestoredAsync(secondProfile, firstRestore);
        await store.CaptureAsync(
            secondProfile,
            new BitwardenBrowserStorageSnapshot("""{"account":"two"}""", """{"unlocked":true}"""));

        var restoreBack = await store.GetRestoreAsync(firstProfile);

        Assert.NotNull(restoreBack);
        Assert.Equal("""{"account":"two"}""", restoreBack.LocalJson);
        Assert.Equal("""{"unlocked":true}""", restoreBack.SessionJson);
    }

    [Fact]
    public async Task Capture_DoesNotLetStaleProfileOverwriteNewerSharedRevision()
    {
        var store = CreateStore();
        var firstProfile = Profile("first");
        var staleProfile = Profile("stale");
        await store.CaptureAsync(
            firstProfile,
            new BitwardenBrowserStorageSnapshot("""{"revision":1}""", "{}"));
        var initialRestore = await store.GetRestoreAsync(staleProfile);
        Assert.NotNull(initialRestore);
        await store.MarkRestoredAsync(staleProfile, initialRestore);
        await store.CaptureAsync(
            firstProfile,
            new BitwardenBrowserStorageSnapshot("""{"revision":2}""", "{}"));

        await store.CaptureAsync(
            staleProfile,
            new BitwardenBrowserStorageSnapshot("""{"revision":1}""", "{}"));

        var current = await store.GetRestoreAsync(Profile("new-profile"));
        Assert.NotNull(current);
        Assert.Equal("""{"revision":2}""", current.LocalJson);
        Assert.NotNull(await store.GetRestoreAsync(staleProfile));
    }

    [Fact]
    public async Task Reload_UsesAtomicBackupWhenPrimarySnapshotIsCorrupt()
    {
        var path = Path.Combine(_directory, "shared.dpapi");
        var store = CreateStore(path);
        await store.CaptureAsync(
            Profile("first"),
            new BitwardenBrowserStorageSnapshot("""{"revision":1}""", "{}"));
        Assert.True(File.Exists(path + ".bak"));
        await store.CaptureAsync(
            Profile("first"),
            new BitwardenBrowserStorageSnapshot("""{"revision":2}""", "{}"));
        File.WriteAllText(path, "corrupt");

        var restarted = CreateStore(path);
        var restore = await restarted.GetRestoreAsync(Profile("second"));

        Assert.NotNull(restore);
        Assert.Equal("""{"revision":2}""", restore.LocalJson);

        await restarted.CaptureAsync(
            Profile("second"),
            new BitwardenBrowserStorageSnapshot("""{"revision":2}""", "{}"));
    }

    [Fact]
    public async Task Reload_RepairsRecoveryCopyWhenItContainsAnOlderRevision()
    {
        var path = Path.Combine(_directory, "shared.dpapi");
        var backupPath = path + ".bak";
        var writer = CreateStore(path);
        await writer.CaptureAsync(
            Profile("source"),
            new BitwardenBrowserStorageSnapshot("""{"revision":1}""", "{}"));
        var oldRecovery = await File.ReadAllBytesAsync(backupPath);
        await writer.CaptureAsync(
            Profile("source"),
            new BitwardenBrowserStorageSnapshot("""{"revision":2}""", "{}"));
        await File.WriteAllBytesAsync(backupPath, oldRecovery);

        var repairer = CreateStore(path);
        var current = await repairer.GetRestoreAsync(Profile("probe"));
        Assert.NotNull(current);
        Assert.Equal("""{"revision":2}""", current.LocalJson);
        await repairer.CaptureAsync(
            Profile("repair"),
            new BitwardenBrowserStorageSnapshot("""{"revision":2}""", "{}"));
        await File.WriteAllTextAsync(path, "corrupt");

        var recovered = await CreateStore(path).GetRestoreAsync(Profile("recovered"));
        Assert.NotNull(recovered);
        Assert.Equal("""{"revision":2}""", recovered.LocalJson);
    }

    [Fact]
    public async Task Reload_RetriesAfterTransientReadFailureInsteadOfTreatingStoreAsEmpty()
    {
        var path = Path.Combine(_directory, "shared.dpapi");
        var writer = CreateStore(path);
        await writer.CaptureAsync(
            Profile("source"),
            new BitwardenBrowserStorageSnapshot("""{"token":"preserved"}""", "{}"));
        var failReads = true;
        var reader = new BitwardenBrowserSharedStorage(
            NullLogger<BitwardenBrowserSharedStorage>.Instance,
            path,
            bytes => bytes.ToArray(),
            bytes => failReads ? throw new IOException("simulated transient read failure") : bytes.ToArray());

        Assert.Null(await reader.GetRestoreAsync(Profile("first-attempt")));
        failReads = false;

        var recovered = await reader.GetRestoreAsync(Profile("second-attempt"));
        Assert.NotNull(recovered);
        Assert.Equal("""{"token":"preserved"}""", recovered.LocalJson);
    }

    [Fact]
    public async Task Capture_DoesNotOverwriteUnreadablePrimaryWithoutRecoveryCopy()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "shared.dpapi");
        const string unreadable = "not-a-valid-snapshot";
        await File.WriteAllTextAsync(path, unreadable);
        var store = CreateStore(path);

        await store.CaptureAsync(
            Profile("source"),
            new BitwardenBrowserStorageSnapshot("""{"token":"live-only"}""", "{}"));

        Assert.Equal(unreadable, await File.ReadAllTextAsync(path));
        var liveRestore = await store.GetRestoreAsync(Profile("destination"));
        Assert.NotNull(liveRestore);
        Assert.False(liveRestore.IsDurable);
        Assert.Equal("""{"token":"live-only"}""", liveRestore.LocalJson);
    }

    [Fact]
    public async Task PersistenceFailure_KeepsSnapshotShareableInMemoryAndDoesNotAdvanceMarker()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "shared.dpapi");
        var store = new BitwardenBrowserSharedStorage(
            NullLogger<BitwardenBrowserSharedStorage>.Instance,
            path,
            _ => throw new IOException("simulated disk failure"),
            bytes => bytes);
        var firstProfile = Profile("first");

        await store.CaptureAsync(
            firstProfile,
            new BitwardenBrowserStorageSnapshot("""{"token":"still-live"}""", """{"unlocked":true}"""));
        var restore = await store.GetRestoreAsync(Profile("second"));

        Assert.NotNull(restore);
        Assert.False(restore.IsDurable);
        Assert.Equal("""{"token":"still-live"}""", restore.LocalJson);
        Assert.False(File.Exists(Path.Combine(
            firstProfile, BitwardenBrowserSharedStorage.ProfileRevisionFileName)));
    }

    [Fact]
    public void StorageBridge_RejectsUnrelatedMessagesAndParsesSnapshots()
    {
        Assert.False(BitwardenBrowserStorageBridge.TryParseMessage(
            """{"channel":"other","nonce":"n","command":"capture","ok":true}""",
            "n",
            "capture",
            out _,
            out _));

        Assert.False(BitwardenBrowserStorageBridge.TryParseMessage(
            """"primitive"""",
            "n",
            "capture",
            out _,
            out _));
        Assert.False(BitwardenBrowserStorageBridge.TryParseMessage(
            "[]",
            "n",
            "capture",
            out _,
            out _));
        Assert.False(BitwardenBrowserStorageBridge.TryParseMessage(
            """{"channel":1,"nonce":"n","command":"capture","ok":true}""",
            "n",
            "capture",
            out _,
            out _));

        var parsed = BitwardenBrowserStorageBridge.TryParseMessage(
            """{"channel":"wormhole-bitwarden-storage-v1","nonce":"n","command":"capture","ok":true,"local":{"token":"x"},"session":{"unlocked":true}}""",
            "n",
            "capture",
            out var snapshot,
            out var error);

        Assert.True(parsed);
        Assert.Null(error);
        Assert.NotNull(snapshot);
        Assert.Equal("""{"token":"x"}""", snapshot.LocalJson);
        Assert.Equal("""{"unlocked":true}""", snapshot.SessionJson);
    }

    [Fact]
    public void RestoreScript_UsesBothExtensionStorageAreas()
    {
        var script = BitwardenBrowserStorageBridge.BuildRestoreScript(
            "nonce",
            new BitwardenBrowserStorageRestore(1, """{"local":1}""", """{"session":2}""", true));

        Assert.Contains("chrome.storage.local.clear", script, StringComparison.Ordinal);
        Assert.Contains("chrome.storage.local.set", script, StringComparison.Ordinal);
        Assert.Contains("chrome.storage.session.clear", script, StringComparison.Ordinal);
        Assert.Contains("chrome.storage.session.set", script, StringComparison.Ordinal);
    }

    private BitwardenBrowserSharedStorage CreateStore(string? path = null) =>
        new(
            NullLogger<BitwardenBrowserSharedStorage>.Instance,
            path ?? Path.Combine(_directory, "shared.dpapi"),
            bytes => bytes.ToArray(),
            bytes => bytes.ToArray());

    private string Profile(string name)
    {
        var path = Path.Combine(_directory, name);
        Directory.CreateDirectory(path);
        return path;
    }

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); }
        catch { /* best effort */ }
    }
}
