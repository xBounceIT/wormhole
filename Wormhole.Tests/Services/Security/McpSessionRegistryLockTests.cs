using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Mcp;
using Wormhole.Services.Security;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.Services.Security;

public sealed class McpSessionRegistryLockTests
{
    [Fact]
    public async Task ListSessionsAsync_WhenLocked_Throws()
    {
        var lockState = new AppLockState();
        lockState.SetLocked(true);
        var registry = CreateRegistry(lockState);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => registry.ListSessionsAsync());

        Assert.Contains("Wormhole is locked", ex.Message);
    }

    [Fact]
    public async Task ListSessionsAsync_WhenUnlocked_ReturnsEmptyList()
    {
        var registry = CreateRegistry(new AppLockState());

        var sessions = await registry.ListSessionsAsync();

        Assert.Empty(sessions);
    }

    private static McpSessionRegistry CreateRegistry(IAppLockState lockState)
    {
        var settings = new FakeSettingsService();
        var update = (UpdateViewModel)RuntimeHelpers.GetUninitializedObject(typeof(UpdateViewModel));
        var tree = new ConnectionTreeViewModel(
            new EmptyConnectionRepository(),
            new InheritanceResolver(),
            new NoopSessionTabFactory(),
            new FakeDialogService(),
            new FakeCredentialService(),
            new FakeCredentialRepository(),
            NullLogger<ConnectionTreeViewModel>.Instance);
        var shell = new ShellViewModel(tree, update, settings, NullLogger<ShellViewModel>.Instance);
        return new McpSessionRegistry(shell, new FakeDialogService(), lockState, NullLoggerFactory.Instance);
    }

    private sealed class FakeSettingsService : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged { add { } remove { } }
        public void Save() { }
    }

    private sealed class FakeUpdateService : IUpdateService
    {
        public UpdateCheckResult? LatestKnown => null;
        public event EventHandler<UpdateCheckResult>? UpdateAvailable { add { } remove { } }
        public Task<UpdateCheckResult> CheckAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(UpdateCheckResult.NoUpdate(new Version(0, 0, 0)));
        public Task<string> DownloadInstallerAsync(UpdateCheckResult update, IProgress<double>? progress, CancellationToken cancellationToken = default) =>
            Task.FromResult(string.Empty);
        public Task LaunchInstallerAndExitAsync(string installerPath) => Task.CompletedTask;
    }

    private sealed class NoopSessionTabFactory : ISessionTabFactory
    {
        public void Open(ConnectionProfile profile) { }
    }

    private sealed class EmptyConnectionRepository : IConnectionRepository
    {
        public Task<IReadOnlyList<ConnectionNode>> GetAllAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<ConnectionNode>>(Array.Empty<ConnectionNode>());
        public Task<ConnectionNode?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
            Task.FromResult<ConnectionNode?>(null);
        public Task<IReadOnlyList<(Guid Id, string Name)>> GetByTunnelConfigIdAsync(Guid tunnelConfigId, int limit, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<(Guid Id, string Name)>>(Array.Empty<(Guid Id, string Name)>());
        public Task AddAsync(ConnectionNode node, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task UpdateAsync(ConnectionNode node, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task UpdateManyAsync(IReadOnlyCollection<ConnectionNode> nodes, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task UpdateHostFingerprintAsync(Guid nodeId, string fingerprint, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task DeleteAsync(Guid id, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
