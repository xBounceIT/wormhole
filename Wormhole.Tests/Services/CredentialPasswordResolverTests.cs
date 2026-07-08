using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services;

public sealed class CredentialPasswordResolverTests
{
    [Fact]
    public async Task ReadPasswordAsync_LocalCredential_ReadsLocalStore()
    {
        var id = Guid.NewGuid();
        var local = new FakeCredentialService(passwords: new() { [id] = "local-pw" });
        var resolver = NewResolver(local, new FakeBitwardenClient());

        var password = await resolver.ReadPasswordAsync(new CredentialProfile { Id = id });

        Assert.Equal("local-pw", password);
    }

    [Fact]
    public async Task ReadPasswordAsync_BitwardenCredential_UnlocksAndReadsLoginPassword()
    {
        var bitwarden = new FakeBitwardenClient
        {
            Status = new BitwardenStatus(BitwardenVaultStatus.Locked),
            Item = new BitwardenLoginItem("item-1", "Server", "root", "vault-pw"),
        };
        var resolver = NewResolver(new FakeCredentialService(), bitwarden);

        var password = await resolver.ReadPasswordAsync(
            new CredentialProfile
            {
                SecretProvider = CredentialSecretProvider.Bitwarden,
                BitwardenItemId = "item-1",
            },
            _ => Task.FromResult<string?>("master"));

        Assert.Equal("vault-pw", password);
        Assert.Equal("master", bitwarden.UnlockPassword);
        Assert.Equal("SESSION", bitwarden.SessionSeenByGet);
    }

    [Fact]
    public async Task ReadPasswordAsync_BitwardenLocked_PromptsOnCapturedSynchronizationContext()
    {
        var context = new InlineSynchronizationContext();
        var previousContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            var bitwarden = new FakeBitwardenClient
            {
                Status = new BitwardenStatus(BitwardenVaultStatus.Locked),
                Item = new BitwardenLoginItem("item-1", "Server", "root", "vault-pw"),
                CompleteStatusAsynchronously = true,
            };
            var resolver = NewResolver(new FakeCredentialService(), bitwarden);
            var promptSawCapturedContext = false;

            var password = await resolver.ReadPasswordAsync(
                new CredentialProfile
                {
                    SecretProvider = CredentialSecretProvider.Bitwarden,
                    BitwardenItemId = "item-1",
                },
                _ =>
                {
                    promptSawCapturedContext = ReferenceEquals(context, SynchronizationContext.Current);
                    return Task.FromResult<string?>("master");
                });

            Assert.Equal("vault-pw", password);
            Assert.True(promptSawCapturedContext);
            Assert.True(context.PostCount > 0);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previousContext);
        }
    }

    [Fact]
    public async Task ReadPasswordAsync_BitwardenAlreadyUnlocked_DoesNotPromptForMasterPassword()
    {
        var bitwarden = new FakeBitwardenClient
        {
            Status = new BitwardenStatus(BitwardenVaultStatus.Unlocked),
            Item = new BitwardenLoginItem("item-1", "Server", "root", "vault-pw"),
        };
        var resolver = NewResolver(new FakeCredentialService(), bitwarden);

        var password = await resolver.ReadPasswordAsync(
            new CredentialProfile
            {
                SecretProvider = CredentialSecretProvider.Bitwarden,
                BitwardenItemId = "item-1",
            },
            _ => throw new InvalidOperationException("Prompt should not be shown for an already unlocked vault."));

        Assert.Equal("vault-pw", password);
        Assert.Null(bitwarden.UnlockPassword);
        Assert.Null(bitwarden.SessionSeenByGet);
    }

    [Fact]
    public async Task ReadPasswordAsync_BitwardenUnlockCancelled_ThrowsCancellation()
    {
        var resolver = NewResolver(new FakeCredentialService(), new FakeBitwardenClient
        {
            Status = new BitwardenStatus(BitwardenVaultStatus.Locked),
        });

        await Assert.ThrowsAsync<BitwardenUnlockCancelledException>(() => resolver.ReadPasswordAsync(
            new CredentialProfile
            {
                SecretProvider = CredentialSecretProvider.Bitwarden,
                BitwardenItemId = "item-1",
            },
            _ => Task.FromResult<string?>(null)));
    }

    private static CredentialPasswordResolver NewResolver(FakeCredentialService local, FakeBitwardenClient bitwarden)
    {
        var settings = new FakeSettings { Current = { EnableBitwardenVault = true } };
        return new CredentialPasswordResolver(
            local,
            bitwarden,
            new BitwardenSessionService(),
            settings,
            NullLogger<CredentialPasswordResolver>.Instance);
    }

    private sealed class FakeSettings : IAppSettingsService
    {
        public AppSettings Current { get; } = new();
        public event EventHandler? SettingsChanged { add { } remove { } }
        public void Save() { }
    }

    private sealed class InlineSynchronizationContext : SynchronizationContext
    {
        public int PostCount { get; private set; }

        public override void Post(SendOrPostCallback d, object? state)
        {
            PostCount++;
            var previous = Current;
            SetSynchronizationContext(this);
            try
            {
                d(state);
            }
            finally
            {
                SetSynchronizationContext(previous);
            }
        }
    }

    private sealed class FakeBitwardenClient : IBitwardenVaultClient
    {
        public BitwardenStatus Status { get; set; } = new(BitwardenVaultStatus.Unlocked);
        public BitwardenLoginItem? Item { get; set; }
        public string? UnlockPassword { get; private set; }
        public string? SessionSeenByGet { get; private set; }
        public bool CompleteStatusAsynchronously { get; set; }

        public Task<BitwardenStatus> GetStatusAsync(CancellationToken cancellationToken = default) =>
            CompleteStatusAsynchronously
                ? Task.Run(() => Status, cancellationToken)
                : Task.FromResult(Status);

        public Task<string> UnlockAsync(string masterPassword, CancellationToken cancellationToken = default)
        {
            UnlockPassword = masterPassword;
            return Task.FromResult("SESSION");
        }

        public Task<string> LoginAsync(
            string email,
            string masterPassword,
            string? authenticatorCode = null,
            BitwardenCliServerRegion serverRegion = BitwardenCliServerRegion.UnitedStates,
            CancellationToken cancellationToken = default) =>
            Task.FromResult("SESSION");

        public Task<IReadOnlyList<BitwardenLoginItem>> ListLoginItemsAsync(string? sessionKey, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<BitwardenLoginItem>>(Array.Empty<BitwardenLoginItem>());

        public Task<IReadOnlyList<BitwardenLoginItem>> SearchLoginItemsAsync(string query, string? sessionKey, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<BitwardenLoginItem>>(Array.Empty<BitwardenLoginItem>());

        public Task<BitwardenLoginItem?> GetLoginItemAsync(string itemId, string? sessionKey, CancellationToken cancellationToken = default)
        {
            SessionSeenByGet = sessionKey;
            return Task.FromResult(Item);
        }

        public Task SyncAsync(string? sessionKey, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
