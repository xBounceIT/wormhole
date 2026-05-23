using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Ssh;
using Wormhole.Tests.Fakes;
using Xunit;

namespace Wormhole.Tests.Services;

public class SshCredentialResolverTests
{
    [Fact]
    public async Task Resolve_NoCredentialId_PromptsForPassword()
    {
        var dialogs = new FakeDialogService { PasswordPromptResult = "prompted-pwd" };
        var resolver = NewResolver(dialogs);

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: null));

        Assert.Equal("prompted-pwd", creds.Password);
        Assert.Null(creds.PrivateKey);
        Assert.Equal(1, dialogs.PasswordPromptCount);
    }

    [Fact]
    public async Task Resolve_NoCredentialId_PromptCancelled_ReturnsEmpty()
    {
        var resolver = NewResolver(new FakeDialogService());

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: null));

        Assert.False(creds.HasAny);
    }

    [Fact]
    public async Task Resolve_PasswordCredential_Stored_NoPrompt()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService();
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.Password }),
            creds: new FakeCredentialService(passwords: new() { [credId] = "stored-pwd" }));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Equal("stored-pwd", creds.Password);
        Assert.Null(creds.PrivateKey);
        Assert.Equal(0, dialogs.PasswordPromptCount);
    }

    [Fact]
    public async Task Resolve_PasswordCredential_NotStored_Prompts()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService { PasswordPromptResult = "typed-pwd" };
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.Password }));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Equal("typed-pwd", creds.Password);
        Assert.Equal(1, dialogs.PasswordPromptCount);
    }

    [Fact]
    public async Task Resolve_KeyCredential_KeyPresent_NotEncrypted_ReturnsKey_NoPrompt()
    {
        var credId = Guid.NewGuid();
        var keyBytes = new byte[] { 1, 2, 3 };
        var dialogs = new FakeDialogService();
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.SshKey }),
            creds: new FakeCredentialService(keys: new() { [credId] = keyBytes }),
            inspector: new FakePrivateKeyInspector(isEncrypted: false));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Equal(keyBytes, creds.PrivateKey);
        Assert.Null(creds.Password);
        Assert.Null(creds.KeyPassphrase);
        Assert.Equal(0, dialogs.PasswordPromptCount);
    }

    // Regression: previously the passphrase landed in Password, so a failed key auth would
    // cause SSH.NET to send the passphrase as a login attempt. Must stay in KeyPassphrase only.
    [Fact]
    public async Task Resolve_KeyCredential_WithStoredPassphrase_PassesPassphraseAsKeyPassphraseOnly()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService();
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.SshKey }),
            creds: new FakeCredentialService(
                keys: new() { [credId] = new byte[] { 9, 9 } },
                passwords: new() { [credId] = "passphrase" }),
            inspector: new FakePrivateKeyInspector(isEncrypted: true));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Null(creds.Password);
        Assert.Equal("passphrase", creds.KeyPassphrase);
        Assert.NotNull(creds.PrivateKey);
    }

    // Encrypted key with no stored passphrase must prompt — not silently return null
    // and let SshSessionService throw later.
    [Fact]
    public async Task Resolve_KeyCredential_EncryptedKeyNoPassphrase_PromptsAndUsesResult()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService { PasswordPromptResult = "typed-passphrase" };
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.SshKey }),
            creds: new FakeCredentialService(keys: new() { [credId] = new byte[] { 1, 2, 3 } }),
            inspector: new FakePrivateKeyInspector(isEncrypted: true));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Null(creds.Password);
        Assert.Equal("typed-passphrase", creds.KeyPassphrase);
        Assert.NotNull(creds.PrivateKey);
        Assert.Equal(1, dialogs.PasswordPromptCount);
    }

    [Fact]
    public async Task Resolve_KeyCredential_EncryptedKey_PassphrasePromptCancelled_ReturnsEmpty()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService();
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.SshKey }),
            creds: new FakeCredentialService(keys: new() { [credId] = new byte[] { 1, 2, 3 } }),
            inspector: new FakePrivateKeyInspector(isEncrypted: true));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.False(creds.HasAny);
    }

    [Fact]
    public async Task Resolve_KeyCredential_KeyMissing_FallsBackToPasswordPrompt()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService { PasswordPromptResult = "fallback-pwd" };
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.SshKey }));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Equal("fallback-pwd", creds.Password);
        Assert.Null(creds.PrivateKey);
    }

    [Fact]
    public async Task Resolve_CredentialIdSet_ButNotInRepo_Prompts()
    {
        var resolver = NewResolver(new FakeDialogService { PasswordPromptResult = "guessed-pwd" });

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: Guid.NewGuid()));

        Assert.Equal("guessed-pwd", creds.Password);
    }

    private static SshCredentialResolver NewResolver(
        FakeDialogService dialogs,
        FakeCredentialRepository? repo = null,
        FakeCredentialService? creds = null,
        FakePrivateKeyInspector? inspector = null)
        => new(
            repo ?? new FakeCredentialRepository(),
            creds ?? new FakeCredentialService(),
            dialogs,
            inspector ?? new FakePrivateKeyInspector());

    private static ConnectionProfile MakeProfile(Guid? credentialId)
        => new()
        {
            NodeId = Guid.NewGuid(),
            Name = "test",
            Protocol = ProtocolType.Ssh,
            Host = "host.example",
            Port = 22,
            Username = "alice",
            CredentialId = credentialId,
        };

    private sealed class FakeCredentialRepository : ICredentialRepository
    {
        private readonly Dictionary<Guid, CredentialProfile> _byId;

        public FakeCredentialRepository(params CredentialProfile[] profiles)
        {
            _byId = new Dictionary<Guid, CredentialProfile>();
            foreach (var p in profiles) _byId[p.Id] = p;
        }

        public Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
            => throw new NotImplementedException();
        public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult(_byId.TryGetValue(id, out var p) ? p : null);
        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default)
            => throw new NotImplementedException();
        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default)
            => throw new NotImplementedException();
        public Task DeleteAsync(Guid id, CancellationToken ct = default)
            => throw new NotImplementedException();
    }

    private sealed class FakePrivateKeyInspector : IPrivateKeyInspector
    {
        private readonly bool _isEncrypted;
        public FakePrivateKeyInspector(bool isEncrypted = false) { _isEncrypted = isEncrypted; }
        public bool IsEncrypted(byte[] keyBytes) => _isEncrypted;
    }
}
