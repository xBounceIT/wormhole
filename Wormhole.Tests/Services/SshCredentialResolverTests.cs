using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;
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
    public async Task Resolve_NoCredentialId_PassesCancellationToken_ToPasswordPrompt()
    {
        var dialogs = new FakeDialogService { PasswordPromptResult = "prompted-pwd" };
        var resolver = NewResolver(dialogs);
        using var cts = new CancellationTokenSource();

        await resolver.ResolveAsync(MakeProfile(credentialId: null), cts.Token);

        Assert.Equal(cts.Token, dialogs.LastPasswordPromptCancellationToken);
    }

    [Fact]
    public async Task Resolve_NoCredentialId_PromptCancelled_ThrowsUserCancellation()
    {
        var resolver = NewResolver(new FakeDialogService());

        await Assert.ThrowsAsync<UserInteractionCancelledException>(
            () => resolver.ResolveAsync(MakeProfile(credentialId: null)));
    }

    [Fact]
    public async Task Resolve_NoCredentialId_SelectedSavedCredential_UsesCredentialPasswordAndUsername()
    {
        var credential = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Protocol = ProtocolType.Ssh,
            Kind = CredentialKind.Password,
            Username = "saved-user",
        };
        var bindings = new FakeConnectionCredentialBindingService();
        var dialogs = new FakeDialogService
        {
            AccountCredentialPromptResult = new AccountCredentialPromptResult(
                credential.Username,
                "stored-pwd",
                credential,
                SaveCredentialToConnection: false),
        };
        var resolver = NewResolver(dialogs, credentialBindings: bindings);

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: null));

        Assert.Equal("stored-pwd", creds.Password);
        Assert.Equal("saved-user", creds.UsernameOverride);
        Assert.Equal(1, dialogs.AccountCredentialPromptCount);
        Assert.Equal(ProtocolType.Ssh, dialogs.LastAccountCredentialPromptProtocol);
        Assert.Equal(0, bindings.SaveCount);
    }

    [Fact]
    public async Task Resolve_NoCredentialId_SelectedSavedCredential_WithSave_PersistsBinding()
    {
        var nodeId = Guid.NewGuid();
        var credential = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "prod",
            Protocol = ProtocolType.Ssh,
            Kind = CredentialKind.Password,
            Username = "saved-user",
        };
        var bindings = new FakeConnectionCredentialBindingService();
        var dialogs = new FakeDialogService
        {
            AccountCredentialPromptResult = new AccountCredentialPromptResult(
                credential.Username,
                "stored-pwd",
                credential,
                SaveCredentialToConnection: true),
        };
        var resolver = NewResolver(dialogs, credentialBindings: bindings);

        await resolver.ResolveAsync(MakeProfile(credentialId: null, nodeId: nodeId));

        Assert.Equal(1, bindings.SaveCount);
        Assert.Equal(nodeId, bindings.LastNodeId);
        Assert.Same(credential, bindings.LastCredential);
    }

    [Fact]
    public async Task Resolve_NoCredentialId_ManualPassword_WithSave_PersistsInlinePassword()
    {
        var nodeId = Guid.NewGuid();
        var bindings = new FakeConnectionCredentialBindingService();
        var dialogs = new FakeDialogService
        {
            AccountCredentialPromptResult = new AccountCredentialPromptResult(
                "typed-user",
                "typed-pwd",
                SelectedCredential: null,
                SaveCredentialToConnection: true),
        };
        var resolver = NewResolver(dialogs, credentialBindings: bindings);

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: null, nodeId: nodeId) with { Username = null });

        Assert.Equal("typed-pwd", creds.Password);
        Assert.Equal("typed-user", creds.UsernameOverride);
        Assert.Equal(0, bindings.SaveCount);
        Assert.Equal(1, bindings.SaveInlineCount);
        Assert.Equal(nodeId, bindings.LastNodeId);
        Assert.Equal("typed-pwd", bindings.LastInlinePassword);
        Assert.Equal("typed-user", bindings.LastInlineUsername);
    }

    [Fact]
    public async Task Resolve_PasswordCredential_Stored_NoPrompt()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService();
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile
            {
                Id = credId,
                Kind = CredentialKind.Password,
                Username = "credential-user",
            }),
            creds: new FakeCredentialService(passwords: new() { [credId] = "stored-pwd" }));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Equal("stored-pwd", creds.Password);
        Assert.Null(creds.PrivateKey);
        Assert.Equal("credential-user", creds.CredentialUsername);
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
    public async Task Resolve_PasswordCredentialWithNonSshProtocol_PromptsWithoutUsingCredential()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService { PasswordPromptResult = "typed-pwd" };
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile
            {
                Id = credId,
                Protocol = ProtocolType.Vnc,
                Kind = CredentialKind.Password,
                Username = "vnc-user",
            }),
            creds: new FakeCredentialService(passwords: new() { [credId] = "vnc-secret" }));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Equal("typed-pwd", creds.Password);
        Assert.Null(creds.CredentialUsername);
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
            repo: new FakeCredentialRepository(new CredentialProfile
            {
                Id = credId,
                Kind = CredentialKind.SshKey,
                Username = "key-user",
            }),
            creds: new FakeCredentialService(keys: new() { [credId] = keyBytes }),
            inspector: new FakePrivateKeyInspector(isEncrypted: false));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

        Assert.Equal(keyBytes, creds.PrivateKey);
        Assert.Null(creds.Password);
        Assert.Null(creds.KeyPassphrase);
        Assert.Equal("key-user", creds.CredentialUsername);
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

    [Fact]
    public async Task Resolve_KeyCredential_ReadsKeyAndStoredPassphraseConcurrently()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService();
        var service = new ConcurrentKeyCredentialService(new byte[] { 9, 9 }, "passphrase");
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.SshKey }),
            creds: service,
            inspector: new FakePrivateKeyInspector(isEncrypted: true));

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credId));

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
        Assert.Equal(0, dialogs.AccountCredentialPromptCount);
    }

    [Fact]
    public async Task Resolve_KeyCredential_EncryptedKey_PassphrasePromptCancelled_ThrowsUserCancellation()
    {
        var credId = Guid.NewGuid();
        var dialogs = new FakeDialogService();
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile { Id = credId, Kind = CredentialKind.SshKey }),
            creds: new FakeCredentialService(keys: new() { [credId] = new byte[] { 1, 2, 3 } }),
            inspector: new FakePrivateKeyInspector(isEncrypted: true));

        await Assert.ThrowsAsync<UserInteractionCancelledException>(
            () => resolver.ResolveAsync(MakeProfile(credentialId: credId)));
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

    [Fact]
    public async Task Resolve_InlinePassword_Stored_ReturnsItWithoutPrompt()
    {
        var nodeId = Guid.NewGuid();
        var dialogs = new FakeDialogService();
        var resolver = NewResolver(
            dialogs,
            creds: new FakeCredentialService(passwords: new() { [nodeId] = "inline-pwd" }));

        var creds = await resolver.ResolveAsync(
            MakeProfile(credentialId: null, useInlinePassword: true, nodeId: nodeId));

        Assert.Equal("inline-pwd", creds.Password);
        Assert.Null(creds.PrivateKey);
        Assert.Equal(0, dialogs.PasswordPromptCount);
    }

    [Fact]
    public async Task Resolve_InlinePassword_SecretMissing_FallsBackToPrompt()
    {
        // Flag set but no Credential Manager entry (e.g. DB restored without the local secret) —
        // prompt rather than failing the connect opaquely.
        var dialogs = new FakeDialogService { PasswordPromptResult = "typed-pwd" };
        var resolver = NewResolver(dialogs);

        var creds = await resolver.ResolveAsync(
            MakeProfile(credentialId: null, useInlinePassword: true, nodeId: Guid.NewGuid()));

        Assert.Equal("typed-pwd", creds.Password);
        Assert.Equal(1, dialogs.PasswordPromptCount);
    }

    [Fact]
    public async Task Resolve_InlinePassword_EmptyStored_FallsBackToPrompt()
    {
        // An empty stored secret must be treated like a missing one (it yields no auth method),
        // matching the saved-credential password branch — prompt rather than fail the connect.
        var nodeId = Guid.NewGuid();
        var dialogs = new FakeDialogService { PasswordPromptResult = "typed-pwd" };
        var resolver = NewResolver(
            dialogs,
            creds: new FakeCredentialService(passwords: new() { [nodeId] = "" }));

        var creds = await resolver.ResolveAsync(
            MakeProfile(credentialId: null, useInlinePassword: true, nodeId: nodeId));

        Assert.Equal("typed-pwd", creds.Password);
        Assert.Equal(1, dialogs.PasswordPromptCount);
    }

    [Fact]
    public async Task Resolve_BitwardenCredentialUnavailable_FallsBackToPrompt()
    {
        var credentialId = Guid.NewGuid();
        var dialogs = new FakeDialogService { PasswordPromptResult = "typed-pwd" };
        var resolver = NewResolver(
            dialogs,
            repo: new FakeCredentialRepository(new CredentialProfile
            {
                Id = credentialId,
                Protocol = ProtocolType.Ssh,
                Kind = CredentialKind.Password,
                Username = "alice",
                SecretProvider = CredentialSecretProvider.Bitwarden,
                BitwardenItemId = "missing-item",
            }),
            passwordResolver: new ThrowingPasswordResolver());

        var creds = await resolver.ResolveAsync(MakeProfile(credentialId: credentialId));

        Assert.Equal("typed-pwd", creds.Password);
        Assert.Equal(1, dialogs.PasswordPromptCount);
    }

    [Fact]
    public async Task Resolve_EphemeralProfile_UsesTransientPasswordWithoutPromptOrCredentialManager()
    {
        var nodeId = Guid.NewGuid();
        var store = new TransientSessionCredentialStore();
        store.Store(nodeId, "session-only");
        var dialogs = new FakeDialogService();
        var resolver = NewResolver(dialogs, transientCredentials: store);

        var credentials = await resolver.ResolveAsync(
            MakeProfile(credentialId: null, nodeId: nodeId, isEphemeral: true));

        Assert.Equal("session-only", credentials.Password);
        Assert.Equal(0, dialogs.AccountCredentialPromptCount);
    }

    [Fact]
    public async Task Resolve_EphemeralTransientPasswordWithoutUsername_PromptsForIdentity()
    {
        var nodeId = Guid.NewGuid();
        var store = new TransientSessionCredentialStore();
        store.Store(nodeId, "session-only");
        var dialogs = new FakeDialogService
        {
            AccountCredentialPromptResult = new AccountCredentialPromptResult(
                "prompted-user",
                "prompted-password",
                SelectedCredential: null,
                SaveCredentialToConnection: false),
        };
        var resolver = NewResolver(dialogs, transientCredentials: store);
        var profile = MakeProfile(credentialId: null, nodeId: nodeId, isEphemeral: true) with
        {
            Username = null,
        };

        var credentials = await resolver.ResolveAsync(profile);

        Assert.True(dialogs.LastAccountCredentialPromptRequiredUsername);
        Assert.Equal("prompted-user", credentials.ResolveUsername(profile));
        Assert.Equal("prompted-password", credentials.Password);
        Assert.Equal("prompted-password", store.Read(nodeId));

        var reconnected = await resolver.ResolveAsync(profile with { Username = "prompted-user" });

        Assert.Equal("prompted-password", reconnected.Password);
        Assert.Equal(1, dialogs.AccountCredentialPromptCount);
    }

    [Fact]
    public async Task Resolve_EphemeralPrompt_NeverPersistsSelectedCredentialBinding()
    {
        var credential = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Protocol = ProtocolType.Ssh,
            Kind = CredentialKind.Password,
            Username = "saved-user",
        };
        var dialogs = new FakeDialogService
        {
            AccountCredentialPromptResult = new AccountCredentialPromptResult(
                credential.Username,
                "prompted",
                credential,
                SaveCredentialToConnection: true),
        };
        var bindings = new FakeConnectionCredentialBindingService();
        var resolver = NewResolver(dialogs, credentialBindings: bindings);

        await resolver.ResolveAsync(MakeProfile(credentialId: null, isEphemeral: true));

        Assert.Equal(0, bindings.SaveCount);
        Assert.Equal(0, bindings.SaveInlineCount);
    }

    [Fact]
    public async Task Resolve_EphemeralPrompt_NeverPersistsManualInlinePassword()
    {
        var dialogs = new FakeDialogService
        {
            AccountCredentialPromptResult = new AccountCredentialPromptResult(
                "typed-user",
                "prompted",
                SelectedCredential: null,
                SaveCredentialToConnection: true),
        };
        var bindings = new FakeConnectionCredentialBindingService();
        var resolver = NewResolver(dialogs, credentialBindings: bindings);

        await resolver.ResolveAsync(MakeProfile(credentialId: null, isEphemeral: true) with { Username = null });

        Assert.Equal(0, bindings.SaveCount);
        Assert.Equal(0, bindings.SaveInlineCount);
    }

    [Fact]
    public async Task Resolve_MissingUsername_RequiresAndUsesPromptedUsername()
    {
        var dialogs = new FakeDialogService
        {
            AccountCredentialPromptResult = new AccountCredentialPromptResult(
                "prompted-user",
                "prompted-password",
                SelectedCredential: null,
                SaveCredentialToConnection: false),
        };
        var resolver = NewResolver(dialogs);
        var profile = MakeProfile(credentialId: null, isEphemeral: true) with { Username = null };

        var credentials = await resolver.ResolveAsync(profile);

        Assert.True(dialogs.LastAccountCredentialPromptRequiredUsername);
        Assert.Null(dialogs.LastAccountCredentialPromptInitialUsername);
        Assert.Equal("prompted-user", credentials.ResolveUsername(profile));
        Assert.Equal("prompted-password", credentials.Password);
    }

    private static SshCredentialResolver NewResolver(
        FakeDialogService dialogs,
        FakeCredentialRepository? repo = null,
        ICredentialService? creds = null,
        FakePrivateKeyInspector? inspector = null,
        IConnectionCredentialBindingService? credentialBindings = null,
        ICredentialPasswordResolver? passwordResolver = null,
        ITransientSessionCredentialStore? transientCredentials = null)
    {
        creds ??= new FakeCredentialService();
        return new SshCredentialResolver(
            repo ?? new FakeCredentialRepository(),
            creds,
            passwordResolver ?? new FakeCredentialPasswordResolver(creds),
            credentialBindings ?? new FakeConnectionCredentialBindingService(),
            dialogs,
            inspector ?? new FakePrivateKeyInspector(),
            transientCredentials);
    }

    private static ConnectionProfile MakeProfile(
        Guid? credentialId,
        bool useInlinePassword = false,
        Guid? nodeId = null,
        bool isEphemeral = false)
        => new()
        {
            NodeId = nodeId ?? Guid.NewGuid(),
            Name = "test",
            Protocol = ProtocolType.Ssh,
            Host = "host.example",
            Port = 22,
            Username = "alice",
            CredentialId = credentialId,
            UseInlinePassword = useInlinePassword,
            IsEphemeral = isEphemeral,
        };

    private sealed class ThrowingPasswordResolver : ICredentialPasswordResolver
    {
        public Task<string?> ReadPasswordAsync(
            CredentialProfile credential,
            BitwardenUnlockPrompt? unlockPrompt = null,
            CancellationToken cancellationToken = default) =>
            throw new BitwardenVaultException("missing item");
    }
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

    private sealed class ConcurrentKeyCredentialService : ICredentialService
    {
        private readonly byte[] _key;
        private readonly string _passphrase;
        private readonly TaskCompletionSource _passwordReadStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ConcurrentKeyCredentialService(byte[] key, string passphrase)
        {
            _key = key;
            _passphrase = passphrase;
        }

        public Task StorePasswordAsync(Guid credentialId, string password) => throw new NotImplementedException();

        public Task<string?> ReadPasswordAsync(Guid credentialId)
        {
            _passwordReadStarted.TrySetResult();
            return Task.FromResult<string?>(_passphrase);
        }

        public Task DeletePasswordAsync(Guid credentialId) => throw new NotImplementedException();
        public Task StorePrivateKeyAsync(Guid credentialId, byte[] privateKeyBytes) => throw new NotImplementedException();

        public async Task<byte[]?> ReadPrivateKeyAsync(Guid credentialId)
        {
            await _passwordReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));
            return (byte[])_key.Clone();
        }

        public Task DeletePrivateKeyAsync(Guid credentialId) => throw new NotImplementedException();
        public Task StoreTunnelConfigAsync(Guid tunnelConfigId, byte[] configBytes) => throw new NotImplementedException();
        public Task<byte[]?> ReadTunnelConfigAsync(Guid tunnelConfigId) => throw new NotImplementedException();
        public Task DeleteTunnelConfigAsync(Guid tunnelConfigId) => throw new NotImplementedException();
    }
}
