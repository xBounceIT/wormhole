using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Tests.Fakes;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class CredentialsViewModelTests
{
    [Fact]
    public async Task LoadAsync_populates_collection_from_repository()
    {
        var repo = new FakeCredentialRepository(
            MakeProfile("alpha", ProtocolType.Ssh),
            MakeProfile("beta", ProtocolType.Rdp, domain: "WORK"));
        var vm = NewVm(repo);

        await vm.LoadCommand.ExecuteAsync(null);

        Assert.Equal(2, vm.Credentials.Count);
        Assert.False(vm.IsEmpty);
        Assert.Contains(vm.Credentials, c => c.Name == "alpha");
        Assert.Contains(vm.Credentials, c => c.Name == "beta");
    }

    [Fact]
    public async Task LoadAsync_failure_shows_message_and_leaves_collection_empty()
    {
        var repo = new FakeCredentialRepository { GetAllShouldThrow = true };
        var dialog = new FakeDialogService();
        var vm = NewVm(repo, dialog: dialog);

        await vm.LoadCommand.ExecuteAsync(null);

        Assert.True(vm.IsEmpty);
        Assert.Single(dialog.Messages);
        Assert.Equal("Couldn't load credentials", dialog.Messages[0].title);
    }

    [Fact]
    public async Task AddCredentialAsync_does_nothing_when_dialog_cancelled()
    {
        var repo = new FakeCredentialRepository();
        var dialog = new FakeDialogService { CredentialPromptResult = null };
        var vm = NewVm(repo, dialog: dialog);

        await vm.AddCredentialCommand.ExecuteAsync(null);

        Assert.Empty(repo.Profiles);
    }

    [Fact]
    public async Task AddCredentialAsync_persists_draft_and_stores_password()
    {
        var repo = new FakeCredentialRepository();
        var credService = new FakeCredentialService();
        var dialog = new FakeDialogService
        {
            CredentialPromptResult = new CredentialDraft("ssh-prod", ProtocolType.Ssh, "alice", null, "hunter2"),
        };
        var vm = NewVm(repo, credService, dialog);

        await vm.AddCredentialCommand.ExecuteAsync(null);

        var added = Assert.Single(repo.Profiles);
        Assert.Equal("ssh-prod", added.Name);
        Assert.Equal("alice", added.Username);
        Assert.Null(added.Domain);
        Assert.Equal(ProtocolType.Ssh, added.Protocol);
        Assert.Equal(CredentialKind.Password, added.Kind);
        Assert.Equal("hunter2", credService.Passwords[added.Id]);
        Assert.Single(vm.Credentials);
    }

    [Fact]
    public async Task AddCredentialAsync_blocks_duplicate_name_case_insensitively()
    {
        var repo = new FakeCredentialRepository(MakeProfile("PROD", ProtocolType.Ssh));
        var dialog = new FakeDialogService
        {
            CredentialPromptResult = new CredentialDraft("prod", ProtocolType.Rdp, "bob", "WORK", "pw"),
        };
        var vm = NewVm(repo, dialog: dialog);
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.AddCredentialCommand.ExecuteAsync(null);

        Assert.Single(repo.Profiles);
        Assert.Contains(dialog.Messages, m => m.title == "Name already in use");
    }

    [Fact]
    public async Task EditCredentialAsync_returns_silently_for_null_profile()
    {
        var vm = NewVm(new FakeCredentialRepository());

        await vm.EditCredentialCommand.ExecuteAsync(null);
        // No exception, no state change — success.
    }

    [Fact]
    public async Task EditCredentialAsync_blocks_ssh_key_credentials()
    {
        var key = MakeProfile("key", ProtocolType.Ssh, kind: CredentialKind.SshKey);
        var dialog = new FakeDialogService();
        var vm = NewVm(new FakeCredentialRepository(key), dialog: dialog);

        await vm.EditCredentialCommand.ExecuteAsync(key);

        Assert.Single(dialog.Messages);
        Assert.Equal("Can't edit here", dialog.Messages[0].title);
        Assert.Equal(0, dialog.CredentialPromptCallCount);
    }

    [Fact]
    public async Task EditCredentialAsync_updates_persisted_row_and_password()
    {
        var existing = MakeProfile("old", ProtocolType.Ssh, username: "u1");
        var repo = new FakeCredentialRepository(existing);
        var credService = new FakeCredentialService();
        credService.Passwords[existing.Id] = "oldpw";
        var dialog = new FakeDialogService
        {
            CredentialPromptResult = new CredentialDraft("new", ProtocolType.Rdp, "u2", "WORK", "newpw"),
        };
        var vm = NewVm(repo, credService, dialog);
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.EditCredentialCommand.ExecuteAsync(existing);

        var updated = Assert.Single(repo.Profiles);
        Assert.Equal(existing.Id, updated.Id);
        Assert.Equal("new", updated.Name);
        Assert.Equal("u2", updated.Username);
        Assert.Equal("WORK", updated.Domain);
        Assert.Equal(ProtocolType.Rdp, updated.Protocol);
        Assert.Equal("newpw", credService.Passwords[existing.Id]);
    }

    [Fact]
    public async Task EditCredentialAsync_passes_stored_password_into_dialog_prefill()
    {
        var existing = MakeProfile("p", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(existing);
        var credService = new FakeCredentialService();
        credService.Passwords[existing.Id] = "stored-pw";
        var dialog = new FakeDialogService
        {
            CredentialPromptResult = new CredentialDraft("p", ProtocolType.Ssh, "u", null, "stored-pw"),
        };
        var vm = NewVm(repo, credService, dialog);

        await vm.EditCredentialCommand.ExecuteAsync(existing);

        Assert.NotNull(dialog.LastCredentialPromptInitial);
        Assert.Equal("stored-pw", dialog.LastCredentialPromptInitial!.Password);
    }

    [Fact]
    public async Task EditCredentialAsync_prefills_empty_password_when_secret_missing()
    {
        var existing = MakeProfile("p", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(existing);
        var credService = new FakeCredentialService();
        // No password registered for this credential.
        var dialog = new FakeDialogService { CredentialPromptResult = null };
        var vm = NewVm(repo, credService, dialog);

        await vm.EditCredentialCommand.ExecuteAsync(existing);

        Assert.NotNull(dialog.LastCredentialPromptInitial);
        Assert.Equal(string.Empty, dialog.LastCredentialPromptInitial!.Password);
    }

    [Fact]
    public async Task EditCredentialAsync_blocks_rename_to_existing_other_name()
    {
        var first = MakeProfile("first", ProtocolType.Ssh);
        var second = MakeProfile("second", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(first, second);
        var dialog = new FakeDialogService
        {
            CredentialPromptResult = new CredentialDraft("FIRST", ProtocolType.Ssh, "u", null, "pw"),
        };
        var vm = NewVm(repo, dialog: dialog);
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.EditCredentialCommand.ExecuteAsync(second);

        Assert.Equal("second", repo.Profiles.Single(p => p.Id == second.Id).Name);
        Assert.Contains(dialog.Messages, m => m.title == "Name already in use");
    }

    [Fact]
    public async Task EditCredentialAsync_allows_keeping_same_name()
    {
        var existing = MakeProfile("keep", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(existing);
        var dialog = new FakeDialogService
        {
            CredentialPromptResult = new CredentialDraft("keep", ProtocolType.Ssh, "new-user", null, "pw"),
        };
        var vm = NewVm(repo, dialog: dialog);
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.EditCredentialCommand.ExecuteAsync(existing);

        var updated = Assert.Single(repo.Profiles);
        Assert.Equal("keep", updated.Name);
        Assert.Equal("new-user", updated.Username);
    }

    [Fact]
    public async Task DeleteCredentialAsync_removes_row_and_password_when_confirmed()
    {
        var profile = MakeProfile("doomed", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(profile);
        var credService = new FakeCredentialService();
        credService.Passwords[profile.Id] = "pw";
        var dialog = new FakeDialogService { ConfirmResult = true };
        var vm = NewVm(repo, credService, dialog);
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.DeleteCredentialCommand.ExecuteAsync(profile);

        Assert.Empty(repo.Profiles);
        Assert.False(credService.Passwords.ContainsKey(profile.Id));
        Assert.Empty(vm.Credentials);
    }

    [Fact]
    public async Task DeleteCredentialAsync_keeps_row_when_user_declines()
    {
        var profile = MakeProfile("safe", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(profile);
        var dialog = new FakeDialogService { ConfirmResult = false };
        var vm = NewVm(repo, dialog: dialog);
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.DeleteCredentialCommand.ExecuteAsync(profile);

        Assert.Single(repo.Profiles);
    }

    [Fact]
    public async Task DeleteCredentialAsync_also_removes_profile_from_selection()
    {
        // Regression test: Codex caught that a successful single-delete was leaving the
        // deleted profile in SelectedCredentials, stranding HasSelection/SelectedCount.
        var profile = MakeProfile("doomed", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(profile);
        var dialog = new FakeDialogService { ConfirmResult = true };
        var vm = NewVm(repo, dialog: dialog);
        await vm.LoadCommand.ExecuteAsync(null);
        vm.SelectedCredentials.Add(profile);

        await vm.DeleteCredentialCommand.ExecuteAsync(profile);

        Assert.Empty(vm.SelectedCredentials);
        Assert.False(vm.HasSelection);
        Assert.Equal(0, vm.SelectedCount);
    }

    [Fact]
    public async Task LoadAsync_clears_selection_so_singleton_VM_drops_stale_references()
    {
        var profile = MakeProfile("ghost", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(profile);
        var vm = NewVm(repo);
        await vm.LoadCommand.ExecuteAsync(null);
        vm.SelectedCredentials.Add(vm.Credentials.Single());

        await vm.LoadCommand.ExecuteAsync(null);

        Assert.Empty(vm.SelectedCredentials);
    }

    [Fact]
    public async Task DeleteSelectedAsync_does_nothing_when_selection_empty()
    {
        var profile = MakeProfile("untouched", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(profile);
        var dialog = new FakeDialogService { ConfirmResult = true };
        var vm = NewVm(repo, dialog: dialog);
        await vm.LoadCommand.ExecuteAsync(null);

        await vm.DeleteSelectedCommand.ExecuteAsync(null);

        Assert.Single(repo.Profiles);
        Assert.Empty(dialog.Messages); // no confirmation prompt counted as a Message, but also nothing surfaced
    }

    [Fact]
    public async Task DeleteSelectedAsync_does_nothing_when_user_declines()
    {
        var a = MakeProfile("a", ProtocolType.Ssh);
        var b = MakeProfile("b", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(a, b);
        var dialog = new FakeDialogService { ConfirmResult = false };
        var vm = NewVm(repo, dialog: dialog);
        await vm.LoadCommand.ExecuteAsync(null);
        foreach (var p in vm.Credentials) vm.SelectedCredentials.Add(p);

        await vm.DeleteSelectedCommand.ExecuteAsync(null);

        Assert.Equal(2, repo.Profiles.Count);
        Assert.Equal(2, vm.SelectedCredentials.Count); // selection preserved on cancel
    }

    [Fact]
    public async Task DeleteSelectedAsync_deletes_all_selected_and_clears_selection()
    {
        var keep = MakeProfile("keep", ProtocolType.Ssh);
        var doomedA = MakeProfile("doomedA", ProtocolType.Rdp);
        var doomedB = MakeProfile("doomedB", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(keep, doomedA, doomedB);
        var credService = new FakeCredentialService();
        credService.Passwords[doomedA.Id] = "pwA";
        credService.Passwords[doomedB.Id] = "pwB";
        credService.Passwords[keep.Id] = "pwKeep";
        var dialog = new FakeDialogService { ConfirmResult = true };
        var vm = NewVm(repo, credService, dialog);
        await vm.LoadCommand.ExecuteAsync(null);
        vm.SelectedCredentials.Add(vm.Credentials.Single(p => p.Id == doomedA.Id));
        vm.SelectedCredentials.Add(vm.Credentials.Single(p => p.Id == doomedB.Id));

        await vm.DeleteSelectedCommand.ExecuteAsync(null);

        Assert.Single(repo.Profiles); // only `keep` survives
        Assert.Equal(keep.Id, repo.Profiles[0].Id);
        Assert.False(credService.Passwords.ContainsKey(doomedA.Id));
        Assert.False(credService.Passwords.ContainsKey(doomedB.Id));
        Assert.True(credService.Passwords.ContainsKey(keep.Id));
        Assert.Empty(vm.SelectedCredentials);
        Assert.Single(vm.Credentials);
    }

    [Fact]
    public async Task DeleteSelectedAsync_continues_after_per_item_failure_and_surfaces_summary()
    {
        var ok = MakeProfile("ok", ProtocolType.Ssh);
        var bad = MakeProfile("bad", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(ok, bad);
        repo.DeleteShouldThrowForIds.Add(bad.Id);
        var dialog = new FakeDialogService { ConfirmResult = true };
        var vm = NewVm(repo, dialog: dialog);
        await vm.LoadCommand.ExecuteAsync(null);
        foreach (var p in vm.Credentials) vm.SelectedCredentials.Add(p);

        await vm.DeleteSelectedCommand.ExecuteAsync(null);

        Assert.Single(repo.Profiles); // only `bad` remains — `ok` succeeded
        Assert.Equal(bad.Id, repo.Profiles[0].Id);
        Assert.Single(vm.Credentials); // mirror
        Assert.Contains(dialog.Messages, m => m.title == "Couldn't delete some credentials");
        Assert.Contains(dialog.Messages, m => m.message.Contains("'bad'"));
        Assert.Empty(vm.SelectedCredentials); // selection drained even with partial failure
    }

    [Fact]
    public async Task SelectionStatus_and_HasSelection_track_selection_changes()
    {
        var a = MakeProfile("a", ProtocolType.Ssh);
        var b = MakeProfile("b", ProtocolType.Ssh);
        var repo = new FakeCredentialRepository(a, b);
        var vm = NewVm(repo);
        await vm.LoadCommand.ExecuteAsync(null);

        Assert.False(vm.HasSelection);
        Assert.Equal(0, vm.SelectedCount);
        Assert.Equal("0 selected", vm.SelectionStatus);

        vm.SelectedCredentials.Add(vm.Credentials.First());
        Assert.True(vm.HasSelection);
        Assert.Equal(1, vm.SelectedCount);
        Assert.Equal("1 selected", vm.SelectionStatus);

        vm.SelectedCredentials.Add(vm.Credentials.Last());
        Assert.Equal(2, vm.SelectedCount);
        Assert.Equal("2 selected", vm.SelectionStatus);

        vm.SelectedCredentials.Clear();
        Assert.False(vm.HasSelection);
        Assert.Equal("0 selected", vm.SelectionStatus);
    }

    [Fact]
    public async Task HasNoMatches_is_true_when_search_filters_everything_out()
    {
        var repo = new FakeCredentialRepository(MakeProfile("alpha", ProtocolType.Ssh));
        var vm = NewVm(repo);
        await vm.LoadCommand.ExecuteAsync(null);

        Assert.False(vm.IsEmpty);
        Assert.True(vm.HasMatches);
        Assert.False(vm.HasNoMatches);

        vm.SearchText = "no-such-thing";

        Assert.False(vm.IsEmpty);
        Assert.False(vm.HasMatches);
        Assert.True(vm.HasNoMatches);
    }

    [Fact]
    public void HasNoMatches_is_false_when_collection_is_empty()
    {
        var vm = NewVm(new FakeCredentialRepository());

        Assert.True(vm.IsEmpty);
        Assert.False(vm.HasMatches);
        Assert.False(vm.HasNoMatches);
    }

    [Fact]
    public async Task FilteredCredentials_matches_across_name_username_and_domain()
    {
        var repo = new FakeCredentialRepository(
            MakeProfile("alpha", ProtocolType.Ssh, username: "root"),
            MakeProfile("beta", ProtocolType.Rdp, username: "admin", domain: "CORP"),
            MakeProfile("gamma", ProtocolType.Ssh, username: "alice"));
        var vm = NewVm(repo);
        await vm.LoadCommand.ExecuteAsync(null);

        vm.SearchText = "ALP";
        Assert.Single(vm.FilteredCredentials, c => c.Name == "alpha");

        vm.SearchText = "admin";
        Assert.Single(vm.FilteredCredentials, c => c.Name == "beta");

        vm.SearchText = "corp";
        Assert.Single(vm.FilteredCredentials, c => c.Name == "beta");

        vm.SearchText = "";
        Assert.Equal(3, vm.FilteredCredentials.Count);

        vm.SearchText = "no-such-thing";
        Assert.Empty(vm.FilteredCredentials);
    }

    private static CredentialProfile MakeProfile(
        string name,
        ProtocolType protocol,
        string? username = null,
        string? domain = null,
        CredentialKind kind = CredentialKind.Password) =>
        new()
        {
            Id = Guid.NewGuid(),
            Name = name,
            Username = username,
            Domain = domain,
            Protocol = protocol,
            Kind = kind,
        };

    private static CredentialsViewModel NewVm(
        FakeCredentialRepository repo,
        FakeCredentialService? credService = null,
        FakeDialogService? dialog = null) =>
        new(repo, credService ?? new FakeCredentialService(), dialog ?? new FakeDialogService(), NullLogger<CredentialsViewModel>.Instance);

    private sealed class FakeCredentialRepository : ICredentialRepository
    {
        public List<CredentialProfile> Profiles { get; }
        public bool GetAllShouldThrow { get; set; }

        public FakeCredentialRepository(params CredentialProfile[] initial)
        {
            Profiles = new List<CredentialProfile>(initial);
        }

        public Task<IReadOnlyList<CredentialProfile>> GetAllAsync(CancellationToken ct = default)
        {
            if (GetAllShouldThrow) throw new InvalidOperationException("repo offline");
            return Task.FromResult<IReadOnlyList<CredentialProfile>>(Profiles.OrderBy(p => p.Name).ToList());
        }

        public Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken ct = default)
            => Task.FromResult(Profiles.FirstOrDefault(p => p.Id == id));

        public Task AddAsync(CredentialProfile profile, CancellationToken ct = default)
        {
            Profiles.Add(profile);
            return Task.CompletedTask;
        }

        public Task UpdateAsync(CredentialProfile profile, CancellationToken ct = default)
        {
            var idx = Profiles.FindIndex(p => p.Id == profile.Id);
            if (idx >= 0) Profiles[idx] = profile;
            return Task.CompletedTask;
        }

        public HashSet<Guid> DeleteShouldThrowForIds { get; } = new();

        public Task DeleteAsync(Guid id, CancellationToken ct = default)
        {
            if (DeleteShouldThrowForIds.Contains(id))
                throw new InvalidOperationException($"simulated delete failure for {id}");
            Profiles.RemoveAll(p => p.Id == id);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeDialogService : IDialogService
    {
        public List<(string title, string message)> Messages { get; } = new();
        public bool ConfirmResult { get; set; } = true;
        public CredentialDraft? CredentialPromptResult { get; set; }
        public int CredentialPromptCallCount { get; private set; }
        public CredentialDraft? LastCredentialPromptInitial { get; private set; }

        public Task ShowMessageAsync(string title, string message)
        {
            Messages.Add((title, message));
            return Task.CompletedTask;
        }

        public Task<bool> ConfirmAsync(string title, string message, string primaryText = "Yes", string closeText = "No")
            => Task.FromResult(ConfirmResult);

        public Task<string?> PromptForTextAsync(string title, string label, string defaultValue = "")
            => Task.FromResult<string?>(null);

        public Task<ConnectionNode?> EditConnectionAsync(ConnectionNode initial, bool isNew)
            => Task.FromResult<ConnectionNode?>(null);

        public Task<CredentialDraft?> PromptForCredentialAsync(CredentialDraft? initial = null)
        {
            CredentialPromptCallCount++;
            LastCredentialPromptInitial = initial;
            return Task.FromResult(CredentialPromptResult);
        }

        public Task<TunnelDraft?> PromptForTunnelAsync(TunnelDraft? initial = null)
            => Task.FromResult<TunnelDraft?>(null);

        public Task<string?> PromptPasswordAsync(string title, string message)
            => Task.FromResult<string?>(null);

        public Task<MRemoteNgImportResult?> PromptForMRemoteNgImportAsync()
            => Task.FromResult<MRemoteNgImportResult?>(null);

        public Task<Wormhole.Models.Backup.BackupExportResult?> PromptForBackupExportAsync()
            => Task.FromResult<Wormhole.Models.Backup.BackupExportResult?>(null);

        public Task<Wormhole.Models.Backup.BackupImportResult?> PromptForBackupImportAsync()
            => Task.FromResult<Wormhole.Models.Backup.BackupImportResult?>(null);
    }
}
