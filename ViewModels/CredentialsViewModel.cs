using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Bitwarden;

namespace Wormhole.ViewModels;

public partial class CredentialsViewModel : ObservableObject
{
    private readonly ICredentialRepository _repository;
    private readonly IBitwardenCredentialCatalogService _credentialCatalog;
    private readonly IBitwardenCredentialSyncService _bitwardenCredentialSync;
    private readonly ICredentialService _credentialService;
    private readonly IDialogService _dialog;
    private readonly ILogger<CredentialsViewModel> _logger;
    private readonly HashSet<CredentialProfile> _selectedCredentialSet = new();
    private bool _hasLoaded;

    public BulkObservableCollection<CredentialProfile> Credentials { get; } = new();
    public BulkObservableCollection<CredentialProfile> FilteredCredentials { get; } = new();

    /// <summary>
    /// Mirrors GridView.SelectedItems via the page code-behind. Bulk commands read this directly.
    /// </summary>
    public BulkObservableCollection<CredentialProfile> SelectedCredentials { get; } = new();

    public bool IsEmpty => Credentials.Count == 0;

    public bool HasMatches => FilteredCredentials.Count > 0;

    public bool HasNoMatches => !IsEmpty && !HasMatches;

    public bool CanSelectAll => HasMatches;

    public bool HasSelection => SelectedCredentials.Count > 0;

    public int SelectedCount => SelectedCredentials.Count;

    // Derived string so the XAML binds a plain TextBlock.Text instead of `<Run Text="{x:Bind ...}">`,
    // which has had spotty INotifyPropertyChanged support across WinUI 3 versions.
    public string SelectionStatus => $"{SelectedCount} selected";

    [ObservableProperty]
    private string searchText = string.Empty;

    // Search is bound with UpdateSourceTrigger=PropertyChanged, so debounce production
    // keystrokes to avoid rebuilding the visible collection on every character.
    internal TimeSpan SearchDebounceDelay { get; set; } = TimeSpan.FromMilliseconds(120);

    private CancellationTokenSource? _filterDebounceCts;

    public CredentialsViewModel(
        ICredentialRepository repository,
        ICredentialService credentialService,
        IDialogService dialog,
        ILogger<CredentialsViewModel> logger)
        : this(
            repository,
            new RepositoryCredentialCatalogAdapter(repository),
            NoOpBitwardenCredentialSyncService.Instance,
            credentialService,
            dialog,
            logger)
    {
    }

    public CredentialsViewModel(
        ICredentialRepository repository,
        IBitwardenCredentialCatalogService credentialCatalog,
        IBitwardenCredentialSyncService bitwardenCredentialSync,
        ICredentialService credentialService,
        IDialogService dialog,
        ILogger<CredentialsViewModel> logger)
    {
        _repository = repository;
        _credentialCatalog = credentialCatalog;
        _bitwardenCredentialSync = bitwardenCredentialSync;
        _credentialService = credentialService;
        _dialog = dialog;
        _logger = logger;
        Credentials.CollectionChanged += (_, args) =>
        {
            if (!FilteredCredentials.TryMirror(args, Credentials, MatchesFilter))
            {
                RebuildFilteredCredentials(SearchText);
            }
            OnPropertyChanged(nameof(IsEmpty));
            // HasNoMatches derives from IsEmpty, but an incremental mirror can flip IsEmpty
            // without changing FilteredCredentials (e.g. adding the first credential while a
            // non-matching search is active). In that path FilteredCredentials.CollectionChanged
            // doesn't fire, so notify the match state here too or the page stays blank.
            OnPropertyChanged(nameof(HasNoMatches));
        };
        FilteredCredentials.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(HasMatches));
            OnPropertyChanged(nameof(HasNoMatches));
            OnPropertyChanged(nameof(CanSelectAll));
            SelectAllCommand.NotifyCanExecuteChanged();
        };
        SelectedCredentials.CollectionChanged += (_, args) =>
        {
            UpdateSelectedCredentialSet(args);
            OnPropertyChanged(nameof(HasSelection));
            OnPropertyChanged(nameof(SelectedCount));
            OnPropertyChanged(nameof(SelectionStatus));
            DeleteSelectedCommand.NotifyCanExecuteChanged();
        };
    }

    public bool IsSelected(CredentialProfile profile) => _selectedCredentialSet.Contains(profile);

    public Task EnsureLoadedAsync() =>
        _hasLoaded ? Task.CompletedTask : LoadAsync();

    partial void OnSearchTextChanged(string value)
    {
        ScheduleFilter(value);
    }

    private void ScheduleFilter(string query)
    {
        var prior = _filterDebounceCts;
        _filterDebounceCts = null;
        if (prior is not null)
        {
            try { prior.Cancel(); } catch (ObjectDisposedException) { }
            prior.Dispose();
        }

        if (SearchDebounceDelay <= TimeSpan.Zero)
        {
            RebuildFilteredCredentials(query);
            return;
        }

        var cts = new CancellationTokenSource();
        _filterDebounceCts = cts;
        _ = DebouncedApplyFilterAsync(query, cts);
    }

    private async Task DebouncedApplyFilterAsync(string query, CancellationTokenSource cts)
    {
        try
        {
            await Task.Delay(SearchDebounceDelay, cts.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        finally
        {
            if (ReferenceEquals(_filterDebounceCts, cts))
            {
                _filterDebounceCts = null;
            }
            cts.Dispose();
        }

        if (_filterDebounceCts is not null) return;
        RebuildFilteredCredentials(query);
    }

    [RelayCommand(CanExecute = nameof(CanSelectAll))]
    private void SelectAll()
    {
        if (FilteredCredentials.Count == 0) return;

        var next = new List<CredentialProfile>(SelectedCredentials.Count + FilteredCredentials.Count);
        next.AddRange(SelectedCredentials);
        var changed = false;
        foreach (var profile in FilteredCredentials)
        {
            if (!_selectedCredentialSet.Contains(profile))
            {
                next.Add(profile);
                changed = true;
            }
        }
        if (changed) SelectedCredentials.ReplaceAll(next);
    }

    private void UpdateSelectedCredentialSet(NotifyCollectionChangedEventArgs args)
    {
        switch (args.Action)
        {
            case NotifyCollectionChangedAction.Add:
                AddSelected(args.NewItems);
                break;
            case NotifyCollectionChangedAction.Remove:
                RemoveSelected(args.OldItems);
                break;
            case NotifyCollectionChangedAction.Replace:
                RemoveSelected(args.OldItems);
                AddSelected(args.NewItems);
                break;
            case NotifyCollectionChangedAction.Reset:
                _selectedCredentialSet.Clear();
                foreach (var profile in SelectedCredentials)
                {
                    _selectedCredentialSet.Add(profile);
                }
                break;
        }
    }

    private void AddSelected(System.Collections.IList? items)
    {
        if (items is null) return;
        foreach (CredentialProfile profile in items)
        {
            _selectedCredentialSet.Add(profile);
        }
    }

    private void RemoveSelected(System.Collections.IList? items)
    {
        if (items is null) return;
        foreach (CredentialProfile profile in items)
        {
            _selectedCredentialSet.Remove(profile);
        }
    }

    [RelayCommand]
    private async Task LoadAsync()
    {
        try
        {
            await _bitwardenCredentialSync.SyncIfStaleAsync().ConfigureAwait(true);
            var rows = await _credentialCatalog.GetCredentialPageProfilesAsync().ConfigureAwait(true);
            // Drop selection before swapping the collection — Singleton VM means stale
            // CredentialProfile references would otherwise survive across reloads/navigations.
            SelectedCredentials.Clear();
            Credentials.ReplaceAll(rows);
            _hasLoaded = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load credentials");
            await _dialog.ShowMessageAsync("Couldn't load credentials", ex.Message);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddCredentialAsync()
    {
        var draft = await _dialog.PromptForCredentialAsync();
        if (draft is null) return;

        if (NameExists(draft.Name, excludingId: null))
        {
            await _dialog.ShowMessageAsync(
                "Name already in use",
                $"A credential named '{draft.Name}' already exists. Pick a different name.");
            return;
        }

        var profile = new CredentialProfile
        {
            Name = draft.Name,
            Username = draft.Username,
            Domain = draft.Domain,
            Protocol = draft.Protocol,
            Kind = CredentialKind.Password,
            SecretProvider = draft.SecretProvider,
            BitwardenItemId = draft.BitwardenItemId,
            BitwardenItemName = draft.BitwardenItemName,
            BitwardenFieldPath = NormalizeBitwardenFieldPath(draft.BitwardenFieldPath),
        };

        try
        {
            await _repository.AddAsync(profile);
            if (profile.SecretProvider == CredentialSecretProvider.Local)
            {
                await _credentialService.StorePasswordAsync(profile.Id, draft.Password);
            }
            if (profile.SecretProvider == CredentialSecretProvider.Bitwarden)
            {
                await LoadAsync().ConfigureAwait(true);
            }
            else
            {
                // In-place insert instead of a full reload: the row's final state is already in
                // hand, and a reload would clear the user's selection and Reset the grid.
                Credentials.Insert(SortedIndexFor(profile.Name), profile);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add credential '{Name}'", profile.Name);
            await _dialog.ShowMessageAsync("Couldn't save credential", ex.Message);
        }
    }

    // Mirrors the repository's ORDER BY Name (SQLite BINARY collation ≈ ordinal) so an
    // in-place insert lands where the next full load would put the row.
    private int SortedIndexFor(string name)
    {
        var index = 0;
        while (index < Credentials.Count && string.CompareOrdinal(Credentials[index].Name, name) <= 0)
        {
            index++;
        }
        return index;
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task EditCredentialAsync(CredentialProfile? profile)
    {
        if (profile is null) return;

        if (profile.IsReadOnly)
        {
            await _dialog.ShowMessageAsync(
                "Bitwarden credential",
                "This credential is a read-only Bitwarden login item. Edit or delete it in Bitwarden.");
            return;
        }

        if (profile.Kind != CredentialKind.Password)
        {
            await _dialog.ShowMessageAsync(
                "Can't edit here",
                "SSH key credentials aren't editable from this page yet.");
            return;
        }

        var existingPassword = string.Empty;
        if (profile.SecretProvider == CredentialSecretProvider.Local)
        {
            existingPassword = await _credentialService.ReadPasswordAsync(profile.Id) ?? string.Empty;
            if (existingPassword.Length == 0)
            {
                _logger.LogWarning(
                    "Stored password missing for credential {Id} ('{Name}'); user will be prompted to re-enter it.",
                    profile.Id, profile.Name);
            }
        }

        var initial = new CredentialDraft(
            profile.Name,
            profile.Protocol,
            profile.Username ?? string.Empty,
            profile.Domain,
            existingPassword,
            profile.SecretProvider,
            profile.BitwardenItemId,
            profile.BitwardenItemName,
            NormalizeBitwardenFieldPath(profile.BitwardenFieldPath));

        var draft = await _dialog.PromptForCredentialAsync(initial);
        if (draft is null) return;

        if (NameExists(draft.Name, excludingId: profile.Id))
        {
            await _dialog.ShowMessageAsync(
                "Name already in use",
                $"A credential named '{draft.Name}' already exists. Pick a different name.");
            return;
        }

        var updated = new CredentialProfile
        {
            Id = profile.Id,
            Name = draft.Name,
            Username = draft.Username,
            Domain = draft.Domain,
            Protocol = draft.Protocol,
            Kind = profile.Kind,
            PrivateKeyFileName = profile.PrivateKeyFileName,
            CreatedAt = profile.CreatedAt,
            SecretProvider = draft.SecretProvider,
            BitwardenItemId = draft.BitwardenItemId,
            BitwardenItemName = draft.BitwardenItemName,
            BitwardenFieldPath = NormalizeBitwardenFieldPath(draft.BitwardenFieldPath),
        };

        try
        {
            await _repository.UpdateAsync(updated);
            if (updated.SecretProvider == CredentialSecretProvider.Local)
            {
                await _credentialService.StorePasswordAsync(updated.Id, draft.Password);
            }
            else
            {
                await _credentialService.DeletePasswordAsync(updated.Id);
            }
            if (profile.SecretProvider == CredentialSecretProvider.Bitwarden ||
                updated.SecretProvider == CredentialSecretProvider.Bitwarden)
            {
                await LoadAsync().ConfigureAwait(true);
            }
            else
            {
                ReplaceInPlace(profile, updated);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update credential '{Name}'", updated.Name);
            await _dialog.ShowMessageAsync("Couldn't update credential", ex.Message);
            await LoadAsync();
        }
    }

    // Swaps the edited row in place instead of a full reload, which would clear the user's
    // selection and Reset the grid. A rename moves the card to its new Name-sorted position.
    private void ReplaceInPlace(CredentialProfile original, CredentialProfile updated)
    {
        var index = Credentials.IndexOf(original);
        if (index < 0)
        {
            // The instance vanished (a reload raced the edit dialog); insert the saved row
            // so the UI still reflects what was persisted.
            Credentials.Insert(SortedIndexFor(updated.Name), updated);
            return;
        }

        if (string.Equals(original.Name, updated.Name, StringComparison.Ordinal))
        {
            Credentials[index] = updated;
        }
        else
        {
            Credentials.RemoveAt(index);
            Credentials.Insert(SortedIndexFor(updated.Name), updated);
        }

        // The card is a new object; migrate any selection so the action strip's count
        // doesn't strand a stale reference.
        if (SelectedCredentials.Remove(original))
        {
            SelectedCredentials.Add(updated);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task DeleteCredentialAsync(CredentialProfile? profile)
    {
        if (profile is null) return;

        if (profile.IsReadOnly)
        {
            await _dialog.ShowMessageAsync(
                "Bitwarden credential",
                "This credential is a read-only Bitwarden login item. Delete it in Bitwarden.");
            return;
        }

        var confirmed = await _dialog.ConfirmAsync(
            "Delete credential",
            $"Delete '{profile.Name}'? This cannot be undone.",
            primaryText: "Delete",
            closeText: "Cancel");
        if (!confirmed) return;

        try
        {
            await _repository.DeleteAsync(profile.Id);
            // Repository delete is the source of truth — once it succeeds the row is gone.
            // Drop from the UI list before secret cleanup so a later failure can't leave a ghost card.
            Credentials.Remove(profile);
            // Also drop from the selection set so the action strip's count doesn't get
            // stranded when the deleted card was checked.
            SelectedCredentials.Remove(profile);
            await _credentialService.DeletePasswordAsync(profile.Id);
            await _credentialService.DeletePrivateKeyAsync(profile.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete credential '{Name}'", profile.Name);
            await _dialog.ShowMessageAsync("Couldn't delete credential", ex.Message);
        }
    }

    private bool CanDeleteSelected() => SelectedCredentials.Any(c => !c.IsReadOnly);

    [RelayCommand(AllowConcurrentExecutions = false, CanExecute = nameof(CanDeleteSelected))]
    private async Task DeleteSelectedAsync()
    {
        // Snapshot first: SelectedCredentials is rebuilt by the GridView when the
        // underlying collection mutates, so iterating live would skip every other item.
        var snapshot = SelectedCredentials.Where(c => !c.IsReadOnly).ToArray();
        if (snapshot.Length == 0) return;

        var message = snapshot.Length == 1
            ? $"Delete '{snapshot[0].Name}'? This cannot be undone."
            : $"Delete {snapshot.Length} credentials? This cannot be undone.";


        var confirmed = await _dialog.ConfirmAsync(
            "Delete credentials",
            message,
            primaryText: "Delete",
            closeText: "Cancel");
        if (!confirmed) return;

        var failures = new List<string>();
        foreach (var profile in snapshot)
        {
            try
            {
                await _repository.DeleteAsync(profile.Id);
                // Same ordering rule as DeleteCredentialAsync: drop the card the moment the
                // DB row is gone, so a later secret-cleanup throw doesn't leave a ghost entry.
                Credentials.Remove(profile);
                await _credentialService.DeletePasswordAsync(profile.Id);
                await _credentialService.DeletePrivateKeyAsync(profile.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete credential '{Name}'", profile.Name);
                failures.Add($"'{profile.Name}': {ex.Message}");
            }
        }

        SelectedCredentials.Clear();

        if (failures.Count > 0)
        {
            await _dialog.ShowMessageAsync(
                "Couldn't delete some credentials",
                string.Join(Environment.NewLine, failures));
        }
    }

    private static bool Contains(string? haystack, string needle) =>
        haystack is not null && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    private bool MatchesFilter(CredentialProfile credential) =>
        string.IsNullOrWhiteSpace(SearchText) || MatchesQuery(credential, SearchText.Trim());

    private static bool MatchesQuery(CredentialProfile credential, string trimmedQuery) =>
        Contains(credential.Name, trimmedQuery) ||
        Contains(credential.Username, trimmedQuery) ||
        Contains(credential.Domain, trimmedQuery);

    private void RebuildFilteredCredentials(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            FilteredCredentials.ReplaceAllIfChanged(Credentials);
            return;
        }

        var q = query.Trim();
        var matches = new List<CredentialProfile>(Credentials.Count);
        foreach (var credential in Credentials)
        {
            if (MatchesQuery(credential, q))
            {
                matches.Add(credential);
            }
        }

        FilteredCredentials.ReplaceAllIfChanged(matches);
    }

    private static string NormalizeBitwardenFieldPath(string? value) =>
        string.IsNullOrWhiteSpace(value) ? BitwardenDefaults.PasswordFieldPath : value.Trim();

    private bool NameExists(string name, Guid? excludingId)
    {
        var hasExcludedId = excludingId.HasValue;
        var excludedId = excludingId.GetValueOrDefault();
        foreach (var credential in Credentials)
        {
            if (credential.IsVirtualBitwarden) continue;
            if (hasExcludedId && credential.Id == excludedId) continue;
            if (string.Equals(credential.Name, name, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }
}
