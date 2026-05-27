using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class CredentialsViewModel : ObservableObject
{
    private readonly ICredentialRepository _repository;
    private readonly ICredentialService _credentialService;
    private readonly IDialogService _dialog;
    private readonly ILogger<CredentialsViewModel> _logger;

    public ObservableCollection<CredentialProfile> Credentials { get; } = new();

    /// <summary>
    /// Mirrors GridView.SelectedItems via the page code-behind. Bulk commands read this directly.
    /// </summary>
    public ObservableCollection<CredentialProfile> SelectedCredentials { get; } = new();

    public bool IsEmpty => Credentials.Count == 0;

    public bool HasMatches => FilteredCredentials.Count > 0;

    public bool HasNoMatches => !IsEmpty && !HasMatches;

    public bool HasSelection => SelectedCredentials.Count > 0;

    public int SelectedCount => SelectedCredentials.Count;

    // Derived string so the XAML binds a plain TextBlock.Text instead of `<Run Text="{x:Bind ...}">`,
    // which has had spotty INotifyPropertyChanged support across WinUI 3 versions.
    public string SelectionStatus => $"{SelectedCount} selected";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FilteredCredentials))]
    [NotifyPropertyChangedFor(nameof(HasMatches))]
    [NotifyPropertyChangedFor(nameof(HasNoMatches))]
    private string searchText = string.Empty;

    public IReadOnlyList<CredentialProfile> FilteredCredentials
    {
        get
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                return Credentials.ToList();
            }

            var q = SearchText.Trim();
            return Credentials
                .Where(c =>
                    Contains(c.Name, q) ||
                    Contains(c.Username, q) ||
                    Contains(c.Domain, q))
                .ToList();
        }
    }

    public CredentialsViewModel(
        ICredentialRepository repository,
        ICredentialService credentialService,
        IDialogService dialog,
        ILogger<CredentialsViewModel> logger)
    {
        _repository = repository;
        _credentialService = credentialService;
        _dialog = dialog;
        _logger = logger;
        Credentials.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(FilteredCredentials));
            OnPropertyChanged(nameof(IsEmpty));
            OnPropertyChanged(nameof(HasMatches));
            OnPropertyChanged(nameof(HasNoMatches));
        };
        SelectedCredentials.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(HasSelection));
            OnPropertyChanged(nameof(SelectedCount));
            OnPropertyChanged(nameof(SelectionStatus));
            DeleteSelectedCommand.NotifyCanExecuteChanged();
        };
    }

    [RelayCommand]
    private void SelectAll()
    {
        foreach (var profile in FilteredCredentials)
        {
            if (!SelectedCredentials.Contains(profile))
            {
                SelectedCredentials.Add(profile);
            }
        }
    }

    [RelayCommand]
    private async Task LoadAsync()
    {
        try
        {
            var rows = await _repository.GetAllAsync();
            // Drop selection before swapping the collection — Singleton VM means stale
            // CredentialProfile references would otherwise survive across reloads/navigations.
            SelectedCredentials.Clear();
            Credentials.Clear();
            foreach (var row in rows)
            {
                Credentials.Add(row);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load credentials");
            await _dialog.ShowMessageAsync("Couldn't load credentials", ex.Message);
        }
    }

    [RelayCommand]
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
        };

        try
        {
            await _repository.AddAsync(profile);
            await _credentialService.StorePasswordAsync(profile.Id, draft.Password);
            await LoadAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add credential '{Name}'", profile.Name);
            await _dialog.ShowMessageAsync("Couldn't save credential", ex.Message);
        }
    }

    [RelayCommand]
    private async Task EditCredentialAsync(CredentialProfile? profile)
    {
        if (profile is null) return;

        if (profile.Kind != CredentialKind.Password)
        {
            await _dialog.ShowMessageAsync(
                "Can't edit here",
                "SSH key credentials aren't editable from this page yet.");
            return;
        }

        var existingPassword = await _credentialService.ReadPasswordAsync(profile.Id);
        if (existingPassword is null)
        {
            _logger.LogWarning(
                "Stored password missing for credential {Id} ('{Name}'); user will be prompted to re-enter it.",
                profile.Id, profile.Name);
        }

        var initial = new CredentialDraft(
            profile.Name,
            profile.Protocol,
            profile.Username ?? string.Empty,
            profile.Domain,
            existingPassword ?? string.Empty);

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
        };

        try
        {
            await _repository.UpdateAsync(updated);
            await _credentialService.StorePasswordAsync(updated.Id, draft.Password);
            await LoadAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update credential '{Name}'", updated.Name);
            await _dialog.ShowMessageAsync("Couldn't update credential", ex.Message);
            await LoadAsync();
        }
    }

    [RelayCommand]
    private async Task DeleteCredentialAsync(CredentialProfile? profile)
    {
        if (profile is null) return;

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

    private bool CanDeleteSelected() => SelectedCredentials.Count > 0;

    [RelayCommand(CanExecute = nameof(CanDeleteSelected))]
    private async Task DeleteSelectedAsync()
    {
        // Snapshot first: SelectedCredentials is rebuilt by the GridView when the
        // underlying collection mutates, so iterating live would skip every other item.
        var snapshot = SelectedCredentials.ToArray();
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

    private bool NameExists(string name, Guid? excludingId) =>
        Credentials.Any(c =>
            (excludingId is null || c.Id != excludingId.Value) &&
            string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));
}
