using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class TunnelConfigsViewModel : ObservableObject
{
    private readonly ITunnelConfigRepository _repo;
    private readonly IConnectionRepository _connectionRepo;
    private readonly ICredentialService _credentials;
    private readonly IDialogService _dialog;
    private readonly ILogger<TunnelConfigsViewModel> _logger;

    public TunnelConfigsViewModel(
        ITunnelConfigRepository repo,
        IConnectionRepository connectionRepo,
        ICredentialService credentials,
        IDialogService dialog,
        ILogger<TunnelConfigsViewModel> logger)
    {
        _repo = repo;
        _connectionRepo = connectionRepo;
        _credentials = credentials;
        _dialog = dialog;
        _logger = logger;
        Configs.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(FilteredConfigs));
            OnPropertyChanged(nameof(IsEmpty));
            OnPropertyChanged(nameof(HasMatches));
            OnPropertyChanged(nameof(HasNoMatches));
        };
    }

    public ObservableCollection<TunnelConfig> Configs { get; } = new();

    public bool IsEmpty => Configs.Count == 0;

    public bool HasMatches => FilteredConfigs.Count > 0;

    public bool HasNoMatches => !IsEmpty && !HasMatches;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FilteredConfigs))]
    [NotifyPropertyChangedFor(nameof(HasMatches))]
    [NotifyPropertyChangedFor(nameof(HasNoMatches))]
    private string searchText = string.Empty;

    public IReadOnlyList<TunnelConfig> FilteredConfigs
    {
        get
        {
            if (string.IsNullOrWhiteSpace(SearchText))
            {
                return Configs.ToList();
            }

            var q = SearchText.Trim();
            return Configs
                .Where(c =>
                    Contains(c.Name, q) ||
                    Contains(c.Kind.ToString(), q))
                .ToList();
        }
    }

    [RelayCommand]
    private async Task LoadAsync()
    {
        try
        {
            var rows = await _repo.GetAllAsync();
            Configs.Clear();
            foreach (var row in rows)
            {
                Configs.Add(row);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load tunnel configs");
            await _dialog.ShowMessageAsync("Couldn't load tunnels", ex.Message);
        }
    }

    [RelayCommand]
    private async Task AddTunnelAsync()
    {
        var draft = await _dialog.PromptForTunnelAsync();
        if (draft is null) return;

        if (NameExists(draft.Name, excludingId: null))
        {
            await _dialog.ShowMessageAsync(
                "Name already in use",
                $"A tunnel named '{draft.Name}' already exists. Pick a different name.");
            return;
        }

        try
        {
            ValidateDraft(draft);
        }
        catch (InvalidOperationException ex)
        {
            await _dialog.ShowMessageAsync("Tunnel settings incomplete", ex.Message);
            return;
        }

        var record = new TunnelConfig
        {
            Id = Guid.NewGuid(),
            Name = draft.Name,
            Kind = draft.Kind,
        };

        try
        {
            await _repo.AddAsync(record);
            // Compensate: a half-created config (DB row but no secret blob on disk) is worse
            // than nothing — TunnelConfigs.Name is UNIQUE, so the user can't even retry the
            // save with the same name without hitting the constraint. Roll the row back if
            // the secret write throws so a retry can use the same name.
            await SaveSecretWithCompensationAsync(
                record.Id,
                SerializeSecret(draft),
                rollback: () => _repo.DeleteAsync(record.Id));
            Configs.Add(record);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add tunnel '{Name}'", record.Name);
            await _dialog.ShowMessageAsync("Couldn't save tunnel", ex.Message);
        }
    }

    [RelayCommand]
    private async Task EditTunnelAsync(TunnelConfig? config)
    {
        if (config is null) return;

        var existing = await ReadDraftAsync(config);
        var draft = await _dialog.PromptForTunnelAsync(existing);
        if (draft is null) return;

        if (NameExists(draft.Name, excludingId: config.Id))
        {
            await _dialog.ShowMessageAsync(
                "Name already in use",
                $"A tunnel named '{draft.Name}' already exists. Pick a different name.");
            return;
        }

        try
        {
            ValidateDraft(draft);
        }
        catch (InvalidOperationException ex)
        {
            await _dialog.ShowMessageAsync("Tunnel settings incomplete", ex.Message);
            return;
        }

        // Persist row before the secret blob so a failing UpdateAsync doesn't leave the on-disk
        // secret pointing at the new payload while the row still shows the old Name/Kind.
        // Compensate-on-failure: roll the row back to its old Name/Kind if the secret write
        // throws, so the user doesn't end up with a row claiming new settings while the blob
        // still holds the old ones.
        var oldName = config.Name;
        var oldKind = config.Kind;
        var snapshot = new TunnelConfig
        {
            Id = config.Id,
            Name = draft.Name,
            Kind = draft.Kind,
            CreatedAt = config.CreatedAt,
            UpdatedAt = config.UpdatedAt,
        };

        try
        {
            await _repo.UpdateAsync(snapshot);
            await SaveSecretWithCompensationAsync(
                config.Id,
                SerializeSecret(draft),
                rollback: () => _repo.UpdateAsync(new TunnelConfig
                {
                    Id = config.Id,
                    Name = oldName,
                    Kind = oldKind,
                    CreatedAt = config.CreatedAt,
                    UpdatedAt = config.UpdatedAt,
                }));
            config.Name = draft.Name;
            config.Kind = draft.Kind;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update tunnel '{Name}'", draft.Name);
            await _dialog.ShowMessageAsync("Couldn't update tunnel", ex.Message);
            await LoadAsync();
        }
    }

    [RelayCommand]
    private async Task DeleteTunnelAsync(TunnelConfig? config)
    {
        if (config is null) return;

        // Refuse deletion if any connection node still points at this tunnel: silently
        // removing the row would leave those connections in a state where TunnelManager
        // throws "Tunnel config <guid> was not found" at session start, with no way for
        // the user to recover except by editing the DB by hand. Ask the user to detach
        // first instead. Cap the query at 4 rows so we can render up to three names + an
        // "and more" suffix without loading every connection off SQLite. Backed by the
        // partial index IX_Nodes_TunnelConfigId so this is an index-only lookup.
        const int sampleCap = 3;
        IReadOnlyList<(Guid Id, string Name)> referencing;
        try
        {
            referencing = await _connectionRepo.GetByTunnelConfigIdAsync(config.Id, sampleCap + 1);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check tunnel references for '{Name}'", config.Name);
            await _dialog.ShowMessageAsync("Couldn't delete tunnel", ex.Message);
            return;
        }

        if (referencing.Count > 0)
        {
            var sample = string.Join(", ", referencing.Take(sampleCap).Select(n => $"'{n.Name}'"));
            var more = referencing.Count > sampleCap ? " and more" : string.Empty;
            await _dialog.ShowMessageAsync(
                "Tunnel is in use",
                $"Can't delete '{config.Name}': connections still reference it ({sample}{more}). " +
                "Detach the tunnel from those connections first.");
            return;
        }

        var confirmed = await _dialog.ConfirmAsync(
            "Delete tunnel",
            $"Delete '{config.Name}'? This cannot be undone.",
            primaryText: "Delete",
            closeText: "Cancel");
        if (!confirmed) return;

        try
        {
            await _repo.DeleteAsync(config.Id);
            await _credentials.DeleteTunnelConfigAsync(config.Id);
            Configs.Remove(config);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete tunnel '{Name}'", config.Name);
            await _dialog.ShowMessageAsync("Couldn't delete tunnel", ex.Message);
        }
    }

    // Always returns a draft: failures degrade to an empty WireGuardSettings so the user can
    // re-enter values and Save to repair. The dialog's IsValid gating prevents accidentally
    // saving an empty draft over real data.
    private async Task<TunnelDraft> ReadDraftAsync(TunnelConfig config)
    {
        WireGuardSettings wg;
        try
        {
            var secret = await _credentials.ReadTunnelConfigAsync(config.Id);
            if (secret is null or { Length: 0 })
            {
                _logger.LogWarning(
                    "Secret blob missing for tunnel {Id} ('{Name}'); user will re-enter values.",
                    config.Id, config.Name);
                wg = new WireGuardSettings();
            }
            else
            {
                wg = JsonSerializer.Deserialize<WireGuardSettings>(secret) ?? new WireGuardSettings();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load tunnel secret for '{Name}'", config.Name);
            wg = new WireGuardSettings();
        }
        return new TunnelDraft(config.Name, config.Kind, wg);
    }

    private static byte[] SerializeSecret(TunnelDraft draft) => draft.Kind switch
    {
        TunnelKind.WireGuard => JsonSerializer.SerializeToUtf8Bytes(draft.WireGuard),
        _ => throw new InvalidOperationException($"Unsupported tunnel kind '{draft.Kind}'."),
    };

    private static void ValidateDraft(TunnelDraft draft)
    {
        // Defense-in-depth: the dialog's IsValid disables Save on an empty name, but if a draft
        // ever bypasses the dialog (programmatic callers, future PRs) we still want to reject
        // it rather than INSERT a row with Name = "" that violates the user's expectation but
        // satisfies the NOT NULL constraint.
        if (string.IsNullOrWhiteSpace(draft.Name))
            throw new InvalidOperationException("Name is required.");

        switch (draft.Kind)
        {
            case TunnelKind.WireGuard:
                ValidateWireGuard(draft.WireGuard);
                return;
            default:
                throw new InvalidOperationException($"Unsupported tunnel kind '{draft.Kind}'.");
        }
    }

    private static void ValidateWireGuard(WireGuardSettings wg)
    {
        var sb = new StringBuilder();
        if (string.IsNullOrWhiteSpace(wg.InterfacePrivateKey)) sb.AppendLine("Interface private key is required.");
        if (string.IsNullOrWhiteSpace(wg.InterfaceAddress)) sb.AppendLine("Interface address is required (e.g. 10.0.0.2/32).");
        if (string.IsNullOrWhiteSpace(wg.PeerPublicKey)) sb.AppendLine("Peer public key is required.");
        if (string.IsNullOrWhiteSpace(wg.PeerEndpoint)) sb.AppendLine("Peer endpoint is required (host:port).");
        if (sb.Length > 0) throw new InvalidOperationException(sb.ToString().TrimEnd());
    }

    // Best-effort compensate when a DPAPI secret write fails after the SQLite row has already
    // committed. Logs (but does not throw on) rollback failures; the original secret-write
    // exception always propagates so the user sees the failure.
    private async Task SaveSecretWithCompensationAsync(Guid id, byte[] secretBytes, Func<Task> rollback)
    {
        try
        {
            await _credentials.StoreTunnelConfigAsync(id, secretBytes);
        }
        catch
        {
            try { await rollback(); }
            catch (Exception rollbackEx)
            {
                _logger.LogWarning(rollbackEx,
                    "Failed to roll back tunnel config row {Id} after secret-write failed.", id);
            }
            throw;
        }
    }

    private static bool Contains(string? haystack, string needle) =>
        haystack is not null && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    private bool NameExists(string name, Guid? excludingId) =>
        Configs.Any(c =>
            (excludingId is null || c.Id != excludingId.Value) &&
            string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));
}
