using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;
using Wormhole.Services.Tunneling.Stormshield;
using Wormhole.Services.Tunneling.Watchguard;

namespace Wormhole.ViewModels;

public partial class TunnelConfigsViewModel : ObservableObject
{
    private readonly ITunnelConfigRepository _repo;
    private readonly IConnectionRepository _connectionRepo;
    private readonly ICredentialService _credentials;
    private readonly IStormshieldConfigCache _stormshieldCache;
    private readonly IDialogService _dialog;
    private readonly ILogger<TunnelConfigsViewModel> _logger;
    private bool _hasLoaded;

    public TunnelConfigsViewModel(
        ITunnelConfigRepository repo,
        IConnectionRepository connectionRepo,
        ICredentialService credentials,
        IStormshieldConfigCache stormshieldCache,
        IDialogService dialog,
        ILogger<TunnelConfigsViewModel> logger)
    {
        _repo = repo;
        _connectionRepo = connectionRepo;
        _credentials = credentials;
        _stormshieldCache = stormshieldCache;
        _dialog = dialog;
        _logger = logger;
        Configs.CollectionChanged += (_, _) =>
        {
            ApplyFilter(SearchText);
            OnPropertyChanged(nameof(IsEmpty));
        };
        FilteredConfigs.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(HasMatches));
            OnPropertyChanged(nameof(HasNoMatches));
        };
    }

    public BulkObservableCollection<TunnelConfig> Configs { get; } = new();

    public BulkObservableCollection<TunnelConfig> FilteredConfigs { get; } = new();

    public bool IsEmpty => Configs.Count == 0;

    public bool HasMatches => FilteredConfigs.Count > 0;

    public bool HasNoMatches => !IsEmpty && !HasMatches;

    [ObservableProperty]
    private string searchText = string.Empty;

    // Search is bound with UpdateSourceTrigger=PropertyChanged, so debounce production
    // keystrokes to avoid rebuilding the visible collection on every character.
    internal TimeSpan SearchDebounceDelay { get; set; } = TimeSpan.FromMilliseconds(120);

    private CancellationTokenSource? _filterDebounceCts;

    partial void OnSearchTextChanged(string value) => ScheduleFilter(value);

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
            ApplyFilter(query);
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
        ApplyFilter(query);
    }

    private void ApplyFilter(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            FilteredConfigs.ReplaceAll(Configs);
            return;
        }

        var q = query.Trim();
        var matches = new List<TunnelConfig>(Configs.Count);
        foreach (var config in Configs)
        {
            if (Contains(config.Name, q) ||
                KindContains(config.Kind, q))
            {
                matches.Add(config);
            }
        }

        FilteredConfigs.ReplaceAll(matches);
    }

    public Task EnsureLoadedAsync() =>
        _hasLoaded ? Task.CompletedTask : LoadAsync();

    [RelayCommand]
    private async Task LoadAsync()
    {
        try
        {
            var rows = await _repo.GetAllAsync();
            Configs.ReplaceAll(rows);
            _hasLoaded = true;
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

        byte[] secretBytes;
        try
        {
            // Serialize BEFORE committing the row: SerializeSecret can throw on a missing
            // per-kind settings group or an unsupported Kind. If it threw inside the
            // SaveSecretWithCompensationAsync argument list below, the row would already be
            // committed via _repo.AddAsync, but the rollback wouldn't register — leaving an
            // orphan row whose name is now reserved by the UNIQUE constraint. Hoist the call
            // so any failure happens before persistence touches the DB.
            secretBytes = SerializeSecret(draft);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to serialize tunnel secret for '{Name}'", record.Name);
            await _dialog.ShowMessageAsync("Couldn't save tunnel", ex.Message);
            return;
        }

        try
        {
            await _repo.AddAsync(record);
            // Compensate: a half-created config (DB row but no secret blob on disk) is worse
            // than nothing — TunnelConfigs.Name is UNIQUE, so the user can't even retry the
            // save with the same name without hitting the constraint. Roll the row back if
            // the secret write throws so a retry can use the same name.
            await SaveSecretWithCompensationAsync(
                record.Id,
                secretBytes,
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

        var (existing, loadFailure) = await ReadDraftAsync(config);
        if (loadFailure is not null)
        {
            // Warn the user BEFORE opening the dialog that the existing settings couldn't be
            // loaded — without this, the form silently appears blank and a casual Save would
            // overwrite the (potentially recoverable) on-disk blob with empty values. The
            // dialog still opens after the warning so the user can re-enter values; cancelling
            // out leaves the original (corrupt-on-disk) blob untouched.
            await _dialog.ShowMessageAsync(
                "Tunnel settings couldn't be loaded",
                $"The saved settings for '{config.Name}' could not be read ({loadFailure}). " +
                "The form will open empty — re-enter the values and Save to repair, or Cancel to leave the existing data on disk untouched.");
        }
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

        // Kind-change confirmation: changing Kind discards the previous kind's secret blob
        // (SerializeSecret routes on draft.Kind, so the unused side is lost on Save). The DPAPI
        // file is overwritten in place and there's no backup — without this prompt the user
        // could destroy a populated password / TOTP secret / preshared key by accidentally
        // toggling the Kind ComboBox before save.
        if (draft.Kind != config.Kind)
        {
            var confirmed = await _dialog.ConfirmAsync(
                "Change tunnel type?",
                $"Saving will switch this tunnel from {config.Kind} to {draft.Kind} and discard the {config.Kind} credentials currently stored. This cannot be undone.",
                primaryText: "Change type",
                closeText: "Cancel");
            if (!confirmed) return;
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

        byte[] secretBytes;
        try
        {
            // Serialize BEFORE committing the row update — same reasoning as AddTunnelAsync:
            // a throw out of SerializeSecret after UpdateAsync would leave the row showing the
            // new Name/Kind while the secret blob still holds the old values, with no rollback.
            secretBytes = SerializeSecret(draft);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to serialize tunnel secret for '{Name}'", draft.Name);
            await _dialog.ShowMessageAsync("Couldn't update tunnel", ex.Message);
            return;
        }

        try
        {
            await _repo.UpdateAsync(snapshot);
            await SaveSecretWithCompensationAsync(
                config.Id,
                secretBytes,
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
            ApplyFilter(SearchText);

            // If the saved tunnel will no longer use the Stormshield OTP profile cache (Kind changed
            // away from Stormshield, Mode switched off Automatic, or "Use an OTP" turned off), drop any
            // cached profile — it holds a plaintext private key and would otherwise linger orphaned.
            // (A still-Automatic-OTP edit that only changes Server/Username is handled by the cache's
            // own site-identity check, so we keep the cache in that case to avoid a needless re-download.)
            var usesOtpCache = draft.Kind == TunnelKind.Stormshield
                && draft.Stormshield is { Mode: StormshieldConnectionMode.Automatic, UseOtp: true };
            if (!usesOtpCache)
                await _stormshieldCache.DeleteAsync(config.Id, System.Threading.CancellationToken.None);
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
            var sample = FormatReferenceSample(referencing, sampleCap);
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
            // Best-effort: drop any cached Stormshield profile (which holds a private key) for this tunnel.
            // A no-op for non-Stormshield tunnels (the cache file simply won't exist).
            await _stormshieldCache.DeleteAsync(config.Id, System.Threading.CancellationToken.None);
            Configs.Remove(config);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete tunnel '{Name}'", config.Name);
            await _dialog.ShowMessageAsync("Couldn't delete tunnel", ex.Message);
        }
    }

    private static string FormatReferenceSample(IReadOnlyList<(Guid Id, string Name)> references, int sampleCap)
    {
        var count = Math.Min(references.Count, sampleCap);
        var sb = new StringBuilder(count * 16);
        for (var i = 0; i < count; i++)
        {
            if (i > 0) sb.Append(", ");
            sb.Append('\'').Append(references[i].Name).Append('\'');
        }
        return sb.ToString();
    }

    // Always returns a draft: failures degrade to empty per-kind settings so the user can
    // re-enter values and Save to repair. The dialog's IsValid gating prevents accidentally
    // saving an empty draft over real data. The string in the returned tuple is null on a
    // successful read; on any failure path (missing blob, IO error, JSON parse error) it's a
    // short human-readable reason — EditTunnelAsync surfaces this to the user via a warning
    // dialog before opening the empty form, so a casual Save doesn't overwrite recoverable
    // bytes with empty defaults.
    private async Task<(TunnelDraft Draft, string? LoadFailure)> ReadDraftAsync(TunnelConfig config)
    {
        byte[]? secret = null;
        string? loadFailure = null;
        try
        {
            secret = await _credentials.ReadTunnelConfigAsync(config.Id);
            if (secret is null or { Length: 0 })
            {
                _logger.LogWarning(
                    "Secret blob missing for tunnel {Id} ('{Name}'); user will re-enter values.",
                    config.Id, config.Name);
                loadFailure = "the encrypted settings file is missing or empty";
                secret = null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load tunnel secret for '{Name}'", config.Name);
            loadFailure = $"could not read the encrypted settings file: {ex.Message}";
            secret = null;
        }

        var draft = config.Kind switch
        {
            TunnelKind.WireGuard => new TunnelDraft(
                config.Name,
                config.Kind,
                WireGuard: DeserializeOrEmpty<WireGuardSettings>(secret, config, ref loadFailure),
                OpenVpn: null,
                Fortinet: null),
            TunnelKind.OpenVpn => new TunnelDraft(
                config.Name,
                config.Kind,
                WireGuard: null,
                OpenVpn: DeserializeOrEmpty<OpenVpnSettings>(secret, config, ref loadFailure),
                Fortinet: null),
            TunnelKind.Fortinet => new TunnelDraft(
                config.Name,
                config.Kind,
                WireGuard: null,
                OpenVpn: null,
                Fortinet: DeserializeOrEmpty<FortinetSettings>(secret, config, ref loadFailure)),
            TunnelKind.Watchguard => new TunnelDraft(
                config.Name,
                config.Kind,
                WireGuard: null,
                OpenVpn: null,
                Fortinet: null,
                Watchguard: DeserializeOrEmpty<WatchguardSettings>(secret, config, ref loadFailure)),
            TunnelKind.Stormshield => new TunnelDraft(
                config.Name,
                config.Kind,
                WireGuard: null,
                OpenVpn: null,
                Fortinet: null,
                Stormshield: DeserializeOrEmpty<StormshieldSettings>(secret, config, ref loadFailure)),
            _ => new TunnelDraft(config.Name, config.Kind, WireGuard: null, OpenVpn: null, Fortinet: null),
        };
        return (draft, loadFailure);
    }

    // Centralized deserialize-or-empty so a corrupt blob (bad JSON, wrong shape) degrades to a
    // blank-form repair path the same way a missing blob does — never throws out of
    // ReadDraftAsync. Updates loadFailure on parse error so EditTunnelAsync can surface the
    // reason to the user before they re-enter values and overwrite the on-disk bytes.
    private T DeserializeOrEmpty<T>(byte[]? secret, TunnelConfig config, ref string? loadFailure) where T : new()
    {
        if (secret is null) return new T();
        try
        {
            return JsonSerializer.Deserialize<T>(secret) ?? new T();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse tunnel secret for '{Name}' as {Type}", config.Name, typeof(T).Name);
            // Only overwrite loadFailure on parse error if it wasn't already set by the outer
            // IO/read path — preserving the more specific upstream cause.
            loadFailure ??= $"the encrypted settings file could not be parsed: {ex.Message}";
            return new T();
        }
    }

    private static byte[] SerializeSecret(TunnelDraft draft) => draft.Kind switch
    {
        TunnelKind.WireGuard => JsonSerializer.SerializeToUtf8Bytes(
            draft.WireGuard ?? throw new InvalidOperationException("WireGuard settings are missing for a WireGuard draft.")),
        TunnelKind.OpenVpn => JsonSerializer.SerializeToUtf8Bytes(
            draft.OpenVpn ?? throw new InvalidOperationException("OpenVPN settings are missing for an OpenVPN draft.")),
        TunnelKind.Fortinet => JsonSerializer.SerializeToUtf8Bytes(
            draft.Fortinet ?? throw new InvalidOperationException("Fortinet settings are missing for a Fortinet draft.")),
        TunnelKind.Watchguard => JsonSerializer.SerializeToUtf8Bytes(
            draft.Watchguard ?? throw new InvalidOperationException("Watchguard settings are missing for a Watchguard draft.")),
        TunnelKind.Stormshield => JsonSerializer.SerializeToUtf8Bytes(
            draft.Stormshield ?? throw new InvalidOperationException("Stormshield settings are missing for a Stormshield draft.")),
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
            case TunnelKind.OpenVpn:
                ValidateOpenVpn(draft.OpenVpn);
                return;
            case TunnelKind.Fortinet:
                ValidateFortinet(draft.Fortinet);
                return;
            case TunnelKind.Watchguard:
                ValidateWatchguard(draft.Watchguard);
                return;
            case TunnelKind.Stormshield:
                ValidateStormshield(draft.Stormshield);
                return;
            default:
                throw new InvalidOperationException($"Unsupported tunnel kind '{draft.Kind}'.");
        }
    }

    private static void ValidateWireGuard(WireGuardSettings? wg)
    {
        if (wg is null)
            throw new InvalidOperationException("WireGuard settings are required for a WireGuard tunnel.");
        StringBuilder? sb = null;
        if (string.IsNullOrWhiteSpace(wg.InterfacePrivateKey)) AppendValidationError(ref sb, "Interface private key is required.");
        if (string.IsNullOrWhiteSpace(wg.InterfaceAddress)) AppendValidationError(ref sb, "Interface address is required (e.g. 10.0.0.2/32).");
        if (string.IsNullOrWhiteSpace(wg.PeerPublicKey)) AppendValidationError(ref sb, "Peer public key is required.");
        if (string.IsNullOrWhiteSpace(wg.PeerEndpoint)) AppendValidationError(ref sb, "Peer endpoint is required (host:port).");
        ThrowValidationErrors(sb);
    }

    private static void ValidateOpenVpn(OpenVpnSettings? ovpn)
    {
        if (ovpn is null)
            throw new InvalidOperationException("OpenVPN settings are required for an OpenVPN tunnel.");
        if (string.IsNullOrWhiteSpace(ovpn.ProfileOvpn))
            throw new InvalidOperationException("OpenVPN profile (.ovpn contents) is required.");
    }

    private static void ValidateFortinet(FortinetSettings? fg)
    {
        if (fg is null)
            throw new InvalidOperationException("Fortinet settings are required for a Fortinet tunnel.");
        StringBuilder? sb = null;
        if (string.IsNullOrWhiteSpace(fg.Host)) AppendValidationError(ref sb, "Gateway host is required.");
        if (fg.Port is < 1 or > 65535) AppendValidationError(ref sb, "Port must be between 1 and 65535.");
        if (string.IsNullOrWhiteSpace(fg.Username)) AppendValidationError(ref sb, "Username is required.");
        // IsNullOrWhiteSpace mirrors every other required field (and ValidateWireGuard) — a
        // single space passed as a password would otherwise reach the gateway as %20 and bounce
        // back as a cryptic 'invalid credentials' instead of a clean client-side rejection.
        if (string.IsNullOrWhiteSpace(fg.Password)) AppendValidationError(ref sb, "Password is required.");
        ThrowValidationErrors(sb);
    }

    private static void ValidateWatchguard(WatchguardSettings? wg)
    {
        if (wg is null)
            throw new InvalidOperationException("Watchguard settings are required for a Watchguard tunnel.");
        StringBuilder? sb = null;
        if (string.IsNullOrWhiteSpace(wg.Server)) AppendValidationError(ref sb, "Server is required.");
        if (wg.Port is < 1 or > 65535) AppendValidationError(ref sb, "Port must be between 1 and 65535.");
        if (string.IsNullOrWhiteSpace(wg.Username)) AppendValidationError(ref sb, "Username is required.");
        if (string.IsNullOrWhiteSpace(wg.Password)) AppendValidationError(ref sb, "Password is required.");
        if (string.IsNullOrWhiteSpace(wg.CaPem)) AppendValidationError(ref sb, "CA certificate (PEM) is required.");
        if (string.IsNullOrWhiteSpace(wg.ClientCertPem)) AppendValidationError(ref sb, "Client certificate (PEM) is required.");
        if (string.IsNullOrWhiteSpace(wg.ClientKeyPem)) AppendValidationError(ref sb, "Client private key (PEM) is required.");
        ThrowValidationErrors(sb);

        // Required fields are all present — now apply the SAME injection-safety checks the
        // profile builder enforces (control chars / quotes in Server or the verify-x509-name
        // subject; angle brackets in a PEM body). Without this, a hand-edited or imported value
        // carrying one of those characters passes Save and only fails at connect time inside
        // WatchguardProfileBuilder.Build, after the bad value is already on disk. Run it after
        // the required-field check so Server / the PEMs are guaranteed non-empty here.
        WatchguardProfileBuilder.ValidateFieldSafety(wg);
    }

    private static void ValidateStormshield(StormshieldSettings? ss)
    {
        if (ss is null)
            throw new InvalidOperationException("Stormshield settings are required for a Stormshield tunnel.");
        StringBuilder? sb = null;
        if (ss.Mode == StormshieldConnectionMode.Import)
        {
            // Import mode uses the pasted .ovpn's own `remote` endpoint, so Server/Port are not
            // required here (and aren't used by the provider) — only the profile is.
            if (string.IsNullOrWhiteSpace(ss.ProfileOvpn))
                AppendValidationError(ref sb, "OpenVPN profile (.ovpn contents) is required for Import mode.");
        }
        else
        {
            // Automatic mode authenticates to the firewall captive portal, so Server + Port are
            // required. Username/password are required unless SSO is used (SSO is handled/rejected
            // separately by the provider as not-yet-supported).
            if (string.IsNullOrWhiteSpace(ss.Server)) AppendValidationError(ref sb, "Server is required.");
            if (ss.Port is < 1 or > 65535) AppendValidationError(ref sb, "Port must be between 1 and 65535.");
            if (!ss.UseSingleSignOn)
            {
                if (string.IsNullOrWhiteSpace(ss.Username)) AppendValidationError(ref sb, "Username is required.");
                if (string.IsNullOrWhiteSpace(ss.Password)) AppendValidationError(ref sb, "Password is required.");
            }
        }
        ThrowValidationErrors(sb);
    }

    private static void AppendValidationError(ref StringBuilder? sb, string message) =>
        (sb ??= new StringBuilder()).AppendLine(message);

    private static void ThrowValidationErrors(StringBuilder? sb)
    {
        if (sb is { Length: > 0 })
            throw new InvalidOperationException(sb.ToString().TrimEnd());
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

    private static bool KindContains(TunnelKind kind, string needle)
    {
        var name = kind switch
        {
            TunnelKind.WireGuard => nameof(TunnelKind.WireGuard),
            TunnelKind.OpenVpn => nameof(TunnelKind.OpenVpn),
            TunnelKind.Fortinet => nameof(TunnelKind.Fortinet),
            TunnelKind.Watchguard => nameof(TunnelKind.Watchguard),
            TunnelKind.Stormshield => nameof(TunnelKind.Stormshield),
            _ => null,
        };
        return Contains(name, needle);
    }

    private bool NameExists(string name, Guid? excludingId)
    {
        var hasExcludedId = excludingId.HasValue;
        var excludedId = excludingId.GetValueOrDefault();
        foreach (var config in Configs)
        {
            if (hasExcludedId && config.Id == excludedId) continue;
            if (string.Equals(config.Name, name, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }
}
