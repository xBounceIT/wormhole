using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services.Bitwarden;

namespace Wormhole.ViewModels;

/// <summary>
/// Backs the folder editor dialog. A folder's load-bearing job is to hold inheritable
/// defaults for its descendants — users can edit the VPN tunnel (see
/// <see cref="Data.InheritanceResolver"/>, which walks ancestor folder TunnelEnabled/
/// TunnelConfigId) and the SSH Auto sudo default (which the resolver likewise walks), so the
/// editor exposes Name + the shared <see cref="TunnelPickerViewModel"/> picker + a tri-state
/// Auto sudo selector.
/// </summary>
public partial class FolderEditorViewModel : ObservableObject
{
    private readonly IBitwardenCredentialCatalogService _credentialCatalog;
    private readonly IBitwardenCredentialSyncService _bitwardenCredentialSync;
    private readonly Dictionary<Guid, CredentialProfile> _availableCredentialsById = new();
    private readonly HashSet<Guid> _loadedCredentialIds = new();

    internal FolderEditorViewModel(
        ITunnelConfigRepository tunnelConfigRepository,
        ICredentialRepository credentialRepository)
        : this(
            tunnelConfigRepository,
            new RepositoryCredentialCatalogAdapter(credentialRepository),
            NoOpBitwardenCredentialSyncService.Instance)
    {
    }

    [ActivatorUtilitiesConstructor]
    public FolderEditorViewModel(
        ITunnelConfigRepository tunnelConfigRepository,
        IBitwardenCredentialCatalogService credentialCatalog,
        IBitwardenCredentialSyncService bitwardenCredentialSync)
    {
        _credentialCatalog = credentialCatalog;
        _bitwardenCredentialSync = bitwardenCredentialSync;
        TunnelPicker = new TunnelPickerViewModel(tunnelConfigRepository, inheritLabel: "(Inherit from parent)");
        AvailableCredentials.Add(InheritCredential);
        AvailableCredentials.Add(NoCredential);
        _availableCredentialsById[InheritCredential.Id] = InheritCredential;
        _availableCredentialsById[NoCredential.Id] = NoCredential;
    }

    /// <summary>Tri-state VPN picker — sentinel labelled "(Inherit from parent)" because a
    /// folder's parent might be another folder OR the root (no parent, where inherit
    /// resolves to "no tunnel"). Connection editor uses the default "(Inherit from folder)"
    /// label.</summary>
    public TunnelPickerViewModel TunnelPicker { get; }

    public CredentialProfile InheritCredential { get; } = new()
    {
        Id = CredentialBindingSentinelIds.Inherit,
        Name = "(Inherit from parent)",
    };

    public static readonly CredentialProfile NoCredential = new()
    {
        Id = CredentialBindingSentinelIds.FolderNone,
        Name = "(No credential)",
    };

    public BulkObservableCollection<CredentialProfile> AvailableCredentials { get; } = new();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private string name = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedCredential))]
    private Guid? credentialId;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedCredential))]
    private CredentialBindingMode? credentialMode;

    public CredentialProfile? SelectedCredential
    {
        get
        {
            return EffectiveCredentialMode switch
            {
                CredentialBindingMode.Inherit => InheritCredential,
                CredentialBindingMode.None => NoCredential,
                CredentialBindingMode.Saved => CredentialId is { } id ? GetCredentialById(id) : null,
                _ => InheritCredential,
            };
        }
        set
        {
            if (value is null || value.Id == InheritCredential.Id)
            {
                CredentialId = null;
                CredentialMode = CredentialBindingMode.Inherit;
            }
            else if (value.Id == NoCredential.Id)
            {
                CredentialId = null;
                CredentialMode = CredentialBindingMode.None;
            }
            else
            {
                CredentialId = value.Id;
                CredentialMode = CredentialBindingMode.Saved;
            }
        }
    }

    private CredentialBindingMode EffectiveCredentialMode =>
        CredentialMode ?? (CredentialId is null ? CredentialBindingMode.Inherit : CredentialBindingMode.Saved);

    /// <summary>
    /// Tri-state SSH Auto sudo default for the subtree: "inherit" (null — defer to this folder's
    /// own parent / the global default), "on" (true), or "off" (false). SSH descendants that leave
    /// their own Auto sudo on "Inherit from folder" resolve to this value. Shared mode keys with
    /// <see cref="ConnectionEditorViewModel"/>; the "inherit" choice is labelled "from parent" here.
    /// </summary>
    [ObservableProperty]
    private string sshAutoSudoMode = ConnectionEditorViewModel.SshAutoSudoInherit;

    public IReadOnlyList<KeyValuePair<string, string>> SshAutoSudoChoices { get; } = new[]
    {
        new KeyValuePair<string, string>(ConnectionEditorViewModel.SshAutoSudoInherit, "Inherit from parent"),
        new KeyValuePair<string, string>(ConnectionEditorViewModel.SshAutoSudoOn, "On — run “sudo su” and send the saved password"),
        new KeyValuePair<string, string>(ConnectionEditorViewModel.SshAutoSudoOff, "Off"),
    };

    public bool IsValid => !string.IsNullOrWhiteSpace(Name);

    public async Task LoadOptionsAsync(CancellationToken cancellationToken = default)
    {
        var credentials = LoadCredentialsAsync(cancellationToken);
        var tunnels = TunnelPicker.LoadAsync(cancellationToken);
        await Task.WhenAll(credentials, tunnels).ConfigureAwait(true);
    }

    public Task LoadTunnelConfigsAsync(CancellationToken cancellationToken = default) =>
        TunnelPicker.LoadAsync(cancellationToken);

    public async Task LoadCredentialsAsync(CancellationToken cancellationToken = default)
    {
        var syncTask = _bitwardenCredentialSync.SyncIfStaleAsync(cancellationToken);
        var refreshAfterSync = !syncTask.IsCompleted;
        var credentials = await _credentialCatalog
            .GetPickerProfilesAsync(cancellationToken)
            .ConfigureAwait(true);
        ApplyCredentialCatalog(credentials);

        if (!refreshAfterSync)
        {
            await syncTask.ConfigureAwait(true);
            return;
        }

        _ = RefreshCredentialsAfterSyncAsync(syncTask, cancellationToken);
    }

    private async Task RefreshCredentialsAfterSyncAsync(Task syncTask, CancellationToken cancellationToken)
    {
        try
        {
            await syncTask.ConfigureAwait(true);
            cancellationToken.ThrowIfCancellationRequested();
            var refreshed = await _credentialCatalog
                .GetPickerProfilesAsync(cancellationToken)
                .ConfigureAwait(true);
            ApplyCredentialCatalog(refreshed);
        }
        catch (OperationCanceledException)
        {
            // The editor was closed while its background refresh was still in flight.
        }
        catch (Exception)
        {
            // Sync is best-effort and the service logs provider failures; keep the usable
            // cached snapshot instead of surfacing an unobserved fire-and-forget exception.
        }
    }

    private void ApplyCredentialCatalog(IReadOnlyList<CredentialProfile> credentials)
    {
        var available = new List<CredentialProfile>(credentials.Count + 2)
        {
            InheritCredential,
            NoCredential,
        };
        _loadedCredentialIds.Clear();
        foreach (var credential in credentials)
        {
            if (credential.Protocol is not (ProtocolType.Ssh or ProtocolType.Rdp or ProtocolType.Vnc)) continue;
            _loadedCredentialIds.Add(credential.Id);
            available.Add(credential);
        }
        ReplaceAvailableCredentials(available);
        AppendStaleCredentialSelection(CredentialId);
        OnPropertyChanged(nameof(SelectedCredential));
    }

    public void LoadFrom(ConnectionNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        Name = node.Name;
        CredentialId = node.CredentialId;
        CredentialMode = node.CredentialMode ?? (node.CredentialId is null
            ? CredentialBindingMode.Inherit
            : CredentialBindingMode.Saved);
        AppendStaleCredentialSelection(CredentialId);
        OnPropertyChanged(nameof(SelectedCredential));
        SshAutoSudoMode = node.SshAutoSudo switch
        {
            true => ConnectionEditorViewModel.SshAutoSudoOn,
            false => ConnectionEditorViewModel.SshAutoSudoOff,
            null => ConnectionEditorViewModel.SshAutoSudoInherit,
        };
        TunnelPicker.LoadFrom(node);
    }

    public void WriteTo(ConnectionNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        node.Name = Name.Trim();
        var effectiveCredentialMode = EffectiveCredentialMode;
        node.CredentialMode = effectiveCredentialMode;
        node.CredentialId = effectiveCredentialMode == CredentialBindingMode.Saved
            ? CredentialId
            : null;
        if (effectiveCredentialMode == CredentialBindingMode.Saved
            && CredentialId is { } credentialId
            && _loadedCredentialIds.Contains(credentialId))
        {
            node.Username = SelectedCredential?.Username?.Trim();
            if (string.IsNullOrWhiteSpace(node.Username)) node.Username = null;
        }
        node.SshAutoSudo = SshAutoSudoMode switch
        {
            ConnectionEditorViewModel.SshAutoSudoOn => true,
            ConnectionEditorViewModel.SshAutoSudoOff => false,
            _ => (bool?)null,
        };
        TunnelPicker.WriteTo(node);
    }

    private CredentialProfile? GetCredentialById(Guid? id) =>
        id is { } guid && _availableCredentialsById.TryGetValue(guid, out var credential)
            ? credential
            : null;

    private void AppendStaleCredentialSelection(Guid? id)
    {
        if (id is not { } guid) return;
        if (_availableCredentialsById.ContainsKey(guid)) return;
        var stale = new CredentialProfile
        {
            Id = guid,
            Name = $"(missing credential {guid:N})",
        };
        _availableCredentialsById[guid] = stale;
        AvailableCredentials.Add(stale);
    }

    private void ReplaceAvailableCredentials(IReadOnlyList<CredentialProfile> available)
    {
        _availableCredentialsById.Clear();
        foreach (var credential in available)
        {
            _availableCredentialsById[credential.Id] = credential;
        }
        AvailableCredentials.ReplaceAll(available);
    }

    /// <summary>
    /// Return a snapshot for the folder editor's type-to-search credential picker. Saved
    /// credentials match by name, username, or domain; an empty query includes both special
    /// choices and every available credential.
    /// </summary>
    public IReadOnlyList<CredentialProfile> FilterCredentials(string? query) =>
        CredentialPickerSearch.Filter(AvailableCredentials, query);

    /// <summary>
    /// Resolve typed picker text without guessing: an exact name wins, otherwise a single
    /// non-sentinel search match is accepted. Ambiguous or unmatched text leaves the selection
    /// unchanged in the view.
    /// </summary>
    public CredentialProfile? ResolveCredentialForCommit(string? text) =>
        CredentialPickerSearch.ResolveForCommit(AvailableCredentials, text);

    partial void OnCredentialIdChanged(Guid? value)
    {
        AppendStaleCredentialSelection(value);
        OnPropertyChanged(nameof(SelectedCredential));
    }
}
