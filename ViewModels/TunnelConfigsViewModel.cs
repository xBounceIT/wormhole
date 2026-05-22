using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Data.Repositories;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public sealed partial class TunnelConfigsViewModel : ObservableObject
{
    private readonly ITunnelConfigRepository _repo;
    private readonly IConnectionRepository _connectionRepo;
    private readonly ICredentialService _credentials;
    private readonly ILogger<TunnelConfigsViewModel> _logger;
    private CancellationTokenSource? _editorLoadCts;

    public TunnelConfigsViewModel(
        ITunnelConfigRepository repo,
        IConnectionRepository connectionRepo,
        ICredentialService credentials,
        ILogger<TunnelConfigsViewModel> logger)
    {
        _repo = repo;
        _connectionRepo = connectionRepo;
        _credentials = credentials;
        _logger = logger;
    }

    public ObservableCollection<TunnelConfig> Configs { get; } = new();

    [ObservableProperty]
    private TunnelConfig? selectedConfig;

    [ObservableProperty] private string editorName = string.Empty;
    [ObservableProperty] private TunnelKind editorKind = TunnelKind.WireGuard;
    [ObservableProperty] private string interfacePrivateKey = string.Empty;
    [ObservableProperty] private string interfaceAddress = string.Empty;
    [ObservableProperty] private string mtuText = string.Empty;
    [ObservableProperty] private string dnsText = string.Empty;
    [ObservableProperty] private string peerPublicKey = string.Empty;
    [ObservableProperty] private string peerPresharedKey = string.Empty;
    [ObservableProperty] private string peerEndpoint = string.Empty;
    [ObservableProperty] private string allowedIpsText = string.Empty;
    [ObservableProperty] private string persistentKeepaliveText = string.Empty;

    [ObservableProperty] private string? statusMessage;
    [ObservableProperty] private string? errorMessage;
    [ObservableProperty] private bool isBusy;

    partial void OnSelectedConfigChanged(TunnelConfig? value)
    {
        // A user flicking through the list would otherwise interleave async loads — whichever
        // resolved last would win the editor fields, often showing the wrong config. Cancel
        // any in-flight load on every selection change.
        var prior = _editorLoadCts;
        var fresh = new CancellationTokenSource();
        _editorLoadCts = fresh;
        try { prior?.Cancel(); } catch { /* already disposed */ }
        prior?.Dispose();
        _ = LoadEditorForAsync(value, fresh.Token);
    }

    public async Task LoadAsync()
    {
        try
        {
            IsBusy = true;
            var rows = await _repo.GetAllAsync().ConfigureAwait(true);
            Configs.Clear();
            foreach (var r in rows) Configs.Add(r);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Loading tunnel configs failed.");
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task LoadEditorForAsync(TunnelConfig? value, CancellationToken ct)
    {
        ErrorMessage = null;
        StatusMessage = null;
        if (value is null)
        {
            ResetEditor();
            return;
        }

        // Sync prefix sets name+kind immediately and CLEARS WireGuard fields so we never show
        // the previous selection's secrets behind the new selection's name while the async
        // ReadTunnelConfigAsync below is in flight.
        EditorName = value.Name;
        EditorKind = value.Kind;
        ClearWireGuardFields();

        try
        {
            var secret = await _credentials.ReadTunnelConfigAsync(value.Id).ConfigureAwait(true);
            if (ct.IsCancellationRequested) return;
            if (secret is null || secret.Length == 0)
            {
                // Row exists but secret blob doesn't — recover by letting the user re-enter.
                ClearWireGuardFields();
                StatusMessage = "Secret blob missing on disk; re-enter values and Save to repair.";
                return;
            }
            var wg = JsonSerializer.Deserialize<WireGuardSettings>(secret) ?? new WireGuardSettings();
            if (ct.IsCancellationRequested) return;
            InterfacePrivateKey = wg.InterfacePrivateKey;
            InterfaceAddress = wg.InterfaceAddress;
            MtuText = wg.Mtu?.ToString() ?? string.Empty;
            DnsText = string.Join(", ", wg.Dns ?? new List<string>());
            PeerPublicKey = wg.PeerPublicKey;
            PeerPresharedKey = wg.PeerPresharedKey ?? string.Empty;
            PeerEndpoint = wg.PeerEndpoint;
            AllowedIpsText = string.Join(", ", wg.AllowedIps ?? new List<string>());
            PersistentKeepaliveText = wg.PersistentKeepaliveSeconds?.ToString() ?? string.Empty;
        }
        catch (Exception ex)
        {
            if (ct.IsCancellationRequested) return;
            _logger.LogError(ex, "Loading tunnel secret for {Id} failed.", value.Id);
            ErrorMessage = ex.Message;
        }
    }

    [RelayCommand]
    private void NewConfig()
    {
        SelectedConfig = null;
        ResetEditor();
        EditorName = "New WireGuard tunnel";
        EditorKind = TunnelKind.WireGuard;
        StatusMessage = "Fill the fields and Save.";
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        try
        {
            IsBusy = true;
            ErrorMessage = null;
            StatusMessage = null;

            if (string.IsNullOrWhiteSpace(EditorName))
            {
                ErrorMessage = "Name is required.";
                return;
            }

            var settings = new WireGuardSettings
            {
                InterfacePrivateKey = InterfacePrivateKey.Trim(),
                InterfaceAddress = InterfaceAddress.Trim(),
                Mtu = TryParseInt(MtuText),
                Dns = SplitCsv(DnsText),
                PeerPublicKey = PeerPublicKey.Trim(),
                PeerPresharedKey = string.IsNullOrWhiteSpace(PeerPresharedKey) ? null : PeerPresharedKey.Trim(),
                PeerEndpoint = PeerEndpoint.Trim(),
                AllowedIps = SplitCsv(AllowedIpsText),
                PersistentKeepaliveSeconds = TryParseInt(PersistentKeepaliveText),
            };

            ValidateWireGuard(settings);

            var secretBytes = JsonSerializer.SerializeToUtf8Bytes(settings);

            if (SelectedConfig is null)
            {
                var record = new TunnelConfig
                {
                    Id = Guid.NewGuid(),
                    Name = EditorName.Trim(),
                    Kind = EditorKind,
                };
                await _repo.AddAsync(record).ConfigureAwait(true);
                await _credentials.StoreTunnelConfigAsync(record.Id, secretBytes).ConfigureAwait(true);
                Configs.Add(record);
                SelectedConfig = record;
                StatusMessage = $"Created '{record.Name}'.";
            }
            else
            {
                // Persist before mutating the bound record so a failing UpdateAsync doesn't
                // leave the ListView showing the new name with the old name still in the DB.
                // UpdatedAt isn't bound to UI so we leave the in-memory copy stale until the
                // next Page_Loaded refresh — no need to thread it back from the repo.
                var newName = EditorName.Trim();
                var newKind = EditorKind;
                var snapshot = new TunnelConfig
                {
                    Id = SelectedConfig.Id,
                    Name = newName,
                    Kind = newKind,
                    CreatedAt = SelectedConfig.CreatedAt,
                    UpdatedAt = SelectedConfig.UpdatedAt,
                };
                await _repo.UpdateAsync(snapshot).ConfigureAwait(true);
                await _credentials.StoreTunnelConfigAsync(SelectedConfig.Id, secretBytes).ConfigureAwait(true);
                SelectedConfig.Name = newName;
                SelectedConfig.Kind = newKind;
                StatusMessage = $"Saved '{SelectedConfig.Name}'.";
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Saving tunnel config failed.");
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task DeleteAsync()
    {
        if (SelectedConfig is null) return;
        try
        {
            IsBusy = true;
            ErrorMessage = null;
            StatusMessage = null;
            var id = SelectedConfig.Id;

            // Refuse deletion if any connection node still points at this tunnel: silently
            // removing the row would leave those connections in a state where TunnelManager
            // throws "Tunnel config <guid> was not found" at session start, with no way for
            // the user to recover except by editing the DB by hand. Ask the user to detach
            // first instead.
            var nodes = await _connectionRepo.GetAllAsync().ConfigureAwait(true);
            var referencing = nodes.Where(n => n.TunnelConfigId == id).ToList();
            if (referencing.Count > 0)
            {
                var sample = string.Join(", ", referencing.Take(3).Select(n => $"'{n.Name}'"));
                var more = referencing.Count > 3 ? $" and {referencing.Count - 3} more" : string.Empty;
                ErrorMessage = $"Cannot delete '{SelectedConfig.Name}': {referencing.Count} connection(s) " +
                               $"still reference it ({sample}{more}). Detach the tunnel from those " +
                               "connections first.";
                return;
            }

            await _repo.DeleteAsync(id).ConfigureAwait(true);
            await _credentials.DeleteTunnelConfigAsync(id).ConfigureAwait(true);
            Configs.Remove(SelectedConfig);
            SelectedConfig = null;
            StatusMessage = "Deleted.";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Deleting tunnel config failed.");
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ResetEditor()
    {
        EditorName = string.Empty;
        EditorKind = TunnelKind.WireGuard;
        ClearWireGuardFields();
    }

    private void ClearWireGuardFields()
    {
        InterfacePrivateKey = string.Empty;
        InterfaceAddress = string.Empty;
        MtuText = string.Empty;
        DnsText = string.Empty;
        PeerPublicKey = string.Empty;
        PeerPresharedKey = string.Empty;
        PeerEndpoint = string.Empty;
        AllowedIpsText = string.Empty;
        PersistentKeepaliveText = string.Empty;
    }

    private static List<string> SplitCsv(string s) =>
        s.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static int? TryParseInt(string s) =>
        int.TryParse(s, out var n) ? n : (int?)null;

    private static void ValidateWireGuard(WireGuardSettings wg)
    {
        var sb = new StringBuilder();
        if (string.IsNullOrWhiteSpace(wg.InterfacePrivateKey)) sb.AppendLine("Interface private key is required.");
        if (string.IsNullOrWhiteSpace(wg.InterfaceAddress)) sb.AppendLine("Interface address is required (e.g. 10.0.0.2/32).");
        if (string.IsNullOrWhiteSpace(wg.PeerPublicKey)) sb.AppendLine("Peer public key is required.");
        if (string.IsNullOrWhiteSpace(wg.PeerEndpoint)) sb.AppendLine("Peer endpoint is required (host:port).");
        if (sb.Length > 0) throw new InvalidOperationException(sb.ToString().TrimEnd());
    }
}
