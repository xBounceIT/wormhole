using System;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.ViewModels;

/// <summary>
/// Reusable tri-state VPN-tunnel picker. The connection editor and folder editor each
/// compose one of these and use <see cref="SelectedTunnel"/> as the picker selection.
/// The two sentinels (<see cref="InheritTunnel"/>, <see cref="NoTunnel"/>) encode the
/// tri-state (null = inherit, false = explicitly off, true = explicitly on) through a
/// single selection property. The "inherit" sentinel's display label is per-instance so
/// the host VM can read "(Inherit from folder)" in the connection editor and "(Inherit
/// from parent)" in the folder editor.
/// </summary>
public partial class TunnelPickerViewModel : ObservableObject
{
    // Fixed non-default Guids so a real TunnelConfig — whose Id is assigned via
    // Guid.NewGuid() — can never collide. Avoid Guid.Empty: that's the default value of an
    // uninitialized Guid, so picking it as a sentinel risks aliasing imported / corrupted
    // data (e.g. a malformed migration row).
    private static readonly Guid InheritTunnelId = new("00000000-0000-0000-0000-000000000001");
    private static readonly Guid NoTunnelId = new("ffffffff-ffff-ffff-ffff-ffffffffffff");

    private readonly ITunnelConfigRepository _repository;
    private readonly Dictionary<Guid, TunnelConfig> _availableTunnelConfigsById = new();

    public TunnelPickerViewModel(ITunnelConfigRepository repository, string inheritLabel = "(Inherit from folder)")
    {
        _repository = repository;
        InheritTunnel = new TunnelConfig { Id = InheritTunnelId, Name = inheritLabel };
        // Seed the picker with both sentinels up-front so a SelectedTunnel getter call
        // before LoadAsync still has inherit/off to return.
        AvailableTunnelConfigs.Add(InheritTunnel);
        AvailableTunnelConfigs.Add(NoTunnel);
        _availableTunnelConfigsById[InheritTunnel.Id] = InheritTunnel;
        _availableTunnelConfigsById[NoTunnel.Id] = NoTunnel;
    }

    /// <summary>Sentinel for "inherit from parent". <see cref="TunnelEnabled"/> stays null
    /// and <see cref="SelectedTunnelConfigId"/> stays null — the resolver walks up.
    /// Per-instance so the host VM can supply a context-appropriate display label.</summary>
    public TunnelConfig InheritTunnel { get; }

    /// <summary>Sentinel for "explicitly no tunnel" — overrides any inherited tunnel.
    /// <see cref="TunnelEnabled"/> = false, <see cref="SelectedTunnelConfigId"/> = null.
    /// Static because the label doesn't vary per host.</summary>
    public static readonly TunnelConfig NoTunnel = new()
    {
        Id = NoTunnelId,
        Name = "(No tunnel)",
    };

    // Tri-state: null = inherit from ancestor folder, false = explicitly off, true = explicitly on.
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedTunnel))]
    private bool? tunnelEnabled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedTunnel))]
    private Guid? selectedTunnelConfigId;

    public BulkObservableCollection<TunnelConfig> AvailableTunnelConfigs { get; } = new();

    /// <summary>
    /// Single picker selection that encodes the tri-state via two sentinels and the available
    /// tunnel list.
    /// </summary>
    public TunnelConfig? SelectedTunnel
    {
        get
        {
            // Enable=false explicitly trumps any persisted ConfigId (the resolver ignores
            // it once Enabled lands false). Show "(No tunnel)" so the user isn't misled by
            // a vestigial id from a previous selection.
            if (TunnelEnabled == false) return NoTunnel;
            // If a concrete ConfigId is bound, surface that selection — independently of
            // TunnelEnabled. This covers the legitimate (TunnelEnabled=null, ConfigId=guid)
            // "inherit enable, override config" state produced by the inheritance resolver
            // (see Resolve_ChildOverridesAncestorTunnelConfigId). Falling back to
            // InheritTunnel here would silently mask the override while WriteTo still
            // persisted the id — a contradiction the user can't see.
            if (SelectedTunnelConfigId is { } id)
            {
                return _availableTunnelConfigsById.GetValueOrDefault(id);
            }
            // No bound ConfigId: pure inherit (null enable) or pure force-on (true enable).
            // The latter ("force on, inherit ConfigId from ancestor") has no sentinel in
            // this single-picker UI; surface it as "no selection" rather than masking it.
            if (TunnelEnabled is null) return InheritTunnel;
            return null;
        }
        set
        {
            // Atomic two-field write — same field-bypass pattern as LoadFrom. Without it,
            // assigning TunnelEnabled first fires PropertyChanged(SelectedTunnel) while
            // SelectedTunnelConfigId still holds the previous value; a TwoWay ComboBox
            // binding that re-reads the getter at that point sees an inconsistent state
            // (e.g. (true, null) returns null) and a subsequent write-back can settle the
            // pair into the unintended (null, newId) "inherit-enable + override-config"
            // shape, silently disagreeing with what the user clicked.
            bool? nextEnabled;
            Guid? nextConfigId;
            if (value is null || ReferenceEquals(value, InheritTunnel))
            {
                nextEnabled = null;
                nextConfigId = null;
            }
            else if (ReferenceEquals(value, NoTunnel))
            {
                nextEnabled = false;
                nextConfigId = null;
            }
            else
            {
                nextEnabled = true;
                nextConfigId = value.Id;
            }

            if (TunnelEnabled == nextEnabled && SelectedTunnelConfigId == nextConfigId) return;

#pragma warning disable MVVMTK0034 // intentional field-bypass to keep the two-field write atomic
            tunnelEnabled = nextEnabled;
            selectedTunnelConfigId = nextConfigId;
#pragma warning restore MVVMTK0034
            OnPropertyChanged(nameof(TunnelEnabled));
            OnPropertyChanged(nameof(SelectedTunnelConfigId));
            OnPropertyChanged(nameof(SelectedTunnel));
        }
    }

    /// <summary>
    /// Rebuild <see cref="AvailableTunnelConfigs"/> from the repository, leading with the
    /// two sentinels so the picker always offers inherit/off.
    /// </summary>
    public async Task LoadAsync(CancellationToken cancellationToken = default)
    {
        var configs = await _repository.GetAllAsync(cancellationToken).ConfigureAwait(true);
        var available = new List<TunnelConfig>(configs.Count + 2)
        {
            InheritTunnel,
            NoTunnel,
        };
        available.AddRange(configs);
        ReplaceAvailableTunnelConfigs(available);

        // Preserve a currently-bound selection that points at a tunnel no longer in the list
        // (e.g. deleted in another window).
        AppendStaleTunnelSelection(SelectedTunnelConfigId);
        OnPropertyChanged(nameof(SelectedTunnel));
    }

    /// <summary>
    /// Append the stale placeholder (if any) FIRST so the SelectedTunnel getter can resolve
    /// the bound id when notifications fire. Then write the two backing fields DIRECTLY
    /// (bypassing the generated setters) and raise PropertyChanged once at the end —
    /// avoiding a transient window where TunnelEnabled is updated but
    /// SelectedTunnelConfigId hasn't been (or vice versa), during which the SelectedTunnel
    /// getter would return null and a TwoWay ComboBox binding could write that null back,
    /// clobbering the load.
    /// </summary>
    public void LoadFrom(ConnectionNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        AppendStaleTunnelSelection(node.TunnelConfigId);
#pragma warning disable MVVMTK0034 // intentional field-bypass to keep the two-field write atomic
        tunnelEnabled = node.TunnelEnabled;
        selectedTunnelConfigId = node.TunnelConfigId;
#pragma warning restore MVVMTK0034
        OnPropertyChanged(nameof(TunnelEnabled));
        OnPropertyChanged(nameof(SelectedTunnelConfigId));
        OnPropertyChanged(nameof(SelectedTunnel));
    }

    public void WriteTo(ConnectionNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        node.TunnelEnabled = TunnelEnabled;
        node.TunnelConfigId = SelectedTunnelConfigId;
    }

    /// <summary>
    /// Return a snapshot for a type-to-search tunnel picker. Tunnels match the name shown in the
    /// picker; an empty query also includes the inheritance and no-tunnel sentinels.
    /// </summary>
    public IReadOnlyList<TunnelConfig> FilterTunnelConfigs(string? query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return AvailableTunnelConfigs.ToList();
        }

        var q = query.Trim();
        var matches = new List<TunnelConfig>(AvailableTunnelConfigs.Count);
        foreach (var config in AvailableTunnelConfigs)
        {
            if (Contains(config.Name, q))
            {
                matches.Add(config);
            }
        }

        return matches;
    }

    /// <summary>
    /// Resolve an exact tunnel name or a single non-sentinel search match. Ambiguous and
    /// unmatched text returns null so the view can preserve the existing selection.
    /// </summary>
    public TunnelConfig? ResolveTunnelForCommit(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        var q = text.Trim();
        foreach (var config in AvailableTunnelConfigs)
        {
            if (string.Equals(config.Name, q, StringComparison.OrdinalIgnoreCase))
            {
                return config;
            }
        }

        TunnelConfig? single = null;
        foreach (var config in AvailableTunnelConfigs)
        {
            if (IsSentinel(config)) continue;
            if (!Contains(config.Name, q)) continue;
            if (single is not null) return null;
            single = config;
        }

        return single;
    }

    private bool IsSentinel(TunnelConfig config) =>
        ReferenceEquals(config, InheritTunnel) || ReferenceEquals(config, NoTunnel);

    private static bool Contains(string? value, string query) =>
        value is not null && value.Contains(query, StringComparison.OrdinalIgnoreCase);

    private void AppendStaleTunnelSelection(Guid? id)
    {
        if (id is not { } guid) return;
        if (guid == InheritTunnel.Id || guid == NoTunnel.Id) return;
        if (_availableTunnelConfigsById.ContainsKey(guid)) return;
        var stale = new TunnelConfig
        {
            Id = guid,
            Name = $"(missing tunnel {guid:N})",
        };
        _availableTunnelConfigsById[guid] = stale;
        AvailableTunnelConfigs.Add(stale);
    }

    private void ReplaceAvailableTunnelConfigs(IReadOnlyList<TunnelConfig> available)
    {
        _availableTunnelConfigsById.Clear();
        foreach (var config in available)
        {
            _availableTunnelConfigsById[config.Id] = config;
        }
        AvailableTunnelConfigs.ReplaceAll(available);
    }
}
