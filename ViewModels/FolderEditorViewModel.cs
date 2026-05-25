using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.ViewModels;

/// <summary>
/// Backs the folder editor dialog. A folder's load-bearing job is to hold inheritable
/// defaults for its descendants — the only one users can edit today is the VPN tunnel
/// (see <see cref="Data.InheritanceResolver"/>, which already walks ancestor folder
/// TunnelEnabled/TunnelConfigId), so the editor exposes Name + the shared
/// <see cref="TunnelPickerViewModel"/> picker.
/// </summary>
public partial class FolderEditorViewModel : ObservableObject
{
    public FolderEditorViewModel(ITunnelConfigRepository tunnelConfigRepository)
    {
        TunnelPicker = new TunnelPickerViewModel(tunnelConfigRepository, inheritLabel: "(Inherit from parent)");
    }

    /// <summary>Tri-state VPN picker — sentinel labelled "(Inherit from parent)" because a
    /// folder's parent might be another folder OR the root (no parent, where inherit
    /// resolves to "no tunnel"). Connection editor uses the default "(Inherit from folder)"
    /// label.</summary>
    public TunnelPickerViewModel TunnelPicker { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsValid))]
    private string name = string.Empty;

    public bool IsValid => !string.IsNullOrWhiteSpace(Name);

    public Task LoadTunnelConfigsAsync() => TunnelPicker.LoadAsync();

    public void LoadFrom(ConnectionNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        Name = node.Name;
        TunnelPicker.LoadFrom(node);
    }

    public void WriteTo(ConnectionNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        node.Name = Name.Trim();
        TunnelPicker.WriteTo(node);
    }
}
