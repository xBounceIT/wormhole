using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Wormhole.Data.Repositories;
using Wormhole.Models;

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

    public Task LoadTunnelConfigsAsync() => TunnelPicker.LoadAsync();

    public void LoadFrom(ConnectionNode node)
    {
        ArgumentNullException.ThrowIfNull(node);
        Name = node.Name;
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
        node.SshAutoSudo = SshAutoSudoMode switch
        {
            ConnectionEditorViewModel.SshAutoSudoOn => true,
            ConnectionEditorViewModel.SshAutoSudoOff => false,
            _ => (bool?)null,
        };
        TunnelPicker.WriteTo(node);
    }
}
