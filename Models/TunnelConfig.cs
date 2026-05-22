using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace Wormhole.Models;

// ObservableObject so Name/Kind mutations after a successful save fire PropertyChanged.
// TunnelConfigsPage's ListView item template binds Name/Kind with `Mode=OneWay`, which
// without INotifyPropertyChanged would still show stale values until the page reloads --
// renames of existing tunnels were invisible in the left-hand list. Id/CreatedAt/UpdatedAt
// are not UI-bound, so they stay as plain auto-properties.
public partial class TunnelConfig : ObservableObject
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [ObservableProperty]
    private string name = string.Empty;

    [ObservableProperty]
    private TunnelKind kind = TunnelKind.WireGuard;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
