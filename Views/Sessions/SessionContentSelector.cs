using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Sessions;

public sealed class SessionContentSelector : DataTemplateSelector
{
    public DataTemplate? SshTemplate { get; set; }
    public DataTemplate? SerialTemplate { get; set; }
    public DataTemplate? RdpTemplate { get; set; }
    public DataTemplate? HttpTemplate { get; set; }
    public DataTemplate? VncTemplate { get; set; }
    public DataTemplate? PlaceholderTemplate { get; set; }

    /// <summary>Public entry used by the multi-surface SessionsPage host.</summary>
    public DataTemplate ResolveTemplate(object item) => SelectTemplateCore(item);

    protected override DataTemplate SelectTemplateCore(object item) => item switch
    {
        SshSessionViewModel when SshTemplate is not null => SshTemplate,
        SerialSessionViewModel when SerialTemplate is not null => SerialTemplate,
        RdpSessionViewModel when RdpTemplate is not null => RdpTemplate,
        HttpSessionViewModel when HttpTemplate is not null => HttpTemplate,
        VncSessionViewModel when VncTemplate is not null => VncTemplate,
        _ => PlaceholderTemplate!,
    };

    protected override DataTemplate SelectTemplateCore(object item, DependencyObject container)
        => SelectTemplateCore(item);
}
