using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Views.Sessions;

public sealed class SessionContentSelector : DataTemplateSelector
{
    public DataTemplate? SshTemplate { get; set; }
    public DataTemplate? RdpTemplate { get; set; }
    public DataTemplate? SftpTemplate { get; set; }
    public DataTemplate? PlaceholderTemplate { get; set; }

    protected override DataTemplate SelectTemplateCore(object item) => item switch
    {
        SshSessionViewModel when SshTemplate is not null => SshTemplate,
        RdpSessionViewModel when RdpTemplate is not null => RdpTemplate,
        SftpSessionViewModel when SftpTemplate is not null => SftpTemplate,
        _ => PlaceholderTemplate!,
    };

    protected override DataTemplate SelectTemplateCore(object item, DependencyObject container)
        => SelectTemplateCore(item);
}
