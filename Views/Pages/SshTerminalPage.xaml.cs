using Microsoft.UI.Xaml.Controls;

namespace Wormhole.Views.Pages;

public sealed partial class SshTerminalPage : Page
{
    public SshTerminalPage()
    {
        this.InitializeComponent();
        // TODO: SSH feature PR — call EnsureCoreWebView2Async, SetVirtualHostNameToFolderMapping
        // to map Assets/web/, navigate to https://terminal.wormhole/terminal.html, then attach
        // TerminalBridge once the SSH session is open.
    }
}
