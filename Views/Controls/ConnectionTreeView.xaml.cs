using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels;

namespace Wormhole.Views.Controls;

public sealed partial class ConnectionTreeView : UserControl
{
    public ConnectionTreeViewModel ViewModel { get; }

    public ConnectionTreeView()
    {
        ViewModel = App.Current.Services.GetRequiredService<ConnectionTreeViewModel>();
        this.InitializeComponent();
    }
}
