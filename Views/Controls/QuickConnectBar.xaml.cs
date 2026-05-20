using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels;

namespace Wormhole.Views.Controls;

public sealed partial class QuickConnectBar : UserControl
{
    public QuickConnectViewModel ViewModel { get; }

    public QuickConnectBar()
    {
        ViewModel = App.Current.Services.GetRequiredService<QuickConnectViewModel>();
        this.InitializeComponent();
    }
}
