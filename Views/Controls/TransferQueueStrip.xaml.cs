using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Wormhole.ViewModels.Sessions.Transfer;

namespace Wormhole.Views.Controls;

public sealed partial class TransferQueueStrip : UserControl
{
    public static readonly DependencyProperty TransfersProperty =
        DependencyProperty.Register(
            nameof(Transfers),
            typeof(ObservableCollection<TransferItemViewModel>),
            typeof(TransferQueueStrip),
            new PropertyMetadata(null));

    public ObservableCollection<TransferItemViewModel>? Transfers
    {
        get => (ObservableCollection<TransferItemViewModel>?)GetValue(TransfersProperty);
        set => SetValue(TransfersProperty, value);
    }

    public TransferQueueStrip()
    {
        this.InitializeComponent();
    }
}
