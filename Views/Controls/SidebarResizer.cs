using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace Wormhole.Views.Controls;

// ContentControl's default template doesn't render Background, so setting Background
// on the ContentControl alone leaves the bounds non-hit-testable. The inner Border is
// the real pointer surface. Cursor lookup walks up the visual tree, so the
// ContentControl's ProtectedCursor activates when the pointer is over the Border.
public sealed class SidebarResizer : ContentControl
{
    public SidebarResizer()
    {
        ProtectedCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeWestEast);
        IsTabStop = false;
        HorizontalContentAlignment = HorizontalAlignment.Stretch;
        VerticalContentAlignment = VerticalAlignment.Stretch;
        Content = new Border
        {
            Background = new SolidColorBrush(Colors.Transparent),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            VerticalAlignment = VerticalAlignment.Stretch,
        };
    }
}
