using Microsoft.UI.Xaml.Controls;
namespace Wormhole.Services;

public sealed class NavigationService : INavigationService
{
    private Frame? _frame;

    public void Initialize(Frame frame)
    {
        _frame = frame;
    }

    public bool Navigate(Type pageType, object? parameter = null)
    {
        if (_frame is null) return false;
        if (_frame.CurrentSourcePageType == pageType)
        {
            _frame.BackStack.Clear();
            return true;
        }

        var navigated = _frame.Navigate(pageType, parameter);
        if (navigated)
        {
            // Main-window destinations behave like tabs, not document history. Letting
            // every footer click accumulate BackStack entries retains page navigation
            // state the app never exposes and grows memory over a long session.
            _frame.BackStack.Clear();
        }
        return navigated;
    }

    public bool CanGoBack => _frame?.CanGoBack ?? false;

    public void GoBack()
    {
        if (_frame is not null && _frame.CanGoBack) _frame.GoBack();
    }
}
