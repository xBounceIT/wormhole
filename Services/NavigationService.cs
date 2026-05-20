using System;
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
        if (_frame.CurrentSourcePageType == pageType) return true;
        return _frame.Navigate(pageType, parameter);
    }

    public bool CanGoBack => _frame?.CanGoBack ?? false;

    public void GoBack()
    {
        if (_frame is not null && _frame.CanGoBack) _frame.GoBack();
    }
}
