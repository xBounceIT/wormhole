using Microsoft.UI.Xaml.Controls;
namespace Wormhole.Services;

public interface INavigationService
{
    void Initialize(Frame frame);
    bool Navigate(Type pageType, object? parameter = null);
    bool CanGoBack { get; }
    void GoBack();
}
