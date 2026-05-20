using System.Threading.Tasks;
using Microsoft.UI.Xaml;

namespace Wormhole.Services;

public interface IDialogService
{
    Task ShowMessageAsync(XamlRoot xamlRoot, string title, string message);
    Task<bool> ConfirmAsync(XamlRoot xamlRoot, string title, string message);
}
