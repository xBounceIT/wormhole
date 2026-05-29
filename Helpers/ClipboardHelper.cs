using Windows.ApplicationModel.DataTransfer;

namespace Wormhole.Helpers;

public static class ClipboardHelper
{
    /// <summary>
    /// Copy text to the system clipboard, flushing so it survives Wormhole exiting. A failed
    /// copy is swallowed: Clipboard.SetContent can throw COMException when another app owns the
    /// clipboard, and that must never crash the caller. Deliberately not logged — the payload
    /// may be a credential.
    /// </summary>
    public static void CopyText(string text)
    {
        try
        {
            var package = new DataPackage();
            package.SetText(text);
            Clipboard.SetContent(package);
            Clipboard.Flush();
        }
        catch
        {
            // Non-fatal; see remarks above.
        }
    }
}
