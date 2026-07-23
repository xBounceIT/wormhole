namespace Wormhole.Views.Sessions;

/// <summary>
/// Session surfaces hosted in the multi-tab panel. Visibility.Collapsed does not Unload the
/// control, so each protocol must hide/show its native/WebView pieces explicitly when the
/// owning tab is deselected or selected again.
/// </summary>
public interface ISessionSurfaceActivation
{
    void SetSessionSurfaceActive(bool isActive);
}
