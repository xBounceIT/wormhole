namespace Wormhole.Views.Dialogs;

public interface IDraftForm<T> where T : class
{
    event EventHandler? ValidityChanged;
    bool IsValid { get; }
    void LoadDraft(T initial);
    T BuildDraft();
    void FocusNameField();

    // Forms wider than ContentDialog's default ~548 px theme cap (e.g. a 2-column tunnel
    // editor) opt in by returning a target width; ShowFormDialogAsync locks Min == Max so
    // the dialog doesn't oscillate while typing. Default null = use the platform default.
    double? PreferredDialogMinWidth => null;
}
