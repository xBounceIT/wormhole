using System;

namespace Wormhole.Views.Dialogs;

public interface IDraftForm<T> where T : class
{
    event EventHandler? ValidityChanged;
    bool IsValid { get; }
    void LoadDraft(T initial);
    T BuildDraft();
    void FocusNameField();
}
