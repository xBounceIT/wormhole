using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wormhole.Data;
using Wormhole.Models;
using Wormhole.Services;

namespace Wormhole.ViewModels;

public partial class QuickConnectViewModel : ObservableObject
{
    private readonly ISessionTabFactory _tabFactory;
    private readonly IDialogService _dialogs;
    private readonly InheritanceResolver _inheritanceResolver;
    private readonly ITransientSessionCredentialStore _transientCredentials;

    public QuickConnectViewModel(
        ISessionTabFactory tabFactory,
        IDialogService dialogs,
        InheritanceResolver inheritanceResolver,
        ITransientSessionCredentialStore transientCredentials)
    {
        _tabFactory = tabFactory;
        _dialogs = dialogs;
        _inheritanceResolver = inheritanceResolver;
        _transientCredentials = transientCredentials;
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task OpenAsync()
    {
        var result = await _dialogs.PromptQuickConnectAsync().ConfigureAwait(true);
        if (result is null) return;

        var node = result.Node;
        var profile = _inheritanceResolver.Resolve(
            node,
            new Dictionary<Guid, ConnectionNode> { [node.Id] = node }) with
        {
            IsEphemeral = true,
        };

        if (!string.IsNullOrEmpty(result.Password))
        {
            _transientCredentials.Store(node.Id, result.Password);
        }

        try
        {
            _tabFactory.Open(profile);
        }
        catch
        {
            _transientCredentials.Remove(node.Id);
            throw;
        }
    }
}
