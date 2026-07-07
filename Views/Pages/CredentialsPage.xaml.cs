using System.Collections.Specialized;
using System.Windows.Input;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Wormhole.Models;
using Wormhole.ViewModels;

namespace Wormhole.Views.Pages;

public sealed partial class CredentialsPage : Page
{
    public CredentialsViewModel ViewModel { get; }

    public CredentialsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<CredentialsViewModel>();
        this.InitializeComponent();
    }

    private static void ExecuteIfCan(ICommand command, object? parameter)
    {
        if (command.CanExecute(parameter))
        {
            command.Execute(parameter);
        }
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        // VM is Singleton — subscribe per navigation and unsubscribe in OnNavigatedFrom so
        // visited pages aren't pinned by a handler the VM keeps alive.
        ViewModel.SelectedCredentials.CollectionChanged += OnSelectedCredentialsChanged;
        _ = ViewModel.LoadCommand.ExecuteAsync(null);
    }

    protected override void OnNavigatedFrom(NavigationEventArgs e)
    {
        ViewModel.SelectedCredentials.CollectionChanged -= OnSelectedCredentialsChanged;
        base.OnNavigatedFrom(e);
    }

    private void OnCardDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CredentialProfile profile })
        {
            ExecuteIfCan(ViewModel.EditCredentialCommand, profile);
        }
    }

    private void OnEditMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CredentialProfile profile })
        {
            ExecuteIfCan(ViewModel.EditCredentialCommand, profile);
        }
    }

    private void OnDeleteMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CredentialProfile profile })
        {
            ExecuteIfCan(ViewModel.DeleteCredentialCommand, profile);
        }
    }

    // Initial state for each card's CheckBox as containers are realized/recycled.
    // Reflects VM selection state; user input flows back via OnSelectionCheckBoxClick.
    private void OnContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
    {
        if (args.InRecycleQueue) return;
        if (args.Item is not CredentialProfile profile) return;

        // A brand-new container's data template isn't inflated at phase 0, so retry on the
        // next rendering phase. With virtualization, this sync is the only thing that sets
        // the checkbox for items realized while a selection exists.
        if (args.ItemContainer.ContentTemplateRoot is not { } root)
        {
            if (args.Phase < 2) args.RegisterUpdateCallback(OnContainerContentChanging);
            return;
        }

        var checkBox = FindSelectCheckBox(root);
        if (checkBox is not null)
        {
            checkBox.IsChecked = ViewModel.IsSelected(profile);
        }
    }

    private void OnSelectionCheckBoxClick(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { Tag: CredentialProfile profile } cb) return;

        if (cb.IsChecked == true)
        {
            if (!ViewModel.IsSelected(profile))
                ViewModel.SelectedCredentials.Add(profile);
        }
        else
        {
            ViewModel.SelectedCredentials.Remove(profile);
        }
    }

    private void OnClearSelectionClick(object sender, RoutedEventArgs e)
    {
        // Just clear the VM — OnSelectedCredentialsChanged drains every visible card's CheckBox.
        ViewModel.SelectedCredentials.Clear();
    }

    // Fires when SelectedCredentials mutates by any path (toolbar Select all, Clear, bulk delete, etc.).
    // Re-sync CheckBoxes so the visual matches the VM source of truth. Add/Remove/Replace
    // pinpoint the affected profiles, so only those containers are touched; a Reset
    // (Select all, Clear) is the only action that needs the full realized-container walk.
    private void OnSelectedCredentialsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (CredentialsGrid?.Items is null) return;

        if (e.Action is not NotifyCollectionChangedAction.Reset)
        {
            SyncCheckBoxes(e.OldItems);
            SyncCheckBoxes(e.NewItems);
            return;
        }

        foreach (var item in CredentialsGrid.Items)
        {
            SyncCheckBox(item);
        }
    }

    private void SyncCheckBoxes(System.Collections.IList? items)
    {
        if (items is null) return;
        foreach (var item in items)
        {
            SyncCheckBox(item);
        }
    }

    private void SyncCheckBox(object? item)
    {
        if (item is null) return;
        if (CredentialsGrid.ContainerFromItem(item) is not GridViewItem container) return;
        var checkBox = FindSelectCheckBox(container);
        if (checkBox is null) return;
        var shouldBeChecked = item is CredentialProfile profile && ViewModel.IsSelected(profile);
        if (checkBox.IsChecked != shouldBeChecked) checkBox.IsChecked = shouldBeChecked;
    }

    private static CheckBox? FindSelectCheckBox(DependencyObject root)
    {
        // Tiny BFS — the CheckBox sits a few levels deep inside the card template.
        var queue = new Queue<DependencyObject>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var node = queue.Dequeue();
            if (node is CheckBox { Name: "SelectCheckBox" } cb) return cb;
            var count = VisualTreeHelper.GetChildrenCount(node);
            for (var i = 0; i < count; i++) queue.Enqueue(VisualTreeHelper.GetChild(node, i));
        }
        return null;
    }
}
