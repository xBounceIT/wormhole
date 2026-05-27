using System.Collections.Specialized;
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

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        // VM is Singleton — subscribe per navigation and unsubscribe in OnNavigatedFrom so
        // visited pages aren't pinned by a handler the VM keeps alive.
        ViewModel.SelectedCredentials.CollectionChanged += OnSelectedCredentialsChanged;
        _ = ViewModel.EnsureLoadedAsync();
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
            ViewModel.EditCredentialCommand.Execute(profile);
        }
    }

    private void OnEditMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CredentialProfile profile })
        {
            ViewModel.EditCredentialCommand.Execute(profile);
        }
    }

    private void OnDeleteMenuItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: CredentialProfile profile })
        {
            ViewModel.DeleteCredentialCommand.Execute(profile);
        }
    }

    // Initial state for each card's CheckBox as containers are realized/recycled.
    // Reflects VM selection state; user input flows back via OnSelectionCheckBoxClick.
    private void OnContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
    {
        if (args.InRecycleQueue) return;
        if (args.Item is not CredentialProfile profile) return;
        if (args.ItemContainer is not GridViewItem container) return;

        var checkBox = FindSelectCheckBox(container);
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
    // Re-sync every realized CheckBox so the visual matches the VM source of truth.
    private void OnSelectedCredentialsChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (CredentialsGrid?.Items is null) return;
        foreach (var item in CredentialsGrid.Items)
        {
            if (CredentialsGrid.ContainerFromItem(item) is not GridViewItem container) continue;
            var checkBox = FindSelectCheckBox(container);
            if (checkBox is null) continue;
            var shouldBeChecked = item is CredentialProfile profile && ViewModel.IsSelected(profile);
            if (checkBox.IsChecked != shouldBeChecked) checkBox.IsChecked = shouldBeChecked;
        }
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
