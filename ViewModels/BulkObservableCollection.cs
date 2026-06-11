using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace Wormhole.ViewModels;

public sealed class BulkObservableCollection<T> : ObservableCollection<T>
{
    public void ReplaceAll(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        CheckReentrancy();
        Items.Clear();
        foreach (var item in items)
        {
            Items.Add(item);
        }

        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }

    /// <summary>
    /// <see cref="ReplaceAll"/>, except a sequence-equal replacement is a silent no-op.
    /// Use for filter rebuilds where the result often matches the current contents —
    /// the skipped Reset would otherwise tear down the bound GridView's realized
    /// viewport and snap its scroll position to the top for nothing.
    /// </summary>
    public void ReplaceAllIfChanged(IReadOnlyList<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        if (items.Count == Items.Count)
        {
            var comparer = EqualityComparer<T>.Default;
            var equal = true;
            for (var i = 0; i < items.Count; i++)
            {
                if (!comparer.Equals(items[i], Items[i]))
                {
                    equal = false;
                    break;
                }
            }
            if (equal) return;
        }

        ReplaceAll(items);
    }

    /// <summary>
    /// Keeps this filtered view in sync with a single change to <paramref name="source"/>
    /// without a full rebuild — a rebuild raises Reset on the bound ItemsSource, which
    /// discards the realized viewport and snaps the scroll position back to the top.
    /// Forwards Add/Remove/Replace incrementally (items <paramref name="matches"/> rejects
    /// are skipped or dropped); returns false for Reset/Move so the caller can rebuild.
    /// </summary>
    public bool TryMirror(NotifyCollectionChangedEventArgs args, IReadOnlyList<T> source, Predicate<T> matches)
    {
        switch (args.Action)
        {
            case NotifyCollectionChangedAction.Remove when args.OldItems is not null:
                foreach (T item in args.OldItems)
                {
                    Remove(item);
                }
                return true;

            case NotifyCollectionChangedAction.Add when args.NewItems is not null && args.NewStartingIndex >= 0:
                {
                    var index = CountMatchesBefore(source, args.NewStartingIndex, matches);
                    foreach (T item in args.NewItems)
                    {
                        if (matches(item))
                        {
                            Insert(index++, item);
                        }
                    }
                    return true;
                }

            case NotifyCollectionChangedAction.Replace when args.OldItems is not null && args.NewItems is not null
                && args.OldItems.Count == args.NewItems.Count && args.NewStartingIndex >= 0:
                {
                    for (var i = 0; i < args.OldItems.Count; i++)
                    {
                        var oldItem = (T)args.OldItems[i]!;
                        var newItem = (T)args.NewItems[i]!;
                        var oldIndex = IndexOf(oldItem);
                        if (matches(newItem))
                        {
                            if (oldIndex >= 0)
                            {
                                this[oldIndex] = newItem;
                            }
                            else
                            {
                                Insert(CountMatchesBefore(source, args.NewStartingIndex + i, matches), newItem);
                            }
                        }
                        else if (oldIndex >= 0)
                        {
                            RemoveAt(oldIndex);
                        }
                    }
                    return true;
                }

            default:
                return false;
        }
    }

    // The filtered view preserves source order, so a source index maps to the filtered
    // index equal to the number of matching items that precede it.
    private static int CountMatchesBefore(IReadOnlyList<T> source, int sourceIndex, Predicate<T> matches)
    {
        var count = 0;
        for (var i = 0; i < sourceIndex && i < source.Count; i++)
        {
            if (matches(source[i])) count++;
        }
        return count;
    }
}
