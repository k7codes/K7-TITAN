using System.Collections.ObjectModel;
using System.Windows;
using K7Titan.Core;

namespace K7Titan.App.Services;

public sealed class ScanLog
{
    public ObservableCollection<Detection> Entries { get; } = new();

    public void Add(Detection detection)
    {
        var app = Application.Current;
        if (app is null)
        {
            Entries.Add(detection);
            return;
        }
        app.Dispatcher.Invoke(() => Entries.Add(detection));
    }

    public void Clear()
    {
        var app = Application.Current;
        if (app is null)
        {
            Entries.Clear();
            return;
        }
        app.Dispatcher.Invoke(Entries.Clear);
    }
}
