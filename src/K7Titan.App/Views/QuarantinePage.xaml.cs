using System.Collections.ObjectModel;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using K7Titan.App.Services;
using K7Titan.Core;
using Wpf.Ui.Controls;

namespace K7Titan.App.Views;

public partial class QuarantinePage : UserControl
{
    private readonly AppServices _services;
    private readonly ObservableCollection<QuarantineRecord> _items = new();

    public QuarantinePage(AppServices services)
    {
        _services = services;
        InitializeComponent();
        Grid.ItemsSource = _items;
        Loaded += (_, _) => Refresh();
    }

    private void Refresh()
    {
        _items.Clear();
        foreach (var record in _services.Quarantine.History)
        {
            _items.Add(record);
        }
    }

    private void OnRefresh(object sender, RoutedEventArgs e) => Refresh();

    private async void OnRestore(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is not QuarantineRecord record ||
            record.Decision != QuarantineDecision.AllowToQuarantine)
        {
            System.Windows.MessageBox.Show("Select a quarantined file to restore.", "K7 TITAN");
            return;
        }

        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = "K7 TITAN — Restore file",
            Content = $"Restore this file to its original location?\n\n{record.OriginalPath}",
            PrimaryButtonText = "Restore",
            CloseButtonText = "Cancel"
        };

        if (await box.ShowDialogAsync() == Wpf.Ui.Controls.MessageBoxResult.Primary)
        {
            await _services.Quarantine.RestoreAsync(record.StoredName, CancellationToken.None);
            Refresh();
        }
    }
}
