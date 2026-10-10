using System.Windows;
using System.Windows.Controls;
using K7Titan.App.Services;

namespace K7Titan.App.Views;

public partial class LogsPage : UserControl
{
    private readonly AppServices _services;

    public LogsPage(AppServices services)
    {
        _services = services;
        InitializeComponent();
        Grid.ItemsSource = _services.Log.Entries;
    }

    private void OnClear(object sender, RoutedEventArgs e) => _services.Log.Clear();
}
