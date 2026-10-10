using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using K7Titan.App.Services;
using K7Titan.App.Views;
using Wpf.Ui.Controls;

namespace K7Titan.App;

public partial class MainWindow : FluentWindow
{
    private readonly AppServices _services = new();
    private readonly Dictionary<string, UserControl> _pages = new();

    public MainWindow()
    {
        InitializeComponent();

        _pages["Dashboard"] = new DashboardPage(_services);
        _pages["Scan"] = new ScanPage(_services);
        _pages["Quarantine"] = new QuarantinePage(_services);
        _pages["Logs"] = new LogsPage(_services);
        _pages["Settings"] = new SettingsPage(_services);

        VersionText.Text = $"engine v{_services.EngineVersion}";
        NavList.SelectedIndex = 0;
    }

    private void OnNavChanged(object sender, SelectionChangedEventArgs e)
    {
        if (NavList.SelectedItem is not ListBoxItem item) return;
        var tag = item.Tag?.ToString();
        if (tag is not null && _pages.TryGetValue(tag, out var page))
        {
            PageHost.Content = page;
        }
    }

    protected override void OnClosed(System.EventArgs e)
    {
        _services.StopRealtime();
        base.OnClosed(e);
    }
}
