using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using K7Titan.App.Services;

namespace K7Titan.App.Views;

public partial class DashboardPage : UserControl
{
    private readonly AppServices _services;

    public DashboardPage(AppServices services)
    {
        _services = services;
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    private void Refresh()
    {
        EngineValue.Text = _services.EngineVersion;
        QuarantineValue.Text = _services.Quarantine.History.Count.ToString();
        LogValue.Text = _services.Log.Entries.Count.ToString();
        ExclusionValue.Text = (_services.Exclusions.ExcludedPaths.Count + _services.Exclusions.ExcludedExtensions.Count).ToString();
        UpdateProtection();
    }

    private void OnToggleRealtime(object sender, RoutedEventArgs e)
    {
        if (_services.RealtimeEnabled)
        {
            _services.StopRealtime();
        }
        else
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var dirs = new List<string>
            {
                Path.Combine(profile, "Downloads"),
                Path.Combine(profile, "Desktop"),
                Path.Combine(profile, "Documents")
            };
            _services.StartRealtime(dirs);
        }
        UpdateProtection();
    }

    private void UpdateProtection()
    {
        if (_services.RealtimeEnabled)
        {
            ProtectionStatus.Text = "You are protected";
            ProtectionDetail.Text = "Real-time protection is active";
            RealtimeButton.Content = "Disable real-time";
            RealtimeButton.Appearance = Wpf.Ui.Controls.ControlAppearance.Secondary;
        }
        else
        {
            ProtectionStatus.Text = "Protection is limited";
            ProtectionDetail.Text = "Real-time protection is off";
            RealtimeButton.Content = "Enable real-time";
            RealtimeButton.Appearance = Wpf.Ui.Controls.ControlAppearance.Primary;
        }
        LogValue.Text = _services.Log.Entries.Count.ToString();
        QuarantineValue.Text = _services.Quarantine.History.Count.ToString();
    }
}
