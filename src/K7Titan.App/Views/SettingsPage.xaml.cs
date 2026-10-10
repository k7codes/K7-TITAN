using System;
using System.Collections.Generic;
using System.IO;
using System.Windows.Controls;
using K7Titan.App.Services;

namespace K7Titan.App.Views;

public partial class SettingsPage : UserControl
{
    private readonly AppServices _services;

    public SettingsPage(AppServices services)
    {
        _services = services;
        InitializeComponent();

        LowConfidenceToggle.IsChecked = false;
        ArchiveToggle.IsChecked = false;
        RealtimeToggle.IsChecked = _services.RealtimeEnabled;
        RealtimeToggle.Checked += (_, _) => StartRealtime();
        RealtimeToggle.Unchecked += (_, _) => _services.StopRealtime();

        ExclusionSummary.Text =
            $"{_services.Exclusions.ExcludedPaths.Count} excluded paths · " +
            $"{_services.Exclusions.ExcludedExtensions.Count} excluded extensions";

        AboutText.Text =
            $"K7 TITAN engine v{_services.EngineVersion}\n" +
            "Multi-language antivirus platform: C++ engine, C minifilter, C# UI, Rust crypto, Java analyzer.";
    }

    private void StartRealtime()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _services.StartRealtime(new List<string>
        {
            Path.Combine(profile, "Downloads"),
            Path.Combine(profile, "Desktop"),
            Path.Combine(profile, "Documents")
        });
    }
}
