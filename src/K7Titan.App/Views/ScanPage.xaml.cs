using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using K7Titan.App.Services;
using K7Titan.Core;
using Microsoft.Win32;
using Wpf.Ui.Controls;

namespace K7Titan.App.Views;

public partial class ScanPage : UserControl
{
    private readonly AppServices _services;
    private readonly ObservableCollection<Detection> _results = new();
    private CancellationTokenSource? _cts;
    private ScanReport? _lastReport;

    public ScanPage(AppServices services)
    {
        _services = services;
        InitializeComponent();
        ResultsGrid.ItemsSource = _results;
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select folder to scan" };
        if (dialog.ShowDialog() == true)
        {
            PathBox.Text = dialog.FolderName;
        }
    }

    private async void OnScan(object sender, RoutedEventArgs e)
    {
        var target = PathBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(target) || (!Directory.Exists(target) && !File.Exists(target)))
        {
            System.Windows.MessageBox.Show("Please choose an existing file or folder.", "K7 TITAN");
            return;
        }

        _cts = new CancellationTokenSource();
        _results.Clear();
        _lastReport = null;
        ScanButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        Progress.Visibility = Visibility.Visible;
        StatusText.Text = "Scanning...";
        StatsText.Text = string.Empty;

        var options = new ScanOptions { Recurse = true };
        var progress = new Progress<ScanProgress>(p =>
        {
            StatusText.Text = $"Scanning: {Shorten(p.CurrentFile)}";
            StatsText.Text = $"Scanned {p.FilesScanned} · Threats {p.ThreatsFound}";
        });

        try
        {
            var report = await _services.Orchestrator.ScanAsync(target, options, progress, _cts.Token);
            _lastReport = report;
            foreach (var detection in report.Detections)
            {
                _results.Add(detection);
                _services.Log.Add(detection);
            }

            StatusText.Text = report.IsClean
                ? "No threats found."
                : $"{report.Detections.Count} threat(s) found.";
            var s = report.Statistics;
            StatsText.Text = $"Scanned {s.FilesScanned} · Skipped {s.FilesSkipped} · Errors {s.Errors} · {s.Elapsed.TotalSeconds:F1}s";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            StatusText.Text = "Scan failed.";
            System.Windows.MessageBox.Show(ex.Message, "K7 TITAN — Scan error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
        }
        finally
        {
            ScanButton.IsEnabled = true;
            CancelButton.IsEnabled = false;
            Progress.Visibility = Visibility.Collapsed;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
    }

    private async void OnQuarantine(object sender, RoutedEventArgs e)
    {
        if (_results.Count == 0)
        {
            System.Windows.MessageBox.Show("No threats to quarantine.", "K7 TITAN");
            return;
        }

        var quarantined = 0;
        foreach (var detection in _results.ToArray())
        {
            var box = new Wpf.Ui.Controls.MessageBox
            {
                Title = "K7 TITAN — Confirm quarantine",
                Content = $"Move this file to quarantine?\n\nThreat: {detection.ThreatName}\nLevel: {detection.Level}\nFile: {detection.FilePath}",
                PrimaryButtonText = "Quarantine",
                CloseButtonText = "Allow",
                PrimaryButtonAppearance = ControlAppearance.Danger
            };

            var choice = await box.ShowDialogAsync();
            var confirmed = choice == Wpf.Ui.Controls.MessageBoxResult.Primary;
            var record = await _services.Quarantine.QuarantineAsync(
                detection.FilePath, detection.ThreatName, detection.Score, confirmed, CancellationToken.None);

            if (record is not null && record.Decision == QuarantineDecision.AllowToQuarantine)
            {
                quarantined++;
                _results.Remove(detection);
            }
            else if (record is not null && record.Decision == QuarantineDecision.Rejected)
            {
                _services.Log.Add(new Detection(detection.FilePath, "Allowed by user", ThreatLevel.Clean, 0, "user", DateTime.UtcNow));
            }
        }

        StatusText.Text = $"{quarantined} file(s) moved to quarantine.";
    }

    private async void OnExport(object sender, RoutedEventArgs e)
    {
        if (_lastReport is null)
        {
            System.Windows.MessageBox.Show("Run a scan first.", "K7 TITAN");
            return;
        }

        var outDir = Path.Combine(AppContext.BaseDirectory, "reports");
        var json = await _services.Reports.WriteJsonAsync(_lastReport, outDir, CancellationToken.None);
        await _services.Reports.WriteCsvAsync(_lastReport, outDir, CancellationToken.None);
        System.Windows.MessageBox.Show($"Report written to:\n{json}", "K7 TITAN");
    }

    private static string Shorten(string path) =>
        path.Length <= 70 ? path : "..." + path[^67..];
}
