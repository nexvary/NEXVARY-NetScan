using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text;
using System.Windows;
using System.Windows.Data;
using Microsoft.Win32;
using NEXVARY.NetScan.Models;
using NEXVARY.NetScan.Services;

namespace NEXVARY.NetScan;

public partial class MainWindow : Window
{
    private readonly NetworkScanner _scanner = new();
    private readonly ObservableCollection<DeviceInfo> _devices = new();
    private CancellationTokenSource? _scanCancellation;

    public ICollectionView DevicesView { get; }

    public MainWindow()
    {
        InitializeComponent();
        DevicesView = CollectionViewSource.GetDefaultView(_devices);
        DevicesView.Filter = FilterDevice;
        DataContext = this;
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (_scanCancellation is not null)
            return;

        _scanCancellation = new CancellationTokenSource();
        SetScanningState(true);
        _devices.Clear();
        DeviceCountText.Text = "0";
        ScanProgress.Value = 0;

        try
        {
            var context = _scanner.GetActiveNetwork();
            LocalIpText.Text = context.LocalAddress.ToString();
            GatewayText.Text = context.Gateway?.ToString() ?? "غير معروف";
            NetworkText.Text = context.NetworkLabel;
            StatusText.Text = $"جاري فحص الشبكة عبر {context.AdapterName}…";

            var progress = new Progress<(int Done, int Total)>(p =>
            {
                ScanProgress.Value = p.Total == 0 ? 0 : p.Done * 100d / p.Total;
                StatusText.Text = $"جاري الفحص… {p.Done} من {p.Total}";
            });

            var found = await _scanner.ScanAsync(context, progress, _scanCancellation.Token);
            foreach (var device in found)
                _devices.Add(device);

            DeviceCountText.Text = _devices.Count.ToString();
            StatusText.Text = _devices.Count == 0
                ? "انتهى الفحص ولم يتم العثور على أجهزة أخرى."
                : $"تم العثور على {_devices.Count} جهاز متصل.";
            ScanProgress.Value = 100;
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "تم إيقاف الفحص.";
        }
        catch (Exception ex)
        {
            StatusText.Text = "تعذر تنفيذ الفحص.";
            MessageBox.Show(ex.Message, "NEXVARY NetScan", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            SetScanningState(false);
            UpdateActionButtons();
        }
    }

    private void StopButton_Click(object sender, RoutedEventArgs e) => _scanCancellation?.Cancel();

    private void SearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        DevicesView.Refresh();
    }

    private bool FilterDevice(object item)
    {
        if (item is not DeviceInfo device)
            return false;

        string query = SearchBox?.Text?.Trim() ?? string.Empty;
        if (query.Length == 0)
            return true;

        return device.Ip.Contains(query, StringComparison.OrdinalIgnoreCase)
            || device.HostName.Contains(query, StringComparison.OrdinalIgnoreCase)
            || device.MacAddress.Contains(query, StringComparison.OrdinalIgnoreCase)
            || device.DeviceType.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        var selected = DevicesGrid.SelectedItems.Cast<DeviceInfo>().ToList();
        var source = selected.Count > 0 ? selected : _devices.ToList();
        if (source.Count == 0)
            return;

        var sb = new StringBuilder();
        sb.AppendLine("IP\tMAC\tاسم الجهاز\tالنوع\tالحالة");
        foreach (var d in source)
            sb.AppendLine($"{d.Ip}\t{d.MacAddress}\t{d.HostName}\t{d.DeviceType}\t{d.Status}");

        try
        {
            Clipboard.SetText(sb.ToString());
            StatusText.Text = $"تم نسخ {source.Count} نتيجة.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "تعذر النسخ", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_devices.Count == 0)
            return;

        var dialog = new SaveFileDialog
        {
            Title = "تصدير نتائج NEXVARY NetScan",
            Filter = "CSV (*.csv)|*.csv",
            FileName = $"NEXVARY-NetScan-{DateTime.Now:yyyyMMdd-HHmm}.csv"
        };
        if (dialog.ShowDialog(this) != true)
            return;

        var sb = new StringBuilder();
        sb.AppendLine("IP,MAC,Host Name,Device Type,Status");
        foreach (var d in _devices)
        {
            sb.AppendLine(string.Join(",", new[]
            {
                Csv(d.Ip), Csv(d.MacAddress), Csv(d.HostName), Csv(d.DeviceType), Csv(d.Status)
            }));
        }

        File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true));
        StatusText.Text = "تم تصدير النتائج بنجاح.";
    }

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"")}\"";

    private void SetScanningState(bool scanning)
    {
        ScanButton.IsEnabled = !scanning;
        StopButton.IsEnabled = scanning;
        SearchBox.IsEnabled = !scanning;
        if (scanning)
        {
            CopyButton.IsEnabled = false;
            ExportButton.IsEnabled = false;
        }
    }

    private void UpdateActionButtons()
    {
        bool hasResults = _devices.Count > 0;
        CopyButton.IsEnabled = hasResults;
        ExportButton.IsEnabled = hasResults;
    }
}
