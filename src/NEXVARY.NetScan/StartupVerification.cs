using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Text.Json;
using NEXVARY.NetScan.Analysis;
using NEXVARY.NetScan.Models;

namespace NEXVARY.NetScan;

internal static class StartupVerification
{
    public static async Task RunAsync(MainWindow window, string directory)
    {
        Directory.CreateDirectory(directory);
        if (!window.IsVisible || new System.Windows.Interop.WindowInteropHelper(window).Handle == IntPtr.Zero)
            throw new InvalidOperationException("MainWindow is not visible.");
        foreach (var item in new[] { ("DeviceCountText", "3"), ("LocalIpText", "192.168.1.20"), ("GatewayText", "192.168.1.1"), ("NetworkText", "192.168.1.0/24"), ("DnsText", "192.168.1.1 / 8.8.8.8"), ("AdapterText", "Intel Ethernet — UI verification"), ("ConnectionText", "Ethernet"), ("SpeedText", "1000 Mbps"), ("StatusText", "بيانات اختبار واجهة — ليست نتيجة فحص شبكة فعلية") })
            ((TextBlock)window.FindName(item.Item1)).Text = item.Item2;
        var grid = (DataGrid)window.FindName("DevicesGrid");
        grid.ItemsSource = new[] {
            new DeviceInfo { IpAddress = IPAddress.Parse("192.168.1.1"), HostName = "router-demo", MacAddress = "4C:5E:0C:11:22:33", Vendor = "MikroTik", DeviceType = "راوتر / بوابة", IconKind = "Router", IsGateway = true },
            new DeviceInfo { IpAddress = IPAddress.Parse("192.168.1.20"), HostName = "DESKTOP-QA", MacAddress = "02:11:22:33:44:55", Vendor = "MAC خاص/عشوائي", DnsServer = "192.168.1.1 / 8.8.8.8", DeviceType = "هذا الكمبيوتر", IconKind = "Computer", IsLocalComputer = true },
            new DeviceInfo { IpAddress = IPAddress.Parse("192.168.1.30"), HostName = "ipc-front", DeviceType = "كاميرا / مراقبة", IconKind = "Camera" }
        };
        foreach (ResourceDictionary dictionary in Application.Current.Resources.MergedDictionaries)
            foreach (var key in dictionary.Keys)
                if (dictionary[key] is DataTemplate template)
                {
                    if (template.LoadContent() is not FrameworkElement element) throw new InvalidOperationException($"Icon {key} failed.");
                    element.Measure(new Size(64, 64));
                    element.Arrange(new Rect(0, 0, 64, 64));
                }
        window.UpdateLayout();
        grid.SelectedIndex = 1;
        await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        if (grid.ItemContainerGenerator.ContainerFromIndex(0) is not DataGridRow) throw new InvalidOperationException("Device rows did not render.");
        Capture(window, Path.Combine(directory, "devices.png"));
        var history = (TabItem)window.FindName("HistoryTab");
        var historyGrid = (DataGrid)window.FindName("HistoryGrid");
        historyGrid.ItemsSource = ((IEnumerable<DeviceInfo>)grid.ItemsSource).Select(d => new DeviceHistoryEntry {
            Ip = d.Ip, MacAddress = d.MacAddress, HostName = d.HostName, Vendor = d.Vendor, DeviceType = d.DeviceType,
            IconKind = d.IconKind, DnsServer = d.DnsServer, FirstSeenUtc = DateTimeOffset.UtcNow.AddDays(-1), LastSeenUtc = DateTimeOffset.UtcNow, IsOnline = true
        }).ToArray();
        history.IsSelected = true;
        await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        window.UpdateLayout();
        history.ApplyTemplate();
        if (history.Template.FindName("TabBorder", history) is not Border border || border.Background is not SolidColorBrush brush || brush.Color.R > 90)
            throw new InvalidOperationException("Selected tab is not dark.");
        if (historyGrid.ItemContainerGenerator.ContainerFromIndex(0) is not DataGridRow) throw new InvalidOperationException("History rows did not render.");
        Capture(window, Path.Combine(directory, "history.png"));
        // Import a real JSONL fixture through the production pipeline; never launch a scanner.
        var fixture = Path.Combine(directory, "security-fixture.jsonl");
        var captured = DateTimeOffset.UtcNow;
        window.Analysis.SetSnapshot(new DiscoverySnapshot(Guid.NewGuid(), captured, "qa-interface", "UI verification",
            "192.168.1.20", "255.255.255.0", "192.168.1.1",
            Array.AsReadOnly(new[] { new DeviceObservation("192.168.1.1", "4C:5E:0C:11:22:33", "router-demo") })));
        window.Analysis.LinkToCurrentSnapshot = true;
        await File.WriteAllTextAsync(fixture, JsonSerializer.Serialize(new Dictionary<string, object?> {
            ["template-id"] = "qa-demonstration-only", ["matched-at"] = "http://192.168.1.1:80/private?token=not-stored",
            ["timestamp"] = captured, ["type"] = "http", ["matcher-status"] = true,
            ["info"] = new { name = "بيانات اختبار واجهة — ليست ثغرة حقيقية", severity = "info" }
        }));
        await window.Analysis.ImportAsync(fixture);
        if (window.Analysis.Findings.Count != 1 || window.Analysis.Findings[0].Finding.Correlation != CorrelationState.Candidate)
            throw new InvalidOperationException("Security fixture import/correlation failed.");
        var security = (TabItem)window.FindName("SecurityTab");
        security.IsSelected = true;
        await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        window.UpdateLayout();
        var findingsGrid = (DataGrid)window.FindName("FindingsGrid");
        findingsGrid.SelectedIndex = 0;
        window.UpdateLayout();
        if (findingsGrid.ItemContainerGenerator.ContainerFromIndex(0) is not DataGridRow)
            throw new InvalidOperationException("Security rows did not render.");
        if (window.Analysis.SelectedFinding is null) throw new InvalidOperationException("Security selection binding failed.");
        VerifySecurityLayout(findingsGrid);
        Capture(window, Path.Combine(directory, "security.png"));
        window.Width = window.MinWidth;
        window.Height = window.MinHeight;
        window.UpdateLayout();
        VerifySecurityLayout(findingsGrid);
        Capture(window, Path.Combine(directory, "security-compact.png"));
        ((TabItem)window.FindName("DevicesTab")).IsSelected = true;
        window.Width = window.MinWidth;
        window.Height = window.MinHeight;
        window.UpdateLayout();
        Capture(window, Path.Combine(directory, "compact.png"));
        await Task.Delay(5000);
        await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        if (!window.IsVisible) throw new InvalidOperationException("MainWindow closed during verification.");
        await File.WriteAllTextAsync(Path.Combine(directory, "startup-ok.txt"), "MainWindow shown; rows and icons rendered; dark selected tab; security import/correlation/selection; dispatcher stable.");
    }

    private static void VerifySecurityLayout(DataGrid grid)
    {
        if (grid.ActualHeight < 160 || grid.ItemContainerGenerator.ContainerFromIndex(0) is not DataGridRow row)
            throw new InvalidOperationException("Security workspace is too short to use.");
        var bounds = row.TransformToAncestor(grid).TransformBounds(new Rect(row.RenderSize));
        if (bounds.Top < 0 || bounds.Bottom > grid.ActualHeight || bounds.Height < 40)
            throw new InvalidOperationException("Security result row is clipped.");
    }

    private static void Capture(Window window, string path)
    {
        var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }
}
