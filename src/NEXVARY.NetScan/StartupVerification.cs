using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
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
        ((TabItem)window.FindName("DevicesTab")).IsSelected = true;
        window.Width = window.MinWidth;
        window.Height = window.MinHeight;
        window.UpdateLayout();
        Capture(window, Path.Combine(directory, "compact.png"));
        await Task.Delay(5000);
        await window.Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        if (!window.IsVisible) throw new InvalidOperationException("MainWindow closed during verification.");
        await File.WriteAllTextAsync(Path.Combine(directory, "startup-ok.txt"), "MainWindow shown; rows and icons rendered; dark selected tab; dispatcher stable.");
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
