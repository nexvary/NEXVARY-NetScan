using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Net;
using NEXVARY.NetScan.Models;
using System.Windows.Media;
using Xunit;

namespace NEXVARY.NetScan.Tests;

public sealed class StartupXamlTests
{
    [Fact]
    public void AppAndMainWindow_LoadWithoutAnyXamlException_AndSelectedTabIsDark()
    {
        Exception? failure = null;

        var thread = new Thread(() =>
        {
            try
            {
                var app = new App();
                app.InitializeComponent();

                var window = new MainWindow
                {
                    AutoScanOnLoad = false
                };

                window.Show();
                window.UpdateLayout();

                var tab = Assert.IsType<TabItem>(window.FindName("DevicesTab"));
                Assert.True(tab.IsSelected);

                tab.ApplyTemplate();
                var border = tab.Template.FindName("TabBorder", tab) as Border;
                Assert.NotNull(border);
                var brush = Assert.IsType<SolidColorBrush>(border!.Background);
                Assert.NotEqual(Colors.White, brush.Color);
                Assert.Equal(Color.FromRgb(0x17, 0x47, 0x4B), brush.Color);

                foreach (ResourceDictionary dictionary in app.Resources.MergedDictionaries)
                    foreach (var key in dictionary.Keys)
                        if (dictionary[key] is DataTemplate template)
                            Assert.IsAssignableFrom<FrameworkElement>(template.LoadContent());
                var grid = (DataGrid)window.FindName("DevicesGrid");
                grid.ItemsSource = new[] { new DeviceInfo { IpAddress = IPAddress.Loopback, IconKind = "Router" } };
                window.UpdateLayout();
                Assert.IsType<DataGridRow>(grid.ItemContainerGenerator.ContainerFromIndex(0));
                var history = (TabItem)window.FindName("HistoryTab");
                history.IsSelected = true;
                window.UpdateLayout();
                history.ApplyTemplate();
                Assert.Equal(Color.FromRgb(0x17, 0x47, 0x4B), ((SolidColorBrush)((Border)history.Template.FindName("TabBorder", history)).Background).Color);
                window.Hide();
                window.Close();
                app.Shutdown();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        if (!thread.Join(TimeSpan.FromSeconds(30))) throw new TimeoutException("WPF startup test timed out.");

        if (failure is not null)
            ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
