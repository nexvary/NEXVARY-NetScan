using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows.Controls;
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
        thread.Join();

        if (failure is not null)
            ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
