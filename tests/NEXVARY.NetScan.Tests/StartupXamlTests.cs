using System.Runtime.ExceptionServices;
using System.Threading;
using Xunit;

namespace NEXVARY.NetScan.Tests;

public sealed class StartupXamlTests
{
    [Fact]
    public void AppAndMainWindow_LoadWithoutAnyXamlException()
    {
        Exception? failure = null;

        var thread = new Thread(() =>
        {
            try
            {
                var app = new App();
                app.InitializeComponent();

                var window = new MainWindow();
                window.Show();
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
