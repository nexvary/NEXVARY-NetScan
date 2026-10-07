using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace NEXVARY.NetScan;

public partial class App : Application
{
    private static readonly string LogDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NEXVARY",
        "NetScan");

    private static readonly string CrashLogPath = Path.Combine(LogDirectory, "startup.log");

    private bool _verification;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

        try
        {
            WriteLog("Application startup begin.");
            _verification = e.Args.Length == 2 && e.Args[0] == "--verify-startup";
            var window = new MainWindow { AutoScanOnLoad = !_verification };
            MainWindow = window;
            window.Show();
            WriteLog("Main window shown successfully.");
            if (_verification)
            {
                await StartupVerification.RunAsync(window, e.Args[1]);
                Shutdown(0);
            }
        }
        catch (Exception ex)
        {
            WriteLog("Fatal startup exception.", ex);
            if (!_verification) ShowStartupFailure(ex);
            Shutdown(1);
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        WriteLog("Unhandled UI exception.", e.Exception);
        if (_verification) { e.Handled = true; Shutdown(2); return; }
        MessageBox.Show(
            $"حدث خطأ غير متوقع داخل NEXVARY NetScan.\n\n{e.Exception.Message}\n\nتم حفظ سجل الخطأ في:\n{CrashLogPath}",
            "NEXVARY NetScan",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
            WriteLog("Unhandled application exception.", ex);
        else
            WriteLog("Unhandled non-Exception application failure.");
    }

    private static void ShowStartupFailure(Exception ex)
    {
        MessageBox.Show(
            $"تعذر تشغيل NEXVARY NetScan.\n\n{ex.Message}\n\nتم حفظ التفاصيل في:\n{CrashLogPath}",
            "خطأ بدء التشغيل",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }

    private static void WriteLog(string message, Exception? exception = null)
    {
        try
        {
            Directory.CreateDirectory(LogDirectory);
            var builder = new StringBuilder()
                .Append('[').Append(DateTimeOffset.Now.ToString("O")).Append("] ")
                .AppendLine(message);

            if (exception is not null)
                builder.AppendLine(exception.ToString());

            File.AppendAllText(CrashLogPath, builder.ToString(), Encoding.UTF8);
        }
        catch
        {
            // Logging must never become a second startup failure.
        }
    }
}
