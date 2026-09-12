using System;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

namespace DOGE.Desktop
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // 1. Register unhandled exception handlers immediately
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                try
                {
                    var msg = $"[AppDomain Fatal] {args.ExceptionObject}";
                    File.AppendAllText("doge_crash.log", $"[{DateTime.UtcNow:O}] {msg}\n");
                    MessageBox.Show(msg, "DOGE Desktop Fatal Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch { }
            };

            DispatcherUnhandledException += (s, args) =>
            {
                try
                {
                    var msg = $"[Dispatcher UI Exception] {args.Exception}";
                    File.AppendAllText("doge_crash.log", $"[{DateTime.UtcNow:O}] {msg}\n");
                    MessageBox.Show($"UI Exception: {args.Exception.Message}\n\nCheck doge_crash.log for details.", "DOGE Desktop UI Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                catch { }
                args.Handled = true;
            };

            base.OnStartup(e);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            base.OnExit(e);
        }
    }
}
