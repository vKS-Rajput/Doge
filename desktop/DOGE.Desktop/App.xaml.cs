using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace DOGE.Desktop
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                try
                {
                    File.AppendAllText("doge_crash.log", $"[{DateTime.UtcNow:O}] [AppDomain Unhandled] {args.ExceptionObject}\n");
                }
                catch { }
            };

            DispatcherUnhandledException += (s, args) =>
            {
                try
                {
                    File.AppendAllText("doge_crash.log", $"[{DateTime.UtcNow:O}] [Dispatcher Unhandled] {args.Exception}\n");
                }
                catch { }
                args.Handled = true;
            };

            base.OnStartup(e);
        }
    }
}
