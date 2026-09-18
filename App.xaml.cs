using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace AngelMineChecker
{
    public partial class App : Application
    {
        protected override async void OnStartup(StartupEventArgs e)
        {
            AppDomain.CurrentDomain.UnhandledException += (s, ev) =>
            {
                try
                {
                    File.AppendAllText("crash.log", $"[AppDomain Error] {DateTime.Now}: {ev.ExceptionObject}\r\n");
                }
                catch { }
            };

            DispatcherUnhandledException += (s, ev) =>
            {
                try
                {
                    File.AppendAllText("crash.log", $"[Dispatcher Error] {DateTime.Now}: {ev.Exception}\r\n");
                }
                catch { }
            };

            base.OnStartup(e);

            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            if (!AssetDownloader.AreAssetsInstalled())
            {
                var splash = new SplashWindow();
                splash.Show();
                await splash.StartDownloadAsync();
                splash.Close();
            }

            var main = new MainWindow();
            MainWindow = main;
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            main.Show();
        }
    }
}
