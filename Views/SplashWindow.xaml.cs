using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace AngelMineChecker
{
    public partial class SplashWindow : Window
    {
        public SplashWindow()
        {
            InitializeComponent();
        }

        protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
        {
            base.OnMouseLeftButtonDown(e);
            if (e.ButtonState == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        public async Task StartDownloadAsync()
        {
            await Task.Delay(100);

            bool ok = await AssetDownloader.DownloadAndExtractAsync(
                pct =>
                {
                    Dispatcher.BeginInvoke((Action)(() =>
                    {
                        double max = ActualWidth > 0 ? ActualWidth - 34 : 374;
                        pbarFill.Width = Math.Max(0, Math.Min(max, (pct / 100.0) * max));
                    }));
                },
                status => { }
            );

            double full = ActualWidth > 0 ? ActualWidth - 34 : 374;
            pbarFill.Width = full;
            await Task.Delay(300);
        }
    }
}
