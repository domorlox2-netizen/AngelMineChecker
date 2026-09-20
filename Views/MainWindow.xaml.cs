using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Threading;
using System.Threading.Tasks;
using AngelMineChecker.Services;

namespace AngelMineChecker
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            try
            {
                InitializeComponent();
                InitCheckLogs();
                RefreshProcesses();
                EnsureToolsDirectory();
                Loaded += MainWindow_Loaded;
            }
            catch (Exception ex)
            {
                string log = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash.log");
                File.WriteAllText(log, $"[MainWindow Error] {DateTime.Now}: {ex}\r\n");
            }
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            if (!AssetDownloader.AreAssetsInstalled())
            {
                await EnsureAssetsDownloadedAsync();
            }
        }

        private async Task EnsureAssetsDownloadedAsync()
        {
            if (pnlDownloadProgress != null)
            {
                pnlDownloadProgress.Visibility = Visibility.Visible;
                txtDownloadStatus.Text = "Загрузка компонентов (0%)...";
                pbDownload.Value = 0;
            }

            bool ok = await AssetDownloader.DownloadAndExtractAsync(
                pct =>
                {
                    Dispatcher.BeginInvoke((Action)(() =>
                    {
                        if (pbDownload != null) pbDownload.Value = pct;
                        if (txtDownloadStatus != null) txtDownloadStatus.Text = $"Загрузка компонентов ({pct}%)...";
                    }));
                },
                status =>
                {
                    Dispatcher.BeginInvoke((Action)(() =>
                    {
                        if (txtDownloadStatus != null) txtDownloadStatus.Text = status;
                    }));
                }
            );

            if (ok)
            {
                if (txtDownloadStatus != null) txtDownloadStatus.Text = "Компоненты установлены";
                await Task.Delay(1500);
                if (pnlDownloadProgress != null) pnlDownloadProgress.Visibility = Visibility.Collapsed;
            }
            else
            {
                if (txtDownloadStatus != null) txtDownloadStatus.Text = "Ошибка загрузки";
                await Task.Delay(3000);
                if (pnlDownloadProgress != null) pnlDownloadProgress.Visibility = Visibility.Collapsed;
            }
        }

        private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ButtonState == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        private void BtnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void SidebarTrigger_MouseEnter(object sender, MouseEventArgs e)
        {
            OpenSidebar();
        }

        private void SidebarTrigger_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (sidebar != null && sidebar.Width < 50)
            {
                OpenSidebar();
            }
            else
            {
                CloseSidebar();
            }
        }

        private void Sidebar_MouseEnter(object sender, MouseEventArgs e)
        {
            OpenSidebar();
        }

        private void Sidebar_MouseLeave(object sender, MouseEventArgs e)
        {
            CloseSidebar();
        }

        private void OpenSidebar()
        {
            if (sidebar == null) return;

            DoubleAnimation widthAnim = new DoubleAnimation
            {
                To = 160,
                Duration = TimeSpan.FromMilliseconds(180),
                DecelerationRatio = 0.3
            };
            sidebar.BeginAnimation(WidthProperty, widthAnim);

            if (sidebarShadow != null)
            {
                DoubleAnimation shadowAnim = new DoubleAnimation
                {
                    To = 0.7,
                    Duration = TimeSpan.FromMilliseconds(180)
                };
                sidebarShadow.BeginAnimation(DropShadowEffect.OpacityProperty, shadowAnim);
            }
        }

        private void CloseSidebar()
        {
            if (sidebar == null) return;

            DoubleAnimation widthAnim = new DoubleAnimation
            {
                To = 0,
                Duration = TimeSpan.FromMilliseconds(180),
                AccelerationRatio = 0.3
            };
            sidebar.BeginAnimation(WidthProperty, widthAnim);

            if (sidebarShadow != null)
            {
                DoubleAnimation shadowAnim = new DoubleAnimation
                {
                    To = 0.0,
                    Duration = TimeSpan.FromMilliseconds(180)
                };
                sidebarShadow.BeginAnimation(DropShadowEffect.OpacityProperty, shadowAnim);
            }
        }

        private void NavTab_Checked(object sender, RoutedEventArgs e)
        {
            if (viewTools == null || viewCheck == null || viewFaq == null)
                return;

            viewCheck.Visibility = Visibility.Collapsed;
            viewTools.Visibility = Visibility.Collapsed;
            if (viewOther != null) viewOther.Visibility = Visibility.Collapsed;
            viewFaq.Visibility = Visibility.Collapsed;

            if (tabBtnCheck != null && tabBtnCheck.IsChecked == true)
            {
                viewCheck.Visibility = Visibility.Visible;
            }
            else if (tabBtnTools != null && tabBtnTools.IsChecked == true)
            {
                viewTools.Visibility = Visibility.Visible;
            }
            else if (tabBtnOther != null && tabBtnOther.IsChecked == true)
            {
                if (viewOther != null)
                {
                    viewOther.Visibility = Visibility.Visible;
                    LoadOtherTabData();
                }
            }
            else if (tabBtnFaq != null && tabBtnFaq.IsChecked == true)
            {
                viewFaq.Visibility = Visibility.Visible;
            }
        }

        private void ShowToast(string message, string icon = "ℹ️", bool isError = false)
        {
        }

        private string GetToolsDirectory()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string p1 = Path.Combine(baseDir, "tools");
            if (Directory.Exists(p1)) return p1;

            try
            {
                string p2 = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "tools"));
                if (Directory.Exists(p2)) return p2;
            }
            catch { }

            string p3 = Path.Combine(Directory.GetCurrentDirectory(), "tools");
            if (Directory.Exists(p3)) return p3;

            return p1;
        }

        private void EnsureToolsDirectory()
        {
            try
            {
                string toolsDir = GetToolsDirectory();
                if (!Directory.Exists(toolsDir))
                {
                    Directory.CreateDirectory(toolsDir);
                }
            }
            catch { }
        }

        private string FindExecutable(params string[] candidateNames)
        {
            string toolsDir = GetToolsDirectory();

            foreach (var name in candidateNames)
            {
                if (string.IsNullOrEmpty(name)) continue;

                string direct = Path.Combine(toolsDir, name);
                if (File.Exists(direct)) return direct;

                if (Directory.Exists(toolsDir))
                {
                    try
                    {
                        var matches = Directory.GetFiles(toolsDir, name, SearchOption.AllDirectories);
                        if (matches.Length > 0) return matches[0];
                    }
                    catch { }
                }

                string nextToExe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, name);
                if (File.Exists(nextToExe)) return nextToExe;

                string curDir = Path.Combine(Directory.GetCurrentDirectory(), name);
                if (File.Exists(curDir)) return curDir;
            }

            foreach (var name in candidateNames)
            {
                if (name.IndexOf("everything", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    string p1 = @"C:\Program Files\Everything\Everything.exe";
                    if (File.Exists(p1)) return p1;
                    string p2 = @"C:\Program Files (x86)\Everything\Everything.exe";
                    if (File.Exists(p2)) return p2;
                }
                else if (name.IndexOf("systeminformer", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         name.IndexOf("processhacker", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    string p1 = @"C:\Program Files\System Informer\SystemInformer.exe";
                    if (File.Exists(p1)) return p1;
                    string p2 = @"C:\Program Files\Process Hacker 2\ProcessHacker.exe";
                    if (File.Exists(p2)) return p2;
                }
            }

            return null;
        }

        private async void LaunchTool(string toolTitle, params string[] candidateNames)
        {
            if (AssetDownloader.IsDownloading)
            {
                ShowToast("Идет скачивание компонентов, подождите...", "⏳");
                return;
            }

            if (!AssetDownloader.AreAssetsInstalled())
            {
                ShowToast("Скачивание компонентов с GitHub...", "⬇️");
                await EnsureAssetsDownloadedAsync();
            }

            string path = FindExecutable(candidateNames);
            if (path != null && File.Exists(path))
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = path,
                        WorkingDirectory = Path.GetDirectoryName(path),
                        UseShellExecute = true
                    };
                    Process.Start(psi);
                    ShowToast($"{toolTitle} открыт ({Path.GetFileName(path)})", "🚀");
                }
                catch (Exception ex)
                {
                    ShowToast($"Ошибка при запуске {toolTitle}: {ex.Message}", "⚠️", true);
                }
            }
            else
            {
                string preferredName = candidateNames.Length > 0 ? candidateNames[0] : "утилита";
                ShowToast($"Файл {preferredName} не найден в папке tools/", "📁", true);
            }
        }

        private void BtnLaunchEverything_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("Everything", "Everything.exe", "everything.exe");
        }

        private void BtnLaunchShellBagAnalyzer_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("ShellBagAnalyzer", "ShellBagAnalyzer.exe", "ShellBagsView.exe", "ShellBags.exe");
        }

        private void BtnLaunchBrowserDownloads_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("BrowserDownloadsView", "BrowserDownloadsView.exe");
        }

        private void BtnLaunchExecutedPrograms_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("ExecutedProgramsList", "ExecutedProgramsList.exe", "ExecutedProgramms.exe");
        }

        private void BtnLaunchUSBDeview_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("USBDeview", "USBDeview.exe");
        }

        private void BtnLaunchWinPrefetch_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("WinPrefetchView", "WinPrefetchView.exe");
        }

        private void BtnLaunchBrowsingHistory_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("BrowsingHistoryView", "BrowsingHistoryView.exe", "BrowserHistoryView.exe");
        }

        private void BtnLaunchJumpListView_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("JumpListView", "JumpListsView.exe", "JumpListView.exe");
        }

        private void BtnLaunchUserAssist_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("UserAssistView", "UserAssistView.exe");
        }

        private void BtnLaunchProcessHackerFiles_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("Process Hacker", "ProcessHacker.exe", "ProcessHacker\\x64\\ProcessHacker.exe");
        }

        private void BtnLaunchJournalTrace_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("JournalTrace", "JournalTrace.exe");
        }

        private void BtnLaunchSystemInformer_Click(object sender, RoutedEventArgs e)
        {
            LaunchTool("System Informer", "SystemInformer.exe", "SystemInformer\\SystemInformer.exe", "ProcessHacker.exe");
        }

        private void BtnSystemServices_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start("services.msc");
                ShowToast("Системные службы открыты", "⚙️");
            }
            catch (Exception ex)
            {
                ShowToast($"Ошибка: {ex.Message}", "⚠️", true);
            }
        }

        private void BtnDataUsage_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo("ms-settings:datausage") { UseShellExecute = true });
                ShowToast("Использование данных открыто", "📊");
            }
            catch (Exception ex)
            {
                ShowToast($"Ошибка: {ex.Message}", "⚠️", true);
            }
        }

        private void BtnNvidiaControlPanel_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string p1 = @"C:\Program Files\NVIDIA Corporation\Control Panel Client\nvcplui.exe";
                if (File.Exists(p1))
                {
                    Process.Start(p1);
                    ShowToast("Панель управления NVIDIA открыта", "🟩");
                    return;
                }

                Process.Start(new ProcessStartInfo("control.exe", "/name Microsoft.NVIDIAControlPanel") { UseShellExecute = true });
                ShowToast("Панель управления NVIDIA открыта", "🟩");
            }
            catch (Exception ex)
            {
                ShowToast($"Панель NVIDIA не найдена или не поддерживается: {ex.Message}", "⚠️", true);
            }
        }

        private void BtnOpenFolder_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string tag)
            {
                string targetDir = null;
                switch (tag.ToLower())
                {
                    case "recent":
                        targetDir = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
                        break;
                    case "prefetch":
                        targetDir = @"C:\Windows\Prefetch";
                        break;
                    case "appdata":
                        targetDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                        break;
                    case "temp":
                        targetDir = Path.GetTempPath();
                        break;
                }

                if (!string.IsNullOrEmpty(targetDir))
                {
                    try
                    {
                        if (!Directory.Exists(targetDir))
                        {
                            Directory.CreateDirectory(targetDir);
                        }
                        Process.Start("explorer.exe", targetDir);
                        ShowToast($"Папка {Path.GetFileName(targetDir)} открыта", "📂");
                    }
                    catch (Exception ex)
                    {
                        ShowToast($"Не удалось открыть папку: {ex.Message}", "⚠️", true);
                    }
                }
            }
        }

        private void BtnTelegram_Click(object sender, RoutedEventArgs e)
        {
            OpenUrl("https://t.me/angelgriefnet");
        }

        private void BtnDiscord_Click(object sender, RoutedEventArgs e)
        {
            OpenUrl("https://discord.gg/u7AwfNxHE2");
        }

        private void OpenUrl(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                ShowToast($"Открыта ссылка: {url}", "🔗");
            }
            catch (Exception ex)
            {
                ShowToast($"Не удалось открыть ссылку: {ex.Message}", "⚠️", true);
            }
        }

        private string GetCheckLogsText()
        {
            if (txtCheckLogs == null || txtCheckLogs.Document == null) return "";
            var range = new TextRange(txtCheckLogs.Document.ContentStart, txtCheckLogs.Document.ContentEnd);
            return range.Text.TrimEnd();
        }

        private void ClearCheckLogs()
        {
            if (txtCheckLogs != null && txtCheckLogs.Document != null)
            {
                txtCheckLogs.Document.Blocks.Clear();
            }
        }

        private void InitCheckLogs()
        {
            ClearCheckLogs();
        }

        private void AppendLog(string message)
        {
            if (txtCheckLogs == null) return;

            if (message != null && message.Contains("\n"))
            {
                var lines = message.Replace("\r\n", "\n").Split('\n');
                foreach (var line in lines)
                {
                    AppendLog(line);
                }
                return;
            }

            var doc = txtCheckLogs.Document;
            if (doc == null)
            {
                doc = new FlowDocument { PagePadding = new Thickness(0) };
                txtCheckLogs.Document = doc;
            }

            var p = new Paragraph { Margin = new Thickness(0, 0, 0, 1) };

            if (string.IsNullOrEmpty(message))
            {
                p.Inlines.Add(new Run(" "));
                doc.Blocks.Add(p);
                txtCheckLogs.ScrollToEnd();
                return;
            }

            string trimmed = message.TrimStart();
            bool isSummaryOrRaw = trimmed.StartsWith("=") || trimmed.StartsWith("─") ||
                                  trimmed.StartsWith("[🔴") || trimmed.StartsWith("[⚠️") ||
                                  trimmed.StartsWith("[📁") || trimmed.StartsWith("✅") ||
                                  trimmed.StartsWith("•") || message.StartsWith("   ") ||
                                  trimmed.StartsWith("Итоги проверки", StringComparison.OrdinalIgnoreCase) ||
                                  trimmed.StartsWith("Предупреждения", StringComparison.OrdinalIgnoreCase) ||
                                  trimmed.StartsWith("Читы и инжекты", StringComparison.OrdinalIgnoreCase) ||
                                  trimmed.StartsWith("JournalTrace", StringComparison.OrdinalIgnoreCase) ||
                                  trimmed.StartsWith("Чисто:", StringComparison.OrdinalIgnoreCase) ||
                                  trimmed.StartsWith("Вердикт", StringComparison.OrdinalIgnoreCase);

            if (!isSummaryOrRaw)
            {
                p.Inlines.Add(new Run($"[{DateTime.Now:HH:mm:ss}] ")
                {
                    Foreground = new SolidColorBrush(Color.FromRgb(100, 116, 139)),
                    FontWeight = FontWeights.Normal
                });
            }

            SolidColorBrush textBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225));
            FontWeight weight = FontWeights.Normal;

            string mLower = message.ToLowerInvariant();

            if (mLower.StartsWith("вердикт"))
            {
                if (mLower.Contains("бан"))
                {
                    textBrush = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                }
                else if (mLower.Contains("руками"))
                {
                    textBrush = new SolidColorBrush(Color.FromRgb(245, 158, 11));
                }
                else
                {
                    textBrush = new SolidColorBrush(Color.FromRgb(16, 185, 129));
                }
                weight = FontWeights.Bold;
            }
            else if (trimmed.StartsWith("=") || mLower.StartsWith("итоги проверки"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(255, 122, 0));
                weight = FontWeights.Bold;
            }
            else if (trimmed.StartsWith("[🔴") || mLower.StartsWith("читы и инжекты"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                weight = FontWeights.Bold;
            }
            else if (trimmed.StartsWith("[⚠️") || mLower.StartsWith("предупреждения"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(245, 158, 11));
                weight = FontWeights.Bold;
            }
            else if (trimmed.StartsWith("[📁") || mLower.StartsWith("journaltrace"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(56, 189, 248));
                weight = FontWeights.Bold;
            }
            else if (trimmed.StartsWith("✅") || mLower.StartsWith("чисто:"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(16, 185, 129));
                weight = FontWeights.Bold;
            }
            else if (mLower.Contains("doomsday") || mLower.Contains("думик") || mLower.Contains("чит") ||
                     mLower.Contains("инжект") || mLower.Contains("systemdlc") || mLower.Contains("cortex") ||
                     mLower.Contains("luminar") || mLower.Contains("sk3d") || mLower.Contains("triggerbot") ||
                     mLower.Contains("aimassist") || mLower.Contains("userassist") || mLower.Contains("recentdocs"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(248, 113, 113));
                if (trimmed.StartsWith("•")) weight = FontWeights.SemiBold;
            }
            else if (mLower.Contains("остановлен сервис") || mLower.Contains("отключен драйвер") ||
                     mLower.Contains("отключен") || mLower.Contains("предупреждение") || mLower.Contains("внимание"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(251, 191, 36));
            }
            else if (mLower.Contains("удален") || mLower.Contains("deleted"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(56, 189, 248));
            }
            else if (mLower.Contains("чисто") || mLower.Contains("нарушений не обнаружено") || mLower.Contains("не обнаружено"))
            {
                textBrush = new SolidColorBrush(Color.FromRgb(16, 185, 129));
            }

            p.Inlines.Add(new Run(message) { Foreground = textBrush, FontWeight = weight });
            doc.Blocks.Add(p);

            txtCheckLogs.ScrollToEnd();
        }

        private ScanOptions GetScanOptions()
        {
            return new ScanOptions
            {
                CheckCortex = chkCortex?.IsChecked == true,
                CheckSystemDlc = chkSystemDlc?.IsChecked == true,
                CheckDoomsday = chkDoomsday?.IsChecked == true,
                CheckLuminar = chkLuminar?.IsChecked == true
            };
        }

        private void RefreshProcesses()
        {
            if (comboProcesses == null) return;

            comboProcesses.Items.Clear();

            try
            {
                var candidateProcesses = MinecraftProcessDetector.FindCandidates();

                if (candidateProcesses.Count > 0)
                {
                    foreach (var item in candidateProcesses)
                    {
                        comboProcesses.Items.Add(item.DisplayText);
                    }
                    comboProcesses.SelectedIndex = 0;
                }
                else
                {
                    comboProcesses.Items.Add("Minecraft не найден (введите PID вручную)");
                    comboProcesses.SelectedIndex = 0;
                    if (txtProcessId != null && string.IsNullOrEmpty(txtProcessId.Text))
                    {
                        txtProcessId.Text = "";
                    }
                }
            }
            catch
            {
                comboProcesses.Items.Add("Ошибка сканирования процессов");
                comboProcesses.SelectedIndex = 0;
            }
        }

        private void ComboProcesses_DropDownOpened(object sender, EventArgs e)
        {
            RefreshProcesses();
        }

        private void ComboProcesses_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (comboProcesses == null || comboProcesses.SelectedItem == null || txtProcessId == null) return;
            string selected = comboProcesses.SelectedItem.ToString();

            var match = Regex.Match(selected, @"PID:\s*(\d+)");
            if (match.Success)
            {
                txtProcessId.Text = match.Groups[1].Value;
            }
        }

        private void TxtProcessId_TextChanged(object sender, TextChangedEventArgs e)
        {
        }

        private bool _isScanning = false;

        private async void BtnQuickCheck_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning) return;
            _isScanning = true;

            var options = GetScanOptions();
            var sessionLogs = new List<string>();
            var startTime = DateTime.Now;
            List<string> banReasons = new List<string>();

            int? targetPid = null;
            if (txtProcessId != null && int.TryParse(txtProcessId.Text.Trim(), out int parsedPid) && parsedPid > 0)
            {
                targetPid = parsedPid;
            }
            string targetProcName = comboProcesses?.SelectedItem?.ToString();

            try
            {
                await Task.Run(async () =>
                {
                    banReasons = await QuickScanner.RunAsync(msg =>
                    {
                        lock (sessionLogs)
                        {
                            sessionLogs.Add(string.IsNullOrEmpty(msg) ? "" : $"[{DateTime.Now:HH:mm:ss}] {msg}");
                        }
                        Dispatcher.BeginInvoke((Action)(() => AppendLog(msg)));
                    }, options);
                });

                var report = new ReportModel
                {
                    ScanType = "Быстрая проверка",
                    StartTime = startTime,
                    EndTime = DateTime.Now,
                    TargetPid = targetPid,
                    TargetProcessName = targetProcName,
                    Options = options,
                    BanReasons = banReasons,
                    Logs = sessionLogs,
                    Accounts = AccountScanner.FindAllAccounts()
                };
                HtmlReportGenerator.SaveReport(report);
            }
            catch (Exception ex)
            {
                AppendLog($"Ошибка проверки: {ex.Message}");
            }
            finally
            {
                _isScanning = false;
            }
        }

        private async void BtnDeepCheck_Click(object sender, RoutedEventArgs e)
        {
            if (_isScanning) return;

            if (AssetDownloader.IsDownloading)
            {
                AppendLog("[Инфо] Идет скачивание компонентов с GitHub, подождите...");
                return;
            }

            if (!AssetDownloader.AreAssetsInstalled())
            {
                AppendLog("[Инфо] Загрузка компонентов с GitHub перед тонкой проверкой...");
                await EnsureAssetsDownloadedAsync();
            }

            _isScanning = true;

            var options = GetScanOptions();
            var sessionLogs = new List<string>();
            var startTime = DateTime.Now;
            List<string> banReasons = new List<string>();

            int? targetPid = null;
            if (txtProcessId != null && int.TryParse(txtProcessId.Text.Trim(), out int parsedPid) && parsedPid > 0)
            {
                targetPid = parsedPid;
            }
            string targetProcName = comboProcesses?.SelectedItem?.ToString();

            try
            {
                await Task.Run(async () =>
                {
                    banReasons = await DeepScanner.RunAsync(targetPid, msg =>
                    {
                        lock (sessionLogs)
                        {
                            sessionLogs.Add(string.IsNullOrEmpty(msg) ? "" : $"[{DateTime.Now:HH:mm:ss}] {msg}");
                        }
                        Dispatcher.BeginInvoke((Action)(() => AppendLog(msg)));
                    }, options);
                });

                var report = new ReportModel
                {
                    ScanType = "Тонкая проверка",
                    StartTime = startTime,
                    EndTime = DateTime.Now,
                    TargetPid = targetPid,
                    TargetProcessName = targetProcName,
                    Options = options,
                    BanReasons = banReasons,
                    Logs = sessionLogs,
                    Accounts = AccountScanner.FindAllAccounts()
                };
                HtmlReportGenerator.SaveReport(report);
            }
            catch (Exception ex)
            {
                AppendLog($"Ошибка проверки: {ex.Message}");
            }
            finally
            {
                _isScanning = false;
            }
        }

        private void BtnClearLogs_Click(object sender, RoutedEventArgs e)
        {
            ClearCheckLogs();
        }

        private void BtnCopyLogs_Click(object sender, RoutedEventArgs e)
        {
            string text = GetCheckLogsText();
            if (!string.IsNullOrEmpty(text))
            {
                try
                {
                    Clipboard.SetText(text);
                }
                catch { }
            }
        }

        private void BtnSaveLogs_Click(object sender, RoutedEventArgs e)
        {
            string text = GetCheckLogsText();
            if (string.IsNullOrWhiteSpace(text))
            {
                return;
            }

            try
            {
                var sfd = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "Текстовые файлы (*.txt)|*.txt|Все файлы (*.*)|*.*",
                    FileName = "1.txt",
                    Title = "Сохранить лог"
                };

                if (sfd.ShowDialog() == true)
                {
                    string contentToSave = CheckDoomsday.EnrichSavedLog(text);
                    System.IO.File.WriteAllText(sfd.FileName, contentToSave, System.Text.Encoding.UTF8);
                    AppendLog($"[Инфо] Лог успешно сохранен в файл: {sfd.FileName}");
                }
            }
            catch (Exception ex)
            {
                AppendLog($"[Ошибка] Не удалось сохранить лог: {ex.Message}");
            }
        }

        private List<AccountRecord> _cachedAccounts = new List<AccountRecord>();

        private void LoadOtherTabData()
        {
            var (instDate, relTime) = AccountScanner.GetWindowsInstallDate();
            if (txtWindowsInstallDate != null)
            {
                txtWindowsInstallDate.Text = string.IsNullOrEmpty(relTime) ? instDate : $"{instDate} ({relTime})";
            }

            UpdateActivityStatus();
            RefreshAccountsList();
        }

        private void UpdateActivityStatus()
        {
            Task.Run(() =>
            {
                var obs = ActivityScanner.CheckObs();
                var discord = ActivityScanner.CheckDiscord();

                Dispatcher.BeginInvoke((Action)(() =>
                {
                    if (txtObsStatus != null)
                    {
                        txtObsStatus.Text = obs.status;
                        try
                        {
                            txtObsStatus.Foreground = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString(obs.color);
                        }
                        catch { }
                    }

                    if (txtDiscordStatus != null)
                    {
                        txtDiscordStatus.Text = discord.status;
                        try
                        {
                            txtDiscordStatus.Foreground = (System.Windows.Media.Brush)new System.Windows.Media.BrushConverter().ConvertFromString(discord.color);
                        }
                        catch { }
                    }
                }));
            });
        }

        private void RefreshAccountsList()
        {
            if (txtNicksTitle != null)
            {
                txtNicksTitle.Text = "Ники игрока (поиск...)";
            }

            Task.Run(() =>
            {
                var accounts = AccountScanner.FindAllAccounts();
                Dispatcher.BeginInvoke((Action)(() =>
                {
                    _cachedAccounts = accounts;
                    int count = accounts.Count;

                    if (txtNicksTitle != null)
                    {
                        txtNicksTitle.Text = count > 0 ? $"Ники игрока ({count})" : "Ники игрока (0)";
                    }

                    if (count > 10)
                    {
                        if (itemsNicksList != null)
                        {
                            itemsNicksList.Visibility = Visibility.Collapsed;
                            itemsNicksList.ItemsSource = null;
                        }
                        if (txtNoNicks != null) txtNoNicks.Visibility = Visibility.Collapsed;
                    }
                    else if (count > 0)
                    {
                        if (itemsNicksList != null)
                        {
                            itemsNicksList.Visibility = Visibility.Visible;
                            itemsNicksList.ItemsSource = accounts;
                        }
                        if (txtNoNicks != null) txtNoNicks.Visibility = Visibility.Collapsed;
                    }
                    else
                    {
                        if (itemsNicksList != null)
                        {
                            itemsNicksList.Visibility = Visibility.Collapsed;
                            itemsNicksList.ItemsSource = null;
                        }
                        if (txtNoNicks != null) txtNoNicks.Visibility = Visibility.Visible;
                    }
                }));
            });
        }

        private void BtnRefreshNicks_Click(object sender, RoutedEventArgs e)
        {
            RefreshAccountsList();
            ShowToast("Список аккаунтов обновлен", "🔄");
        }

        private void BtnCopyNicks_Click(object sender, RoutedEventArgs e)
        {
            if (_cachedAccounts == null || _cachedAccounts.Count == 0)
            {
                ShowToast("Ники не найдены", "ℹ️");
                return;
            }

            string allNicks = string.Join("\r\n", _cachedAccounts.Select(a => a.Nickname));
            try
            {
                Clipboard.SetText(allNicks);
                ShowToast($"Скопировано {_cachedAccounts.Count} ников", "📋");
            }
            catch (Exception ex)
            {
                ShowToast($"Ошибка копирования: {ex.Message}", "⚠️", true);
            }
        }

        private void BtnDownloadNicks_Click(object sender, RoutedEventArgs e)
        {
            if (_cachedAccounts == null || _cachedAccounts.Count == 0)
            {
                ShowToast("Ники не найдены для сохранения", "ℹ️");
                return;
            }

            try
            {
                var sfd = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "Текстовые файлы (*.txt)|*.txt|Все файлы (*.*)|*.*",
                    FileName = "nickname.txt",
                    Title = "Скачать список ников"
                };

                if (sfd.ShowDialog() == true)
                {
                    var sb = new StringBuilder();
                    foreach (var acc in _cachedAccounts)
                    {
                        sb.AppendLine($"{acc.Nickname} ({acc.SourceDisplay})");
                    }
                    File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);
                    ShowToast($"Файл сохранен: nickname.txt", "💾");
                }
            }
            catch (Exception ex)
            {
                ShowToast($"Ошибка сохранения: {ex.Message}", "⚠️", true);
            }
        }

        private void BtnCopySingleNick_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string nick && !string.IsNullOrEmpty(nick))
            {
                try
                {
                    Clipboard.SetText(nick);
                    ShowToast($"Ник {nick} скопирован", "📋");
                }
                catch { }
            }
        }

        private void BtnTaskMgr_Click(object sender, RoutedEventArgs e)
        {
            try { Process.Start("taskmgr.exe"); } catch { }
        }

        private void BtnEventVwr_Click(object sender, RoutedEventArgs e)
        {
            try { Process.Start("eventvwr.msc"); } catch { }
        }

        private void BtnServices_Click(object sender, RoutedEventArgs e)
        {
            try { Process.Start("services.msc"); } catch { }
        }

        private void BtnRegedit_Click(object sender, RoutedEventArgs e)
        {
            try { Process.Start("regedit.exe"); } catch { }
        }

        private void BtnOpenDownloads_Click(object sender, RoutedEventArgs e)
        {
            try { Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")); } catch { }
        }

        private void BtnOpenPrefetch_Click(object sender, RoutedEventArgs e)
        {
            try { Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch")); } catch { }
        }

        private void BtnOpenRecycleBin_Click(object sender, RoutedEventArgs e)
        {
            try { Process.Start("explorer.exe", "shell:RecycleBinFolder"); } catch { }
        }
    }
}
