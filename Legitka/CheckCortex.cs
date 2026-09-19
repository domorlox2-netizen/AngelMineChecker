using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;

namespace AngelMineChecker
{
    public static class CheckCortex
    {
        private static readonly string[] NonGameApps = new[]
        {
            "chrome", "msedge", "firefox", "opera", "yandex", "brave", "vivaldi", "browser",
            "discord", "telegram", "explorer", "devenv", "msbuild", "code", "rider", "idea64"
        };

        private static bool IsRazerLegit(string path, string desc, string company)
        {
            if (!string.IsNullOrEmpty(path) && path.IndexOf("razer", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
            if (!string.IsNullOrEmpty(desc) && desc.IndexOf("razer", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
            if (!string.IsNullOrEmpty(company) && company.IndexOf("razer", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
            return false;
        }

        public static void Scan(Action<string> log, List<string> banReasons, int? targetPid = null)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            var candidateDirs = new List<string>
            {
                Path.Combine(appData, "cortex"),
                Path.Combine(appData, "Cortex"),
                Path.Combine(appData, "CortexClient"),
                Path.Combine(appData, "cortexclient"),
                Path.Combine(appData, ".cortex"),
                Path.Combine(localAppData, "cortex"),
                Path.Combine(localAppData, "Cortex"),
                Path.Combine(localAppData, "CortexClient"),
                Path.Combine(userProfile, "cortex"),
                Path.Combine(userProfile, "Cortex"),
                Path.Combine(userProfile, "CortexClient"),
                Path.Combine(appData, ".minecraft", "cortex"),
                Path.Combine(appData, ".minecraft", "Cortex"),
                Path.Combine(appData, ".minecraft", "CortexClient"),
                Path.Combine(appData, ".minecraft", "config", "cortex"),
                Path.Combine(appData, ".minecraft", "config", "Cortex")
            };

            foreach (var d in candidateDirs)
            {
                try
                {
                    if (Directory.Exists(d) && !QuickScanner.IsCheckerOrSelf(d))
                    {
                        if (IsRazerLegit(d, "", "")) continue;
                        if (seen.Add(d))
                        {
                            log($"Найден: Папка чита Cortex ({d})");
                            banReasons.Add($"Найдена папка чита Cortex - {Path.GetFileName(d)} ({d})");
                        }
                    }
                }
                catch { }
            }

            string[] userLocations = new[]
            {
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.GetTempPath(),
                Path.Combine(appData, ".minecraft", "mods")
            };

            foreach (var loc in userLocations)
            {
                if (!Directory.Exists(loc)) continue;
                try
                {
                    foreach (var f in Directory.GetFiles(loc, "*cortex*", SearchOption.TopDirectoryOnly))
                    {
                        if (QuickScanner.IsCheckerOrSelf(f)) continue;
                        if (IsRazerLegit(f, "", "")) continue;

                        string ext = Path.GetExtension(f).ToLower();
                        if (ext == ".exe" || ext == ".jar" || ext == ".dll" || ext == ".zip" || ext == ".rar" || ext == ".json")
                        {
                            if (seen.Add(f))
                            {
                                log($"Найден: Файл чита Cortex ({f})");
                                banReasons.Add($"Найден файл чита Cortex - {Path.GetFileName(f)} ({f})");
                            }
                        }
                    }
                }
                catch { }
            }

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        string pName = proc.ProcessName.ToLower();
                        if (pName == "angelminechecker") continue;

                        string title = "";
                        try { title = proc.MainWindowTitle?.ToLower() ?? ""; } catch { }

                        string desc = "";
                        string company = "";
                        string modulePath = "";
                        try
                        {
                            desc = proc.MainModule?.FileVersionInfo?.FileDescription ?? "";
                            company = proc.MainModule?.FileVersionInfo?.CompanyName ?? "";
                            modulePath = proc.MainModule?.FileName ?? "";
                        }
                        catch { }

                        if (IsRazerLegit(modulePath, desc, company)) continue;

                        bool isNonGame = NonGameApps.Any(app => pName.Contains(app));

                        if (pName.Contains("cortex") || (!isNonGame && title.Contains("cortex")))
                        {
                            string detail = !string.IsNullOrEmpty(proc.MainWindowTitle) ? $" [{proc.MainWindowTitle}]" : "";
                            string key = $"proc_{proc.Id}_{proc.ProcessName}";
                            if (seen.Add(key))
                            {
                                log($"Найден активный процесс Cortex: {proc.ProcessName}.exe (PID: {proc.Id}){detail}");
                                banReasons.Add($"Активный процесс Cortex - {proc.ProcessName}.exe (PID: {proc.Id}){detail}");
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            try
            {
                int currentPid = Process.GetCurrentProcess().Id;
                using (var searcher = new ManagementObjectSearcher("SELECT ProcessId, Name, CommandLine FROM Win32_Process"))
                using (var objects = searcher.Get())
                {
                    foreach (ManagementObject obj in objects)
                    {
                        try
                        {
                            string pName = (obj["Name"] as string ?? "").ToLower();
                            string cmd = obj["CommandLine"] as string ?? "";
                            int pid = Convert.ToInt32(obj["ProcessId"]);
                            if (string.IsNullOrEmpty(cmd) || pid == currentPid) continue;

                            string cmdLower = cmd.ToLower();
                            if (cmdLower.Contains("angelminechecker") || NonGameApps.Any(app => pName.Contains(app))) continue;
                            if (cmdLower.Contains("razer")) continue;

                            if (cmdLower.Contains("cortex") && (cmdLower.Contains("cheat") || cmdLower.Contains("client") || cmdLower.Contains("clicker") || cmdLower.Contains(".jar") || cmdLower.Contains(".dll")))
                            {
                                string key = $"wmi_cortex_{pid}";
                                if (seen.Add(key))
                                {
                                    log($"Найден процесс Cortex: {pName} (PID: {pid})");
                                    banReasons.Add($"Активный процесс Cortex - {pName} (PID: {pid})");
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            try
            {
                string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                if (Directory.Exists(prefetchDir))
                {
                    foreach (var pf in Directory.GetFiles(prefetchDir, "*CORTEX*.pf"))
                    {
                        string pfName = Path.GetFileName(pf).ToLower();
                        if (pfName.Contains("razer")) continue;

                        var fi = new FileInfo(pf);
                        if (seen.Add(fi.Name))
                        {
                            log($"Найден запуск Cortex в Prefetch: {fi.Name} (время: {fi.LastWriteTime:dd.MM.yyyy HH:mm:ss})");
                            banReasons.Add($"Найден запуск чита Cortex в Prefetch - {fi.Name}");
                        }
                    }
                }
            }
            catch { }
        }
    }
}
