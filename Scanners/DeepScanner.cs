using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace AngelMineChecker
{
    public static class DeepScanner
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_GUARD = 0x100;
        private const uint LIST_MODULES_ALL = 0x03;

        private class SearchPattern
        {
            public string Name { get; set; }
            public bool IsSystemDlc { get; set; }
            public byte[] AsciiBytes { get; set; }
            public byte[] UnicodeBytes { get; set; }

            public SearchPattern(string name, bool isSystemDlc = false)
            {
                Name = name;
                IsSystemDlc = isSystemDlc;
                AsciiBytes = Encoding.ASCII.GetBytes(name);
                UnicodeBytes = Encoding.Unicode.GetBytes(name);
            }
        }

        private static string DecodeSig(string b64)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        }

        private static readonly List<SearchPattern> PrecompiledMemoryPatterns = new List<SearchPattern>
        {
            new SearchPattern("triggerbot"),
            new SearchPattern("aimassist"),
            new SearchPattern("dear imgui"),
            new SearchPattern("imgui::createcontext"),
            new SearchPattern("imgui_impl_win32"),
            new SearchPattern("doomsdayclient.xyz"),
            new SearchPattern("doomsdayclient"),
            new SearchPattern(DecodeSig("NjdjZnVlZ3UwcDhybQ=="), true),
            new SearchPattern(DecodeSig("QVJST1dfUklHSFRaT05UQUw="), true),
            new SearchPattern(DecodeSig("RFJPUERPV05fU1VDQ0VTUw=="), true),
            new SearchPattern(DecodeSig("dG9vbHRpcF9hcnJvd191cA=="), true),
            new SearchPattern(DecodeSig("TjFZMEc2emZ6MEVTSm9DSQ=="), true),
            new SearchPattern(DecodeSig("YXJTQnFCUWZiVW5GUFRHZQ=="), true),
            new SearchPattern(DecodeSig("dX1weG10aG9iaV1kWF5SWExSRkxARjo/MzgsMSYq"), true)
        };

        private static readonly HashSet<string> WhitelistedJreDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "jvm.dll", "java.dll", "jli.dll", "net.dll", "nio.dll", "zip.dll", "awt.dll",
            "fontmanager.dll", "freetype.dll", "jimage.dll", "jsvml.dll", "sunmscapi.dll",
            "management.dll", "management_ext.dll", "javajpeg.dll", "lcms.dll", "jawt.dll",
            "extnet.dll", "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "ucrtbase.dll",
            "attach.dll", "instrument.dll", "prefs.dll", "w2k_lsa_auth.dll", "sspi_bridge.dll"
        };

        public static async Task RunAsync(int? targetPid, Action<string> log)
        {
            var banReasons = new List<string>();

            log("Запуск проверки");
            await Task.Delay(200);

            log("Поиск папок");
            await Task.Delay(250);
            QuickScanner.ScanDirectoriesForCheats(log, banReasons);
            await Task.Delay(150);

            log("Поиск логов инжекта");
            await Task.Delay(250);
            QuickScanner.ScanUserFolderForInjectors(log, banReasons);
            await Task.Delay(150);

            var (modsDirs, logsDirs) = QuickScanner.DiscoverLauncherDirectories();

            log("Проверка папки модов");
            await Task.Delay(250);
            await QuickScanner.ScanModsFoldersAsync(modsDirs, log, banReasons);
            QuickScanner.CheckModsDeletedAfterMinecraftLaunch(modsDirs, logsDirs, log, banReasons);
            await Task.Delay(150);

            log("Поиск запуска loader");
            await Task.Delay(250);
            QuickScanner.ScanRegistry(log, banReasons);
            await Task.Delay(150);

            log("Проверка логов");
            await Task.Delay(250);
            QuickScanner.ScanLatestLogs(logsDirs, log, banReasons);
            await Task.Delay(150);

            log("Проверяем следы отчистки");
            await Task.Delay(250);
            QuickScanner.CheckCleanupActivity(log, banReasons);
            await Task.Delay(150);

            QuickScanner.CheckRecentDownloads(log, banReasons);
            QuickScanner.CheckSuspiciousProcesses(log, banReasons);

            log("Проверка системных служб");
            await Task.Delay(250);
            CheckServices(log, banReasons);
            await Task.Delay(150);

            log("Проверка USN Journal");
            await Task.Delay(250);
            CheckUsnJournal(log, banReasons);
            var deletedJournalFiles = ScanJournalTraceDeletedFiles(log);
            await Task.Delay(150);

            log("Глубокий анализ реестра");
            await Task.Delay(250);
            CheckRegistryDeep(log, banReasons);
            await Task.Delay(150);

            log("Поиск следов SystemDLC");
            await Task.Delay(250);
            CheckSystemDlc(log, banReasons);
            CheckConsoleHostHistory(log, banReasons);
            await Task.Delay(150);

            int resolvedPid = ResolveTargetPid(targetPid, log);
            if (resolvedPid > 0)
            {
                log($"Анализ памяти процесса PID {resolvedPid} (строки triggerbot, aimassist, imgui, сигнатуры SystemDLC)");
                await Task.Delay(200);
                await ScanProcessMemoryAsync(resolvedPid, log, banReasons);
                await Task.Delay(150);

                log($"Проверка инжекта DLL в процесс PID {resolvedPid}");
                await Task.Delay(200);
                CheckInjectedDlls(resolvedPid, log, banReasons);
                await Task.Delay(150);
            }
            else
            {
                log("Процесс javaw.exe не запущен (пропуск анализа памяти и DLL инжектов)");
            }

            await CheckDoomsday.RunDoomsdayCheckAsync(log, banReasons, resolvedPid > 0 ? (int?)resolvedPid : targetPid);

            log("");
            log("");
            log("");
            log("");
            log("");
            log("Итоги:");
            if (banReasons.Count > 0)
            {
                foreach (var item in banReasons.Distinct())
                {
                    log(item);
                }
            }
            else
            {
                log("Нарушений не обнаружено.");
            }

            log("");
            log("Удаленные exe / jar за последние 30 минут (JournalTrace):");
            if (deletedJournalFiles != null && deletedJournalFiles.Count > 0)
            {
                foreach (var item in deletedJournalFiles)
                {
                    log($"{item.Name} (время удаления: {item.Time:HH:mm:ss})");
                }
            }
            else
            {
                log("Не обнаружено.");
            }
        }

        private static void CheckServices(Action<string> log, List<string> banReasons)
        {
            var servicesToCheck = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "EventLog", "Журнал событий Windows (EventLog)" },
                { "PcaSvc", "Ассистент совместимости программ (PcaSvc)" },
                { "DPS", "Служба политик диагностики (DPS)" },
                { "SysMain", "Служба кэширования Prefetch/Superfetch (SysMain)" }
            };

            foreach (var kvp in servicesToCheck)
            {
                try
                {
                    using (var sc = new ServiceController(kvp.Key))
                    {
                        if (sc.Status != ServiceControllerStatus.Running && sc.Status != ServiceControllerStatus.StartPending)
                        {
                            log($"Найден остановленный сервис: {kvp.Key} ({kvp.Value}) - статус: {sc.Status}");
                            banReasons.Add($"Остановлен сервис - {kvp.Key} ({kvp.Value})");
                        }
                    }
                }
                catch { }
            }

            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\bam"))
                {
                    if (key != null)
                    {
                        object startVal = key.GetValue("Start");
                        if (startVal != null && Convert.ToInt32(startVal) == 4)
                        {
                            log("Найден отключенный драйвер BAM (Background Activity Moderator, Start=4 Disabled)");
                            banReasons.Add("Отключен драйвер BAM (Background Activity Moderator, Start=4)");
                        }
                    }
                }
            }
            catch { }
        }

        private static void CheckUsnJournal(Action<string> log, List<string> banReasons)
        {
            try
            {
                var psi = new ProcessStartInfo("fsutil", "usn queryjournal c:")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    string error = p.StandardError.ReadToEnd();
                    p.WaitForExit(3000);

                    if (p.ExitCode != 0 || output.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        error.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        log("Обнаружена очистка или отключение USN Journal на диске C:");
                        banReasons.Add("Очистка или отключение USN Journal на диске C:");
                    }
                }
            }
            catch { }

            try
            {
                string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                if (Directory.Exists(prefetchDir))
                {
                    var fsutilFiles = Directory.GetFiles(prefetchDir, "FSUTIL*.pf");
                    foreach (var f in fsutilFiles)
                    {
                        var fi = new FileInfo(f);
                        log($"Найден запуск утилиты fsutil в Prefetch: {fi.Name} (изменен: {fi.LastWriteTime:dd.MM.yyyy HH:mm:ss})");
                        banReasons.Add($"Запуск утилиты fsutil в Prefetch - {fi.Name}");
                    }
                }
            }
            catch { }
        }

        private class DeletedJournalEntry
        {
            public string Name { get; set; }
            public DateTime Time { get; set; }
        }

        private static List<DeletedJournalEntry> ScanJournalTraceDeletedFiles(Action<string> log)
        {
            var results = new List<DeletedJournalEntry>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                string jtPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "JournalTrace.exe");
                if (!File.Exists(jtPath))
                {
                    jtPath = Path.Combine(Environment.CurrentDirectory, "tools", "JournalTrace.exe");
                }
                if (!File.Exists(jtPath))
                {
                    jtPath = @"C:\Users\123\Documents\antigravity\hopeful-faraday\tools\JournalTrace.exe";
                }

                if (!File.Exists(jtPath))
                {
                    log("JournalTrace.exe не найден в папке tools");
                    return results;
                }

                var asm = Assembly.LoadFrom(jtPath);
                var journalType = asm.GetType("JournalTrace.Native.NtfsUsnJournal");
                var stateType = asm.GetType("JournalTrace.Native.Win32Api+USN_JOURNAL_DATA");

                if (journalType == null || stateType == null)
                {
                    return results;
                }

                var getStateMethod = journalType.GetMethod("GetUsnJournalState");
                var getEntriesMethod = journalType.GetMethod("GetUsnJournalEntries");
                var disposeMethod = journalType.GetMethod("Dispose");

                if (getStateMethod == null || getEntriesMethod == null)
                {
                    return results;
                }

                DateTime cutoff = DateTime.Now.AddMinutes(-30);

                var fixedDrives = DriveInfo.GetDrives()
                    .Where(d => d.DriveType == DriveType.Fixed && d.IsReady &&
                                string.Equals(d.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                foreach (var drive in fixedDrives)
                {
                    object journal = null;
                    try
                    {
                        journal = Activator.CreateInstance(journalType, drive);

                        var state = Activator.CreateInstance(stateType);
                        var getStateArgs = new object[] { state };
                        getStateMethod.Invoke(journal, getStateArgs);
                        state = getStateArgs[0];

                        var prevState = Activator.CreateInstance(stateType);
                        var journalIdField = stateType.GetField("UsnJournalID");
                        var nextUsnField = stateType.GetField("NextUsn");

                        if (journalIdField != null)
                        {
                            journalIdField.SetValue(prevState, journalIdField.GetValue(state));
                        }
                        if (nextUsnField != null)
                        {
                            nextUsnField.SetValue(prevState, 0L);
                        }

                        uint reasonMask = 512;
                        var getEntriesArgs = new object[] { prevState, reasonMask, null, null };
                        getEntriesMethod.Invoke(journal, getEntriesArgs);

                        var entries = getEntriesArgs[2] as System.Collections.IEnumerable;
                        if (entries != null)
                        {
                            PropertyInfo timeProp = null;
                            PropertyInfo nameProp = null;

                            foreach (var e in entries)
                            {
                                if (timeProp == null) timeProp = e.GetType().GetProperty("TimeStamp");
                                if (nameProp == null) nameProp = e.GetType().GetProperty("Name");

                                long ts = Convert.ToInt64(timeProp.GetValue(e, null));
                                DateTime dt = DateTime.FromFileTime(ts);
                                if (dt >= cutoff)
                                {
                                    string name = nameProp.GetValue(e, null) as string;
                                    if (!string.IsNullOrEmpty(name))
                                    {
                                        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                                            name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                                        {
                                            if (name.IndexOf("AngelMineChecker", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                name.IndexOf("TestJT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                name.IndexOf("RunDeepTest", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                name.IndexOf("JournalTrace", StringComparison.OrdinalIgnoreCase) >= 0)
                                            {
                                                continue;
                                            }

                                            string key = $"{name}_{dt:HH:mm:ss}";
                                            if (seen.Add(key))
                                            {
                                                results.Add(new DeletedJournalEntry { Name = name, Time = dt });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                    finally
                    {
                        if (journal != null && disposeMethod != null)
                        {
                            try { disposeMethod.Invoke(journal, null); } catch { }
                        }
                    }
                }

                if (results.Count > 0)
                {
                    log($"JournalTrace: зафиксировано удаление {results.Count} файлов (.exe/.jar) за последние 30 минут");
                }
                else
                {
                    log("JournalTrace: удалений exe/jar за последние 30 минут не зафиксировано");
                }
            }
            catch (Exception ex)
            {
                log($"JournalTrace: ошибка чтения журнала ({ex.Message})");
            }

            results.Sort((a, b) => b.Time.CompareTo(a.Time));
            return results;
        }

        private static void CheckRegistryDeep(Action<string> log, List<string> banReasons)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                using (var recentKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"))
                {
                    if (recentKey != null)
                    {
                        string[] subKeys = new[] { ".dll", ".jar", ".exe" };
                        foreach (var ext in subKeys)
                        {
                            using (var extKey = recentKey.OpenSubKey(ext))
                            {
                                if (extKey != null)
                                {
                                    foreach (var valName in extKey.GetValueNames())
                                    {
                                        if (valName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;
                                        byte[] data = extKey.GetValue(valName) as byte[];
                                        if (data != null && data.Length > 0)
                                        {
                                            string text = ExtractUnicodeString(data);
                                            if (!string.IsNullOrWhiteSpace(text) && !seen.Contains(text))
                                            {
                                                string lower = text.ToLower();
                                                foreach (var kw in QuickScanner.CheatKeywords)
                                                {
                                                    if (lower.Contains(kw))
                                                    {
                                                        seen.Add(text);
                                                        log($"Найден файл в RecentDocs: {text}");
                                                        banReasons.Add($"Найден файл чита в RecentDocs - {text}");
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                using (var mruRoot = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"))
                {
                    if (mruRoot != null)
                    {
                        string[] targets = new[] { "*", "dll", "jar", "exe" };
                        foreach (var target in targets)
                        {
                            using (var targetKey = mruRoot.OpenSubKey(target))
                            {
                                if (targetKey != null)
                                {
                                    foreach (var valName in targetKey.GetValueNames())
                                    {
                                        if (valName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;
                                        byte[] data = targetKey.GetValue(valName) as byte[];
                                        if (data != null && data.Length > 0)
                                        {
                                            string text = ExtractUnicodeString(data);
                                            if (!string.IsNullOrWhiteSpace(text) && !seen.Contains(text))
                                            {
                                                string lower = text.ToLower();
                                                foreach (var kw in QuickScanner.CheatKeywords)
                                                {
                                                    if (lower.Contains(kw))
                                                    {
                                                        seen.Add(text);
                                                        log($"Найден файл в OpenSavePidlMRU: {text}");
                                                        banReasons.Add($"Найден файл чита в OpenSavePidlMRU - {text}");
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                using (var appKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"))
                {
                    if (appKey != null)
                    {
                        foreach (var valName in appKey.GetValueNames())
                        {
                            string lower = valName.ToLower();
                            if (!seen.Contains(valName))
                            {
                                foreach (var kw in QuickScanner.CheatKeywords)
                                {
                                    if (lower.Contains(kw))
                                    {
                                        seen.Add(valName);
                                        log($"Найден запуск софта в AppSwitched: {valName}");
                                        banReasons.Add($"Найден запуск софта в AppSwitched - {valName}");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                using (var uaRoot = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"))
                {
                    if (uaRoot != null)
                    {
                        foreach (var guid in uaRoot.GetSubKeyNames())
                        {
                            using (var countKey = uaRoot.OpenSubKey($"{guid}\\Count"))
                            {
                                if (countKey == null) continue;
                                foreach (var valName in countKey.GetValueNames())
                                {
                                    string decoded = Rot13(valName);
                                    if (!seen.Contains(decoded))
                                    {
                                        string lower = decoded.ToLower();
                                        foreach (var kw in QuickScanner.CheatKeywords)
                                        {
                                            if (lower.Contains(kw))
                                            {
                                                seen.Add(decoded);
                                                log($"Найден запуск софта в UserAssist: {decoded}");
                                                banReasons.Add($"Найден запуск софта в UserAssist - {decoded}");
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                string[] bamPaths = new[]
                {
                    @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                    @"SYSTEM\CurrentControlSet\Services\bam\UserSettings"
                };

                foreach (var bp in bamPaths)
                {
                    using (var bamRoot = Registry.LocalMachine.OpenSubKey(bp))
                    {
                        if (bamRoot == null) continue;
                        foreach (var sid in bamRoot.GetSubKeyNames())
                        {
                            using (var userKey = bamRoot.OpenSubKey(sid))
                            {
                                if (userKey == null) continue;
                                foreach (var valName in userKey.GetValueNames())
                                {
                                    if (!seen.Contains(valName))
                                    {
                                        string lower = valName.ToLower();
                                        foreach (var kw in QuickScanner.CheatKeywords)
                                        {
                                            if (lower.Contains(kw))
                                            {
                                                seen.Add(valName);
                                                log($"Найден запуск в BAM: {valName}");
                                                banReasons.Add($"Найден запуск софта в BAM - {valName}");
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private static void CheckSystemDlc(Action<string> log, List<string> banReasons)
        {
            CheckSystemDLC.Scan(log, banReasons);
        }

        private static void CheckConsoleHostHistory(Action<string> log, List<string> banReasons)
        {
            try
            {
                string histPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                );

                if (File.Exists(histPath))
                {
                    var lines = File.ReadAllLines(histPath);
                    var suspiciousCmds = new[] { "psexec", "jlivef", "systemdlc", "clear-eventlog", "wevtutil cl", "wevtutil clear-log", "fsutil usn deletejournal" };
                    foreach (var line in lines)
                    {
                        string trimmed = line.Trim();
                        string lower = trimmed.ToLower();
                        if (string.IsNullOrWhiteSpace(trimmed)) continue;

                        if (lower.Contains("angelminechecker") || lower.Contains("where-object") ||
                            lower.Contains("select-object") || lower.Contains("format-table") ||
                            lower.Contains("findstr") || lower.Contains("select-string") ||
                            lower.Contains("get-help"))
                        {
                            continue;
                        }

                        bool found = false;
                        foreach (var sc in suspiciousCmds)
                        {
                            if (lower.Contains(sc))
                            {
                                log($"Найден след в истории командной строки (PSReadLine): {trimmed}");
                                banReasons.Add($"След в истории PowerShell - {trimmed}");
                                found = true;
                                break;
                            }
                        }

                        if (!found)
                        {
                            foreach (var sig in QuickScanner.SystemDlcSignatures)
                            {
                                if (trimmed.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    log($"Найден след SystemDLC в истории PowerShell: {trimmed} (сигнатура {sig})");
                                    banReasons.Add($"Найден след SystemDLC в истории PowerShell - {trimmed} ({sig})");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private static int ResolveTargetPid(int? preferredPid, Action<string> log = null)
        {
            if (preferredPid.HasValue && preferredPid.Value > 0)
            {
                try
                {
                    var p = Process.GetProcessById(preferredPid.Value);
                    if (!p.HasExited)
                    {
                        if (log != null)
                        {
                            long memMb = p.WorkingSet64 / (1024 * 1024);
                            log($"Выбран указанный процесс Minecraft: PID {p.Id} ({p.ProcessName}, {memMb} МБ, \"{p.MainWindowTitle}\")");
                        }
                        return preferredPid.Value;
                    }
                }
                catch { }
            }

            var candidates = new List<ProcessCandidate>();

            var cmdMap = new Dictionary<int, string>();
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name = 'javaw.exe' OR Name = 'java.exe'"))
                using (var objects = searcher.Get())
                {
                    foreach (ManagementObject obj in objects)
                    {
                        try
                        {
                            int pid = Convert.ToInt32(obj["ProcessId"]);
                            string cmd = obj["CommandLine"] as string ?? "";
                            cmdMap[pid] = cmd;
                        }
                        catch { }
                    }
                }
            }
            catch { }

            var procs = Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java"));
            foreach (var p in procs)
            {
                try
                {
                    if (p.HasExited) continue;

                    string title = "";
                    try { title = p.MainWindowTitle ?? ""; } catch { }

                    string titleLower = title.ToLower();
                    long memBytes = 0;
                    try { memBytes = p.WorkingSet64; } catch { }

                    cmdMap.TryGetValue(p.Id, out string cmdLine);
                    cmdLine = cmdLine ?? "";
                    string cmdLower = cmdLine.ToLower();

                    int score = 0;

                    if (cmdLower.Contains("org.tlauncher") || cmdLower.Contains("ru.turikhay") ||
                        cmdLower.Contains("tlauncher.jar") || cmdLower.Contains("launcher.jar") ||
                        cmdLower.Contains("tl.exe") || titleLower.Contains("tlauncher") ||
                        titleLower.Contains("legacy launcher") || titleLower.Contains("лаунчер"))
                    {
                        score -= 200;
                    }

                    if (cmdLower.Contains("net.minecraft.client.main.main") ||
                        cmdLower.Contains("knotclient") ||
                        cmdLower.Contains("fmlclientlaunchhandler") ||
                        cmdLower.Contains("bootstraplauncher") ||
                        cmdLower.Contains("net.minecraft.launchwrapper.launch"))
                    {
                        score += 300;
                    }

                    if (cmdLower.Contains("--gamedir") || cmdLower.Contains("--assetsdir"))
                    {
                        score += 150;
                    }

                    if (titleLower.Contains("minecraft") ||
                        titleLower.Contains("1.21") || titleLower.Contains("1.20") ||
                        titleLower.Contains("1.19") || titleLower.Contains("1.18") ||
                        titleLower.Contains("1.16") || titleLower.Contains("1.12") ||
                        titleLower.Contains("1.8") || titleLower.Contains("lunar") ||
                        titleLower.Contains("badlion") || titleLower.Contains("feather"))
                    {
                        score += 150;
                    }

                    long memMb = memBytes / (1024 * 1024);
                    if (memMb >= 1000) score += 100;
                    if (memMb >= 1500) score += 100;
                    if (memMb <= 350) score -= 50;

                    score += (int)Math.Min(100, memMb / 20);

                    candidates.Add(new ProcessCandidate
                    {
                        Process = p,
                        Score = score,
                        Title = title,
                        MemMb = memMb
                    });
                }
                catch { }
            }

            if (candidates.Count > 0)
            {
                var best = candidates.OrderByDescending(c => c.Score).ThenByDescending(c => c.MemMb).First();
                if (log != null)
                {
                    log($"Определен процесс Minecraft: {best.Process.ProcessName}.exe (PID {best.Process.Id}, память {best.MemMb} МБ, окно: \"{best.Title}\")");
                }
                return best.Process.Id;
            }

            return -1;
        }

        private class ProcessCandidate
        {
            public Process Process { get; set; }
            public int Score { get; set; }
            public string Title { get; set; }
            public long MemMb { get; set; }
        }

        private static async Task ScanProcessMemoryAsync(int pid, Action<string> log, List<string> banReasons)
        {
            await Task.Run(() =>
            {
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                    if (hProcess == IntPtr.Zero)
                    {
                        log($"Не удалось открыть процесс PID {pid} для чтения памяти (требуются права администратора)");
                        return;
                    }

                    IntPtr address = IntPtr.Zero;
                    MEMORY_BASIC_INFORMATION mbi;
                    int structSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
                    int scannedRegions = 0;
                    var foundSignatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    const int bufferSize = 262144;
                    byte[] buffer = new byte[bufferSize];

                    var sw = Stopwatch.StartNew();

                    while (VirtualQueryEx(hProcess, address, out mbi, (uint)structSize) == structSize)
                    {
                        if (sw.ElapsedMilliseconds > 3000 || scannedRegions > 300)
                            break;

                        if (mbi.State == MEM_COMMIT &&
                            (mbi.Protect & PAGE_GUARD) == 0 &&
                            (mbi.Protect & PAGE_NOACCESS) == 0 &&
                            ((mbi.Protect & PAGE_READWRITE) != 0 || (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0))
                        {
                            long regionBytes = mbi.RegionSize.ToInt64();
                            long bytesToReadTotal = Math.Min(regionBytes, 2097152);
                            long offset = 0;

                            while (offset < bytesToReadTotal)
                            {
                                int chunk = (int)Math.Min((long)bufferSize, bytesToReadTotal - offset);
                                IntPtr readAddr = new IntPtr(mbi.BaseAddress.ToInt64() + offset);

                                if (ReadProcessMemory(hProcess, readAddr, buffer, chunk, out IntPtr bytesRead) && (int)bytesRead > 0)
                                {
                                    int readLen = (int)bytesRead;

                                    foreach (var pat in PrecompiledMemoryPatterns)
                                    {
                                        if (!foundSignatures.Contains(pat.Name))
                                        {
                                            if (ContainsBytePattern(buffer, readLen, pat.AsciiBytes) ||
                                                ContainsBytePattern(buffer, readLen, pat.UnicodeBytes))
                                            {
                                                foundSignatures.Add(pat.Name);
                                                if (pat.IsSystemDlc)
                                                {
                                                    log($"Найден след SystemDLC в памяти процесса PID {pid}: {pat.Name} (адрес 0x{readAddr.ToInt64():X})");
                                                    banReasons.Add($"Найден след SystemDLC в памяти процесса (PID {pid}) - {pat.Name}");
                                                }
                                                else
                                                {
                                                    log($"Найдена сигнатура в памяти PID {pid}: {pat.Name} (адрес 0x{readAddr.ToInt64():X})");
                                                    banReasons.Add($"Найдена сигнатура чита в памяти (PID {pid}) - {pat.Name}");
                                                }
                                            }
                                        }
                                    }
                                }

                                offset += chunk;
                            }

                            scannedRegions++;
                        }

                        long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                        if (nextAddr <= mbi.BaseAddress.ToInt64()) break;
                        address = new IntPtr(nextAddr);
                    }
                }
                catch (Exception ex)
                {
                    log($"Ошибка сканирования памяти PID {pid}: {ex.Message}");
                }
                finally
                {
                    if (hProcess != IntPtr.Zero)
                    {
                        CloseHandle(hProcess);
                    }
                }
            });
        }

        private static bool ContainsBytePattern(byte[] buffer, int length, byte[] pattern)
        {
            if (pattern == null || pattern.Length == 0 || length < pattern.Length) return false;
            byte first = pattern[0];
            int max = length - pattern.Length;
            for (int i = 0; i <= max; i++)
            {
                if (buffer[i] == first)
                {
                    bool match = true;
                    for (int j = 1; j < pattern.Length; j++)
                    {
                        if (buffer[i + j] != pattern[j])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match) return true;
                }
            }
            return false;
        }

        private static void CheckInjectedDlls(int pid, Action<string> log, List<string> banReasons)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    InspectModulesFallback(pid, log, banReasons);
                    return;
                }

                var suspiciousDirs = new[]
                {
                    Path.GetTempPath(),
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\AppData",
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads",
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    "$Recycle.Bin"
                };

                var suspiciousKeywords = new[] { "inject", "hook", "hack", "cheat", "loader", "bypass", "systemdlc", "jlivef", "doomsday", "celestial", "nursultan", "deadcode", "rich", "expensive", "minced" };

                IntPtr[] hMods = new IntPtr[1024];
                uint cb = (uint)(IntPtr.Size * hMods.Length);
                if (EnumProcessModulesEx(hProcess, hMods, cb, out uint cbNeeded, LIST_MODULES_ALL))
                {
                    int totalMods = (int)(cbNeeded / IntPtr.Size);
                    for (int i = 0; i < totalMods && i < hMods.Length; i++)
                    {
                        var sbPath = new StringBuilder(1024);
                        GetModuleFileNameEx(hProcess, hMods[i], sbPath, (uint)sbPath.Capacity);
                        string modPath = sbPath.ToString();

                        var sbName = new StringBuilder(256);
                        GetModuleBaseName(hProcess, hMods[i], sbName, (uint)sbName.Capacity);
                        string modName = sbName.ToString();
                        string modNameLower = modName.ToLower();

                        if (IsWhitelistedInjectedModule(modNameLower, modPath))
                            continue;

                        bool fromSuspiciousFolder =
                            modPath.IndexOf(@"\Temp\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            modPath.IndexOf(@"\Downloads\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            modPath.IndexOf(@"\Desktop\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            modPath.IndexOf(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase) >= 0;

                        bool cheatNameMatch = QuickScanner.CheatKeywords.Any(kw => modNameLower.Contains(kw)) ||
                                              suspiciousKeywords.Any(sk => modNameLower.Contains(sk));

                        if (cheatNameMatch || fromSuspiciousFolder)
                        {
                            log($"Найден подозрительный инжект DLL: {modName} ({modPath})");
                            banReasons.Add($"Найден подозрительный инжект DLL - {modName} ({modPath})");
                        }
                    }
                }
                else
                {
                    InspectModulesFallback(pid, log, banReasons);
                }
            }
            catch (Exception ex)
            {
                log($"Не удалось прочитать модули процесса PID {pid}: {ex.Message}");
            }
            finally
            {
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
        }

        private static bool IsWhitelistedInjectedModule(string modNameLower, string modPath)
        {
            if (string.IsNullOrEmpty(modNameLower) || string.IsNullOrEmpty(modPath)) return true;
            if (modNameLower.EndsWith(".exe")) return true;

            if (modPath.StartsWith(@"C:\Windows\System32", StringComparison.OrdinalIgnoreCase) ||
                modPath.StartsWith(@"C:\Windows\SysWOW64", StringComparison.OrdinalIgnoreCase) ||
                modPath.StartsWith(@"C:\Windows\WinSxS", StringComparison.OrdinalIgnoreCase))
                return true;

            if (modNameLower.StartsWith("api-ms-win-") || modNameLower.StartsWith("ext-ms-win-"))
                return true;

            if (modNameLower.StartsWith("graphics-hook") ||
                modPath.IndexOf(@"\obs-studio-hook\", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;

            if (modNameLower.Contains("watermedia") ||
                modPath.IndexOf(@"\watermedia\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                modNameLower.StartsWith("avutil") || modNameLower.StartsWith("avcodec") ||
                modNameLower.StartsWith("avformat") || modNameLower.StartsWith("swresample") ||
                modNameLower.StartsWith("swscale") || modNameLower.StartsWith("avfilter") ||
                modNameLower.StartsWith("avdevice") || modNameLower.StartsWith("postproc") ||
                modNameLower.StartsWith("jniav") || modNameLower.StartsWith("jnisw"))
                return true;

            if (modNameLower.StartsWith("libopus") || modNameLower.StartsWith("librnnoise") ||
                modNameLower.StartsWith("libspeex") || modNameLower.StartsWith("liblame") ||
                modPath.IndexOf(@"voicechat", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;

            if (modNameLower.StartsWith("jna") || modNameLower.StartsWith("flatlaf") ||
                modNameLower.StartsWith("libtmp") || modNameLower.Contains("junixsocket") ||
                modNameLower.StartsWith("lwjgl") || modNameLower.StartsWith("glfw") ||
                modNameLower.StartsWith("openal") || modNameLower.StartsWith("jemalloc") ||
                modNameLower.StartsWith("libzstd") || modNameLower.Contains("zstd-jni") ||
                modNameLower.StartsWith("sqlite") || modNameLower.Contains("sqlitejdbc") ||
                modNameLower.StartsWith("liblz4") || modNameLower.StartsWith("libsnappy") ||
                modNameLower.Contains("lunarclient") || modNameLower.Contains("lunar") ||
                modNameLower.StartsWith("netty") || modNameLower.StartsWith("leveldb"))
                return true;

            if (WhitelistedJreDlls.Contains(modNameLower) &&
                (modPath.IndexOf(@"\jre\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 modPath.IndexOf(@"\jdk\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 modPath.IndexOf(@"\java-runtime", StringComparison.OrdinalIgnoreCase) >= 0 ||
                 modPath.IndexOf(@"\bin\", StringComparison.OrdinalIgnoreCase) >= 0))
                return true;

            return false;
        }

        private static void InspectModulesFallback(int pid, Action<string> log, List<string> banReasons)
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                string mainExe = "";
                try { mainExe = proc.MainModule.FileName ?? ""; } catch { }

                var suspiciousKeywords = new[] { "inject", "hook", "hack", "cheat", "loader", "bypass", "systemdlc", "jlivef" };

                foreach (ProcessModule mod in proc.Modules)
                {
                    try
                    {
                        string modPath = mod.FileName ?? "";
                        string modName = mod.ModuleName;
                        string modNameLower = modName.ToLower();

                        if (modNameLower.EndsWith(".exe") || modPath.Equals(mainExe, StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (IsWhitelistedInjectedModule(modNameLower, modPath))
                            continue;

                        bool fromSuspiciousFolder =
                            modPath.IndexOf(@"\Temp\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            modPath.IndexOf(@"\Downloads\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            modPath.IndexOf(@"\Desktop\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            modPath.IndexOf(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase) >= 0;

                        bool cheatNameMatch = QuickScanner.CheatKeywords.Any(kw => modNameLower.Contains(kw)) ||
                                              suspiciousKeywords.Any(sk => modNameLower.Contains(sk));

                        if (cheatNameMatch || fromSuspiciousFolder)
                        {
                            log($"Найден подозрительный инжект DLL: {modName} ({modPath})");
                            banReasons.Add($"Найден подозрительный инжект DLL - {modName} ({modPath})");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static string Rot13(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            char[] chars = input.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
            {
                char c = chars[i];
                if (c >= 'a' && c <= 'z')
                {
                    chars[i] = (char)((c - 'a' + 13) % 26 + 'a');
                }
                else if (c >= 'A' && c <= 'Z')
                {
                    chars[i] = (char)((c - 'A' + 13) % 26 + 'A');
                }
            }
            return new string(chars);
        }

        private static string ExtractUnicodeString(byte[] data)
        {
            try
            {
                string text = Encoding.Unicode.GetString(data);
                int nullIdx = text.IndexOf('\0');
                if (nullIdx >= 0) text = text.Substring(0, nullIdx);
                return text.Trim();
            }
            catch
            {
                return "";
            }
        }

    }
}
