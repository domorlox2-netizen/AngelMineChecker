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
using AngelMineChecker.Services;

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
        private const uint MEM_PRIVATE = 0x20000;
        private const uint MEM_MAPPED = 0x40000;
        private const uint MEM_IMAGE = 0x1000000;

        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_WRITECOPY = 0x08;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        private const uint PAGE_GUARD = 0x100;
        private const uint LIST_MODULES_ALL = 0x03;

        private static bool IsReadablePage(uint protect)
        {
            if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0)
                return false;

            return (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }

        private class SearchPattern
        {
            public string Name { get; set; }
            public bool IsSystemDlc { get; set; }
            public bool IsDoomsday { get; set; }
            public byte[] AsciiBytes { get; set; }
            public byte[] UnicodeBytes { get; set; }
            public byte[] LowerAscii { get; set; }
            public bool IsCaseSensitive { get; set; }

            public SearchPattern(string name, bool isSystemDlc = false, bool isDoomsday = false, bool isCaseSensitive = false)
            {
                Name = name;
                IsSystemDlc = isSystemDlc;
                IsDoomsday = isDoomsday;
                IsCaseSensitive = isCaseSensitive;
                AsciiBytes = Encoding.ASCII.GetBytes(name);
                UnicodeBytes = Encoding.Unicode.GetBytes(name);
                LowerAscii = Encoding.ASCII.GetBytes(name.ToLowerInvariant());
            }
        }

        private static string DecodeSig(string b64)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        }

        private static readonly List<SearchPattern> PrecompiledMemoryPatterns = BuildPrecompiledPatterns();

        private static List<SearchPattern> BuildPrecompiledPatterns()
        {
            var list = new List<SearchPattern>
            {
                new SearchPattern("triggerbot"),
                new SearchPattern("aimassist"),
                new SearchPattern("dear imgui"),
                new SearchPattern("imgui::createcontext"),
                new SearchPattern("imgui_impl_win32"),
                new SearchPattern("doomsdayclient.xyz", false, true),
                new SearchPattern("doomsdayclient.com", false, true),
                new SearchPattern("doomsdayclient", false, true),
                new SearchPattern("doomsday", false, true),
                new SearchPattern("com/doomsday", false, true),
                new SearchPattern("z4mfltptb", false, true),
                new SearchPattern("arial_3_128_2.png", false, true),
                new SearchPattern("doomsday loaded successfully", false, true),
                new SearchPattern("starting inject shellcode", false, true),
                new SearchPattern("injected! loading...", false, true),
                new SearchPattern("--doomsdayargs", false, true),
                new SearchPattern("--doomsdayversion", false, true),
                new SearchPattern("--clickguikey", false, true),
                new SearchPattern("failed to inject jvmti agent", false, true),
                new SearchPattern("ru/bcloader", false, true),
                new SearchPattern("bcloader", false, true),
                new SearchPattern(DecodeSig("NjdjZnVlZ3UwcDhybQ=="), true),
                new SearchPattern(DecodeSig("QVJST1dfUklHSFRaT05UQUw="), true),
                new SearchPattern(DecodeSig("RFJPUERPV05fU1VDQ0VTUw=="), true),
                new SearchPattern(DecodeSig("Q0hFVlJPTl9SSUdIVA=="), true),
                new SearchPattern(DecodeSig("dG9vbHRpcF9hcnJvd191cA=="), true),
                new SearchPattern(DecodeSig("TjFZMEc2emZ6MEVTSm9DSQ=="), true),
                new SearchPattern(DecodeSig("YXJTQnFCUWZiVW5GUFRHZQ=="), true),
                new SearchPattern(DecodeSig("dX1weG10aG9iaV1kWF5SWExSRkxARjo/MzgsMSYq"), true),
                new SearchPattern("ARROW_RIGHTZONTAL", true),
                new SearchPattern("DROPDOWN_SUCCESS", true),
                new SearchPattern("CHEVRON_RIGHT", true),
                new SearchPattern("tooltip_arrow_up", true),
                new SearchPattern("N1Y0G6zfz0ESjoCI", true),
                new SearchPattern("N1Y0G6zfz0ESJoCI", true),
                new SearchPattern("arSBqBQfbUnFPTGe", true),
                new SearchPattern("u}pxmthobi]dX^RXLRFL@F:?38,1&*", true),
                new SearchPattern("u}pxmthobi]dX^RxLRFl@F:?38,1&*", true),
                new SearchPattern("systemdlc", true),
                new SearchPattern("system dlc", true),
                new SearchPattern("msc.systemdlc.com", true),
                new SearchPattern("systemdlc.com", true),
                new SearchPattern("Control your system", true),
                new SearchPattern("Loader Panel", true),
                new SearchPattern("7d07ec9c9054e7", true),
                new SearchPattern("1>Jeh{W~;G7ZSI", true)
            };

            foreach (var str in CheckDoomsday.DoomsdayStrings)
            {
                list.Add(new SearchPattern(str, false, true, true));
            }

            return list;
        }

        private static readonly HashSet<string> WhitelistedJreDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "jvm.dll", "java.dll", "jli.dll", "net.dll", "nio.dll", "zip.dll", "awt.dll",
            "fontmanager.dll", "freetype.dll", "jimage.dll", "jsvml.dll", "sunmscapi.dll",
            "management.dll", "management_ext.dll", "javajpeg.dll", "lcms.dll", "jawt.dll",
            "extnet.dll", "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll", "ucrtbase.dll",
            "attach.dll", "instrument.dll", "prefs.dll", "w2k_lsa_auth.dll", "sspi_bridge.dll"
        };

        public static async Task<List<string>> RunAsync(int? targetPid, Action<string> log, ScanOptions options = null)
        {
            if (options == null) options = new ScanOptions();
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
            QuickScanner.CheckPulseVisual(log, banReasons);

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

            int resolvedPid = ResolveTargetPid(targetPid, log);

            if (options.CheckSystemDlc)
            {
                log("Поиск следов SystemDLC");
                await Task.Delay(250);
                CheckSystemDLC.Scan(log, banReasons, resolvedPid > 0 ? (int?)resolvedPid : targetPid);
                CheckConsoleHostHistory(log, banReasons);
                await Task.Delay(150);
            }
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
                log("Процесс Minecraft (javaw.exe / pulse_launcher.exe) не запущен (пропуск анализа памяти и DLL инжектов)");
            }

            if (options.CheckCortex)
            {
                log("Поиск следов Cortex");
                CheckCortex.Scan(log, banReasons, resolvedPid > 0 ? (int?)resolvedPid : targetPid);
            }

            if (options.CheckLuminar)
            {
                log("Поиск следов Luminar");
                CheckLuminar.Scan(log, banReasons, resolvedPid > 0 ? (int?)resolvedPid : targetPid);
            }

            if (options.CheckDoomsday)
            {
                await CheckDoomsday.RunDoomsdayCheckAsync(log, banReasons, resolvedPid > 0 ? (int?)resolvedPid : targetPid);
            }

            var deletedStrings = deletedJournalFiles?.Select(f => $"{f.Name} (время удаления: {f.Time:HH:mm:ss})");
            ScanSummaryFormatter.PrintSummary(banReasons, deletedStrings, log);

            return banReasons;
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
                    var suspiciousCmds = new[] { "psexec", "jlivef", "systemdlc", "systemdlc.com", "msc.systemdlc.com", "7d07ec9c9054e7", "instruction.txt", "idlelib", "clear-eventlog", "wevtutil cl", "wevtutil clear-log", "fsutil usn deletejournal" };
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

            var candidates = MinecraftProcessDetector.FindCandidates();
            if (candidates.Count > 0)
            {
                var best = candidates.First();
                if (log != null)
                {
                    string winInfo = !string.IsNullOrEmpty(best.WindowTitle) ? $", окно: \"{best.WindowTitle}\"" : "";
                    log($"Определен процесс Minecraft: {best.ProcessName}.exe (PID {best.Pid}, память {best.MemoryMb} МБ{winInfo})");
                }
                return best.Pid;
            }

            return -1;
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
                    var foundSignatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    var imageMappedRegions = new List<MEMORY_BASIC_INFORMATION>();
                    var privateRegions = new List<MEMORY_BASIC_INFORMATION>();

                    while (VirtualQueryEx(hProcess, address, out mbi, (uint)structSize) == structSize)
                    {
                        if (mbi.State == MEM_COMMIT && IsReadablePage(mbi.Protect))
                        {
                            if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)
                            {
                                imageMappedRegions.Add(mbi);
                            }
                            else if (mbi.Type == MEM_PRIVATE)
                            {
                                privateRegions.Add(mbi);
                            }
                        }

                        long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                        if (nextAddr <= mbi.BaseAddress.ToInt64()) break;
                        address = new IntPtr(nextAddr);
                    }

                    const int bufferSize = 1048576;
                    byte[] buffer = new byte[bufferSize];

                    // Pass 1: MEM_IMAGE and MEM_MAPPED (Process Hacker strings mode without Private)
                    // Very fast (<200ms) and checks all mapped files, sections, and DLLs
                    foreach (var reg in imageMappedRegions)
                    {
                        ScanProcessMemoryRegion(hProcess, reg, buffer, bufferSize, foundSignatures, pid, log, banReasons);
                    }

                    // Pass 2: MEM_PRIVATE (JVM heap / stack), with a 5 second time budget
                    var sw = Stopwatch.StartNew();
                    foreach (var reg in privateRegions)
                    {
                        if (sw.ElapsedMilliseconds > 5000) break;
                        ScanProcessMemoryRegion(hProcess, reg, buffer, bufferSize, foundSignatures, pid, log, banReasons);
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

        private static void ScanProcessMemoryRegion(IntPtr hProcess, MEMORY_BASIC_INFORMATION mbi, byte[] buffer,
            int bufferSize, HashSet<string> foundSignatures, int pid, Action<string> log, List<string> banReasons)
        {
            long regionBytes = mbi.RegionSize.ToInt64();
            long bytesToReadTotal = Math.Min(regionBytes, 33554432);
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
                            int matchIdx = -1;
                            if (pat.IsCaseSensitive)
                            {
                                matchIdx = FindBytePattern(buffer, readLen, pat.AsciiBytes);
                                if (matchIdx < 0)
                                    matchIdx = FindBytePattern(buffer, readLen, pat.UnicodeBytes);
                            }
                            else
                            {
                                matchIdx = FindBytePatternIgnoreCaseAscii(buffer, readLen, pat.LowerAscii);
                                if (matchIdx < 0)
                                    matchIdx = FindBytePatternIgnoreCaseUnicode(buffer, readLen, pat.LowerAscii);
                            }

                            if (matchIdx >= 0)
                            {
                                foundSignatures.Add(pat.Name);
                                long matchAddr = readAddr.ToInt64() + matchIdx;
                                if (pat.IsSystemDlc)
                                {
                                    log($"Найден след SystemDLC в памяти процесса PID {pid}: {pat.Name} (адрес 0x{matchAddr:X})");
                                    banReasons.Add($"Найден след SystemDLC в памяти процесса (PID {pid}) - {pat.Name}");
                                }
                                else if (pat.IsDoomsday)
                                {
                                    log($"Инжект Doomsday: найдена строка чита в памяти PID {pid}: {pat.Name} (адрес 0x{matchAddr:X})");
                                    banReasons.Add($"Инжект Doomsday: строка чита в памяти Java ({pat.Name} в PID {pid})");
                                }
                                else
                                {
                                    log($"Найдена сигнатура в памяти PID {pid}: {pat.Name} (адрес 0x{matchAddr:X})");
                                    banReasons.Add($"Найдена сигнатура чита в памяти (PID {pid}) - {pat.Name}");
                                }
                            }
                        }
                    }
                }

                int step = Math.Max(chunk - 512, 1);
                offset += step;
            }
        }

        private static int FindBytePattern(byte[] buffer, int length, byte[] pattern)
        {
            if (pattern == null || pattern.Length == 0 || length < pattern.Length) return -1;
            byte first = pattern[0];
            int patLen = pattern.Length;
            int maxStart = length - patLen;
            int start = 0;

            while (start <= maxStart)
            {
                int idx = Array.IndexOf(buffer, first, start, length - start);
                if (idx < 0 || idx > maxStart) return -1;

                bool match = true;
                for (int j = 1; j < patLen; j++)
                {
                    if (buffer[idx + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return idx;

                start = idx + 1;
            }
            return -1;
        }

        private static int FindBytePatternIgnoreCaseAscii(byte[] buffer, int length, byte[] lowerPattern)
        {
            if (lowerPattern == null || lowerPattern.Length == 0 || length < lowerPattern.Length) return -1;
            byte first = lowerPattern[0];
            byte firstUpper = (first >= 'a' && first <= 'z') ? (byte)(first - 32) : first;
            int patLen = lowerPattern.Length;
            int maxStart = length - patLen;
            int start = 0;

            while (start <= maxStart)
            {
                int idx = -1;
                for (int i = start; i <= maxStart; i++)
                {
                    byte b = buffer[i];
                    if (b == first || b == firstUpper)
                    {
                        idx = i;
                        break;
                    }
                }
                if (idx < 0) return -1;

                bool match = true;
                for (int j = 1; j < patLen; j++)
                {
                    byte b = buffer[idx + j];
                    byte bLower = (b >= 'A' && b <= 'Z') ? (byte)(b + 32) : b;
                    if (bLower != lowerPattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return idx;

                start = idx + 1;
            }
            return -1;
        }

        private static int FindBytePatternIgnoreCaseUnicode(byte[] buffer, int length, byte[] lowerPattern)
        {
            if (lowerPattern == null || lowerPattern.Length == 0) return -1;
            int patLen = lowerPattern.Length;
            int unicodeBytesLen = patLen * 2;
            if (length < unicodeBytesLen) return -1;

            byte first = lowerPattern[0];
            byte firstUpper = (first >= 'a' && first <= 'z') ? (byte)(first - 32) : first;
            int maxStart = length - unicodeBytesLen;
            int start = 0;

            while (start <= maxStart)
            {
                int idx = -1;
                for (int i = start; i <= maxStart; i++)
                {
                    if (buffer[i + 1] == 0)
                    {
                        byte b = buffer[i];
                        if (b == first || b == firstUpper)
                        {
                            idx = i;
                            break;
                        }
                    }
                }
                if (idx < 0) return -1;

                bool match = true;
                for (int j = 1; j < patLen; j++)
                {
                    int bufPos = idx + j * 2;
                    if (buffer[bufPos + 1] != 0)
                    {
                        match = false;
                        break;
                    }
                    byte b = buffer[bufPos];
                    byte bLower = (b >= 'A' && b <= 'Z') ? (byte)(b + 32) : b;
                    if (bLower != lowerPattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return idx;

                start = idx + 1;
            }
            return -1;
        }

        private static bool ContainsBytePattern(byte[] buffer, int length, byte[] pattern)
        {
            return FindBytePattern(buffer, length, pattern) >= 0;
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

                var suspiciousKeywords = new[] { "inject", "hook", "hack", "cheat", "loader", "bypass", "systemdlc", "jlivef", "doomsday", "celestial", "nursultan", "deadcode", "rich", "expensive", "minced", "pulse visual", "pulsevisual" };

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
                            log($"   -> [Process Hacker] Как найти: Process Hacker -> PID {pid} (javaw.exe) -> вкладка Modules -> найти \"{modName}\" (проверить цифровую подпись и путь)");
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
                modNameLower.Contains("mediaplayerinfo") ||
                modPath.IndexOf(@"mediaplayerinfo", StringComparison.OrdinalIgnoreCase) >= 0 ||
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
                            log($"   -> [Process Hacker] Как найти: Process Hacker -> PID {pid} (javaw.exe) -> вкладка Modules -> найти \"{modName}\" (проверить цифровую подпись и путь)");
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
