using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AngelMineChecker
{
    public static class CheckDoomsday
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

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
        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_GUARD = 0x100;

        private static readonly string[] DoomsdayConhostSignatures = new[]
        {
            "doomsday loaded successfully",
            "starting inject shellcode",
            "injected! loading...",
            "failed to inject jvmti agent",
            "doomsdayclient.xyz"
        };

        private class MemorySignature
        {
            public string Pattern { get; }
            public string Category { get; }
            public byte[] LowerAscii { get; }

            public MemorySignature(string pattern, string category)
            {
                Pattern = pattern;
                Category = category;
                LowerAscii = Encoding.ASCII.GetBytes(pattern.ToLowerInvariant());
            }
        }

        private static readonly MemorySignature[] JvmMemorySignatures = new[]
        {
            new MemorySignature("post /font/", "font"),
            new MemorySignature("get /font/", "font"),
            new MemorySignature("/font/arial_", "font"),
            new MemorySignature("/font/arial", "font"),
            new MemorySignature("/font/tahoma", "font"),
            new MemorySignature("arial_3_128_2.png", "font"),
            new MemorySignature("host: doomsdayclient.xyz", "network"),
            new MemorySignature("host: doomsdayclient.com", "network"),
            new MemorySignature("https://doomsdayclient.xyz", "network"),
            new MemorySignature("http://doomsdayclient.xyz", "network"),
            new MemorySignature("doomsdayclient.xyz", "network"),
            new MemorySignature("doomsdayclient.com", "network"),
            new MemorySignature("cookie: data=", "network"),
            new MemorySignature("doomsday loaded successfully", "cheat"),
            new MemorySignature("starting inject shellcode", "cheat"),
            new MemorySignature("injected! loading...", "cheat"),
            new MemorySignature("--doomsdayargs", "cheat"),
            new MemorySignature("--doomsdayversion", "cheat"),
            new MemorySignature("--clickguikey", "cheat"),
            new MemorySignature("com/doomsday/tweaker", "cheat"),
            new MemorySignature("failed to inject jvmti agent", "cheat"),
            new MemorySignature("net/java/s", "class"),
            new MemorySignature("net/java/f", "class"),
            new MemorySignature("net/java/n", "class"),
            new MemorySignature("net/java/l", "class"),
            new MemorySignature("net/java/g", "class")
        };

        private static readonly byte[][] MemoryAnchors = new[]
        {
            Encoding.ASCII.GetBytes("doomsday"),
            Encoding.ASCII.GetBytes("/font/"),
            Encoding.ASCII.GetBytes("arial_"),
            Encoding.ASCII.GetBytes("cookie: data="),
            Encoding.ASCII.GetBytes("shellcode"),
            Encoding.ASCII.GetBytes("inject"),
            Encoding.ASCII.GetBytes("--clickgui"),
            Encoding.ASCII.GetBytes("net/java/")
        };

        public static bool CheckFile(FileInfo file, out string reason)
        {
            reason = "";
            if (file == null || !file.Exists) return false;

            try
            {
                long len = file.Length;
                if (len == 0 || len > 50 * 1024 * 1024) return false;

                string ext = file.Extension.ToLower();

                if (len >= 28000 && len <= 35000)
                {
                    byte[] raw = new byte[Math.Min((int)len, 65536)];
                    using (var fs = file.OpenRead())
                    {
                        fs.Read(raw, 0, raw.Length);
                    }
                    string rawUtf8 = Encoding.UTF8.GetString(raw);
                    if (rawUtf8.Contains("net/minecraft/client/entity/player/ClientPlayerEntity") ||
                        rawUtf8.Contains("net/minecraft/util/math/AxisAlignedBB"))
                    {
                        reason = "размер ~30KB и сигнатура Entity/AxisAlignedBB";
                        return true;
                    }
                }

                bool isZipFormat = ext == ".jar" || ext == ".zip" || ext == ".disabled" || ext == ".bak";
                if (!isZipFormat)
                {
                    using (var fs = file.OpenRead())
                    {
                        byte[] magic = new byte[4];
                        if (fs.Read(magic, 0, 4) == 4)
                        {
                            if (magic[0] == 0x50 && magic[1] == 0x4B && (magic[2] == 0x03 || magic[2] == 0x05 || magic[2] == 0x07))
                            {
                                isZipFormat = true;
                            }
                        }
                    }
                }

                if (isZipFormat && len >= 20000)
                {
                    bool hasRootLPng = false;
                    bool hasMcmodInfoDd = false;
                    bool hasFabricJsonDd = false;
                    bool hasModsTomlDd = false;
                    bool hasNetJava = false;
                    bool hasManifestNetJava = false;
                    bool hasDoomsdayPath = false;
                    bool hasLargeEncryptedPayload = false;

                    try
                    {
                        using (var archive = ZipFile.OpenRead(file.FullName))
                        {
                            foreach (var entry in archive.Entries)
                            {
                                string eName = entry.FullName.ToLower().Replace('\\', '/');

                                if (entry.FullName.Equals("l.png", StringComparison.OrdinalIgnoreCase) ||
                                    entry.FullName.Equals("/l.png", StringComparison.OrdinalIgnoreCase))
                                {
                                    hasRootLPng = true;
                                }

                                if (eName == "mcmod.info" || eName == "/mcmod.info")
                                {
                                    try
                                    {
                                        using (var s = entry.Open())
                                        using (var r = new StreamReader(s))
                                        {
                                            string txt = r.ReadToEnd();
                                            if (txt.Contains("\"dd\"") || txt.Contains("\"modid\":\"dd\"") || txt.Contains("\"modid\": \"dd\""))
                                                hasMcmodInfoDd = true;
                                        }
                                    }
                                    catch { }
                                }

                                if (eName == "fabric.mod.json" || eName == "/fabric.mod.json")
                                {
                                    try
                                    {
                                        using (var s = entry.Open())
                                        using (var r = new StreamReader(s))
                                        {
                                            string txt = r.ReadToEnd();
                                            if (txt.Contains("\"id\":\"dd\"") || txt.Contains("\"id\": \"dd\"") || (txt.Contains("\"entrypoints\"") && txt.Contains("\"dd\"")))
                                                hasFabricJsonDd = true;
                                        }
                                    }
                                    catch { }
                                }

                                if (eName.EndsWith("mods.toml") || eName.Contains("meta-inf/mods.toml"))
                                {
                                    try
                                    {
                                        using (var s = entry.Open())
                                        using (var r = new StreamReader(s))
                                        {
                                            string txt = r.ReadToEnd();
                                            if (txt.Contains("modId=\"dd\"") || txt.Contains("modId = \"dd\""))
                                                hasModsTomlDd = true;
                                        }
                                    }
                                    catch { }
                                }

                                if (eName == "net/java/s.class" || eName == "net/java/f.class" ||
                                    eName == "net/java/r.class" || eName == "net/java/h.class")
                                {
                                    hasNetJava = true;
                                }

                                if (eName.Contains("doomsday") || eName.Contains("doomday"))
                                    hasDoomsdayPath = true;

                                if (eName == "meta-inf/manifest.mf" || eName.EndsWith("/manifest.mf"))
                                {
                                    try
                                    {
                                        using (var stream = entry.Open())
                                        using (var reader = new StreamReader(stream))
                                        {
                                            string manifestText = reader.ReadToEnd();
                                            if (manifestText.IndexOf("Premain-Class: net.java.", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                (manifestText.IndexOf("net.java.", StringComparison.OrdinalIgnoreCase) >= 0 &&
                                                 manifestText.IndexOf("SplashScreen-Image: l.png", StringComparison.OrdinalIgnoreCase) >= 0))
                                            {
                                                hasManifestNetJava = true;
                                            }
                                        }
                                    }
                                    catch { }
                                }

                                if (!eName.Contains("/") && !eName.Contains(".") && entry.Length > 400000)
                                {
                                    hasLargeEncryptedPayload = true;
                                }
                            }
                        }

                        if (hasRootLPng && hasMcmodInfoDd)
                        {
                            reason = "сигнатура Doomsday (l.png + mcmod.info dd)";
                            return true;
                        }

                        if (hasRootLPng && (hasFabricJsonDd || hasModsTomlDd || hasManifestNetJava))
                        {
                            reason = "сигнатура Doomsday (l.png + metadata dd / manifest net.java)";
                            return true;
                        }

                        if (hasNetJava && (hasRootLPng || hasLargeEncryptedPayload || hasManifestNetJava))
                        {
                            reason = "сигнатура Doomsday (net/java + payload / manifest)";
                            return true;
                        }

                        if (hasFabricJsonDd && hasLargeEncryptedPayload)
                        {
                            reason = "сигнатура Doomsday (fabric dd + encrypted payload)";
                            return true;
                        }

                        if (hasDoomsdayPath)
                        {
                            reason = "внутренние пути Doomsday в архиве";
                            return true;
                        }
                    }
                    catch { }

                    byte[] zipHead = new byte[Math.Min((int)len, 1048576)];
                    using (var fs = file.OpenRead())
                    {
                        fs.Read(zipHead, 0, zipHead.Length);
                    }
                    string headUtf8 = Encoding.UTF8.GetString(zipHead);
                    if (headUtf8.Contains("net/java/s.class") && headUtf8.Contains("net/java/f.class"))
                    {
                        reason = "сигнатура Doomsday (net/java/s.class, f.class в байткоде)";
                        return true;
                    }
                }
            }
            catch { }

            return false;
        }

        public static int CheckActiveProcesses(Action<string> log, List<string> banReasons)
        {
            int threats = 0;
            int currentPid = Process.GetCurrentProcess().Id;
            try
            {
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
                            if (cmdLower.Contains("angelminechecker") || pName.Contains("devenv") || pName.Contains("msbuild")) continue;

                            if (pName.Contains("chrome") || pName.Contains("brave") || pName.Contains("msedge") ||
                                pName.Contains("firefox") || pName.Contains("opera") || pName.Contains("yandex") ||
                                pName.Contains("browser") || pName.Contains("discord") || pName.Contains("telegram") ||
                                pName.Contains("explorer") || pName.Contains("vivaldi") || pName.Contains("tor") ||
                                pName.Contains("arc") || pName.Contains("waterfox") || pName.Contains("chromium"))
                            {
                                continue;
                            }

                            if (cmdLower.Contains("google.com") || cmdLower.Contains("youtube.com") || cmdLower.Contains("yandex.") ||
                                cmdLower.Contains("/search?") || cmdLower.Contains("q=") || cmdLower.Contains("bing.com") ||
                                cmdLower.Contains("duckduckgo.com"))
                            {
                                continue;
                            }

                            string cleanCmd = cmd.Replace("\r", " ").Replace("\n", " ").Trim();
                            if (cleanCmd.Length > 120) cleanCmd = cleanCmd.Substring(0, 117) + "...";

                            if (pName.Contains("doomsday") || pName.Contains("doomday") ||
                                ((pName.Contains("java") || pName.Contains("cmd") || pName.Contains("powershell")) &&
                                 (cmdLower.Contains("doomsdayclient") || cmdLower.Contains("z4mfltptb") ||
                                  cmdLower.Contains("--doomsday") || cmdLower.Contains("com.doomsday"))))
                            {
                                log?.Invoke($"Найден активный процесс чита Doomsday: {pName} (PID {pid}) -> {cleanCmd}");
                                banReasons.Add($"Активный процесс Doomsday (PID {pid}) - {cleanCmd}");
                                threats++;
                                continue;
                            }

                            if (cmdLower.Contains("inject shellcode") || cmdLower.Contains("doomsday loaded"))
                            {
                                log?.Invoke($"Найден процесс инжектора Doomsday: {pName} (PID {pid}) -> {cleanCmd}");
                                banReasons.Add($"Инжектор Doomsday (PID {pid}) - {cleanCmd}");
                                threats++;
                                continue;
                            }

                            if ((cmdLower.Contains("-jar") || cmdLower.Contains("-cp")) && cmdLower.Contains(".dll"))
                            {
                                log?.Invoke($"Найден активный процесс запуска JAR/Doomsday под видом DLL: {pName} (PID {pid}) -> {cleanCmd}");
                                banReasons.Add($"Запуск чита под видом DLL (PID {pid}) - {cleanCmd}");
                                threats++;
                                continue;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return threats;
        }

        public static int CheckConhostMemory(Action<string> log, List<string> banReasons)
        {
            int found = 0;

            try
            {
                string psHist = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                );

                if (File.Exists(psHist))
                {
                    var lines = File.ReadAllLines(psHist);
                    foreach (var line in lines)
                    {
                        string trimmed = line.Trim();
                        string lower = trimmed.ToLower();
                        if (lower.Contains("angelminechecker") || lower.Contains("checkdoomsday") ||
                            lower.Contains("select-string") || lower.Contains("findstr") || lower.Contains("grep") ||
                            lower.Contains("get-help") || lower.Contains("search")) continue;

                        string cleanLine = trimmed.Replace("\r", " ").Replace("\n", " ").Trim();
                        if (cleanLine.Length > 110) cleanLine = cleanLine.Substring(0, 107) + "...";

                        if (lower.Contains("doomsday") || lower.Contains("doomday") || lower.Contains("shellcode") ||
                            (lower.Contains("java") && lower.Contains("-jar") && lower.Contains(".dll")))
                        {
                            log?.Invoke($"Найден след Doomsday в истории PowerShell: {cleanLine}");
                            banReasons.Add($"След запуска Doomsday в истории PowerShell - {cleanLine}");
                            found++;
                        }
                    }
                }
            }
            catch { }

            try
            {
                var conhosts = Process.GetProcessesByName("conhost");
                var lowerPatterns = DoomsdayConhostSignatures.Select(s => Encoding.ASCII.GetBytes(s.ToLower())).ToList();

                foreach (var proc in conhosts)
                {
                    IntPtr hProcess = IntPtr.Zero;
                    try
                    {
                        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                        if (hProcess == IntPtr.Zero) continue;

                        long maxAddress = 0x7FFFFFFF0000;
                        long currentAddress = 0;
                        byte[] buffer = new byte[131072];

                        var detectedInProc = new HashSet<string>();
                        var sw = Stopwatch.StartNew();

                        while (currentAddress < maxAddress)
                        {
                            if (detectedInProc.Count > 0 || sw.ElapsedMilliseconds > 3000) break;

                            MEMORY_BASIC_INFORMATION mbi;
                            int res = VirtualQueryEx(hProcess, new IntPtr(currentAddress), out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                            if (res == 0) break;

                            long regionBytes = mbi.RegionSize.ToInt64();
                            if (regionBytes <= 0) break;

                            if (mbi.State == MEM_COMMIT &&
                                (mbi.Protect & PAGE_GUARD) == 0 &&
                                (mbi.Protect & PAGE_NOACCESS) == 0 &&
                                ((mbi.Protect & PAGE_READWRITE) != 0 || (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0))
                            {
                                long bytesToRead = Math.Min(regionBytes, 4194304);
                                long offset = 0;

                                while (offset < bytesToRead)
                                {
                                    if (detectedInProc.Count > 0) break;

                                    int chunk = (int)Math.Min((long)buffer.Length, bytesToRead - offset);
                                    IntPtr readAddr = new IntPtr(mbi.BaseAddress.ToInt64() + offset);

                                    if (ReadProcessMemory(hProcess, readAddr, buffer, chunk, out IntPtr readCount))
                                    {
                                        int readLen = readCount.ToInt32();
                                        if (readLen > 0)
                                        {
                                            for (int i = 0; i < lowerPatterns.Count; i++)
                                            {
                                                string patName = DoomsdayConhostSignatures[i];
                                                if (detectedInProc.Contains(patName)) continue;

                                                byte[] patBytes = lowerPatterns[i];
                                                if (ContainsAsciiCaseInsensitive(buffer, readLen, patBytes) ||
                                                    ContainsUnicodeCaseInsensitive(buffer, readLen, patBytes))
                                                {
                                                    detectedInProc.Add(patName);
                                                    log?.Invoke($"Найден след Doomsday в буфере консоли (conhost.exe PID {proc.Id}): \"{patName}\"");
                                                    banReasons.Add($"След Doomsday в буфере консоли conhost.exe (PID {proc.Id}) - {patName}");
                                                    found++;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    offset += chunk;
                                }
                            }

                            currentAddress = mbi.BaseAddress.ToInt64() + regionBytes;
                        }
                    }
                    catch { }
                    finally
                    {
                        if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                    }
                }
            }
            catch { }

            return found;
        }

        public static int CheckJvmAttach(Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                string tempPath = Path.GetTempPath();
                if (Directory.Exists(tempPath))
                {
                    try
                    {
                        var attachFiles = Directory.GetFiles(tempPath, ".attach_pid*");
                        foreach (var af in attachFiles)
                        {
                            try
                            {
                                var fi = new FileInfo(af);
                                if (DateTime.Now - fi.LastWriteTime < TimeSpan.FromHours(4))
                                {
                                    log?.Invoke($"Обнаружен след динамического подключения к JVM (HotSpot Attach API): {Path.GetFileName(af)} ({fi.LastWriteTime:HH:mm:ss})");
                                    banReasons.Add($"Динамическое подключение к JVM (Attach API) - {Path.GetFileName(af)}");
                                    found++;
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }

                var javaProcs = Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java"));
                foreach (var proc in javaProcs)
                {
                    try
                    {
                        foreach (ProcessModule mod in proc.Modules)
                        {
                            if (string.Equals(mod.ModuleName, "attach.dll", StringComparison.OrdinalIgnoreCase))
                            {
                                log?.Invoke($"Обнаружен инжект через Attach API: attach.dll загружен в процесс Java (PID {proc.Id})");
                                banReasons.Add($"Динамический инжект в JVM (attach.dll в процессе PID {proc.Id})");
                                found++;
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return found;
        }

        public static int CheckDnsCache(Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/displaydns",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(3000);

                    if (output.IndexOf("doomsdayclient.xyz", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        output.IndexOf("doomsdayclient.com", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        log?.Invoke("Обнаружен домен Doomsday в системном DNS-кэше Windows (doomsdayclient.xyz)");
                        banReasons.Add("След Doomsday в DNS-кэше Windows (doomsdayclient.xyz)");
                        found++;
                    }
                }

                if (found == 0)
                {
                    try
                    {
                        var psPsi = new ProcessStartInfo
                        {
                            FileName = "powershell",
                            Arguments = "-NoProfile -Command \"Get-DnsClientCache | Where-Object { $_.Entry -like '*doomsdayclient*' } | Select-Object -ExpandProperty Entry\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        };
                        using (var psProc = Process.Start(psPsi))
                        {
                            string psOut = psProc.StandardOutput.ReadToEnd();
                            psProc.WaitForExit(3000);
                            if (psOut.IndexOf("doomsdayclient.xyz", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                psOut.IndexOf("doomsdayclient.com", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                log?.Invoke("Обнаружена запись Doomsday в кэше DNS клиента Windows");
                                banReasons.Add("След Doomsday в DNS-кэше Windows");
                                found++;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return found;
        }

        public static int CheckJnaModules(int? preferredPid, Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var targetPids = new List<int>();
                if (preferredPid.HasValue && preferredPid.Value > 0)
                {
                    targetPids.Add(preferredPid.Value);
                }

                foreach (var p in Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java")))
                {
                    if (!targetPids.Contains(p.Id))
                        targetPids.Add(p.Id);
                }

                foreach (int pid in targetPids)
                {
                    try
                    {
                        var proc = Process.GetProcessById(pid);
                        var jnaModules = new List<ProcessModule>();

                        foreach (ProcessModule mod in proc.Modules)
                        {
                            string mName = (mod.ModuleName ?? "").ToLower();
                            if (mName.Contains("jna") || mName.Contains("jnidispatch"))
                            {
                                jnaModules.Add(mod);
                            }
                        }

                        if (jnaModules.Count == 0) continue;

                        var moduleDescs = new List<string>();
                        bool hasSuspiciousJna = false;

                        for (int i = 0; i < jnaModules.Count; i++)
                        {
                            var mod = jnaModules[i];
                            string modName = "unknown";
                            string filePath = "";

                            try { modName = mod.ModuleName ?? "jna_module"; } catch { }
                            try { filePath = mod.FileName ?? ""; } catch { }

                            string modInfo;
                            if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                            {
                                try
                                {
                                    var fi = new FileInfo(filePath);
                                    var vi = mod.FileVersionInfo;

                                    string desc = (vi?.FileDescription ?? "").Trim();
                                    string ver = (vi?.FileVersion ?? "").Trim();
                                    string prod = (vi?.ProductName ?? "").Trim();

                                    bool emptyMeta = string.IsNullOrEmpty(desc) && string.IsNullOrEmpty(ver) && string.IsNullOrEmpty(prod);
                                    bool hasCompanionX = File.Exists(filePath + ".x");

                                    string sha256 = "";
                                    if (fi.Length > 0 && fi.Length < 20 * 1024 * 1024)
                                    {
                                        using (var sha = SHA256.Create())
                                        using (var fs = fi.OpenRead())
                                        {
                                            byte[] hashBytes = sha.ComputeHash(fs);
                                            sha256 = BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();
                                        }
                                    }

                                    string flagReason = "";
                                    if (sha256 == "AD683F7AE2C912EF502FD802F256094FCEAA238260115CAAEFB1913A13ABD5E2")
                                    {
                                        hasSuspiciousJna = true;
                                        flagReason = "сигнатура Doomsday SHA256";
                                    }
                                    else if (emptyMeta && hasCompanionX)
                                    {
                                        hasSuspiciousJna = true;
                                        flagReason = "Doomsday companion .x";
                                    }
                                    else if (emptyMeta && fi.Length >= 300000 && fi.Length <= 450000)
                                    {
                                        hasSuspiciousJna = true;
                                        flagReason = "аномальный размер и пустые метаданные";
                                    }

                                    string sizeStr = $"{fi.Length / 1024} КБ";
                                    string timeStr = fi.CreationTime.ToString("dd.MM.yyyy HH:mm:ss");
                                    string note = !string.IsNullOrEmpty(flagReason) ? $", {flagReason}" : "";

                                    modInfo = $"{modName} [{filePath}] ({sizeStr}, {timeStr}{note})";
                                }
                                catch
                                {
                                    modInfo = $"{modName} [{filePath}]";
                                }
                            }
                            else
                            {
                                modInfo = string.IsNullOrEmpty(filePath) ? modName : $"{modName} [{filePath}]";
                            }

                            moduleDescs.Add(modInfo);
                        }

                        if (hasSuspiciousJna || jnaModules.Count > 1)
                        {
                            log?.Invoke($"Обнаружен инжект Doomsday через JNA native в процессе PID {pid} ({jnaModules.Count} JNA модулей):");
                            foreach (var md in moduleDescs)
                            {
                                log?.Invoke($"  -> {md}");
                            }

                            for (int i = 0; i < moduleDescs.Count; i++)
                            {
                                banReasons.Add($"Инжект Doomsday в процесс PID {pid} (модуль #{i + 1}: {moduleDescs[i]})");
                            }
                            found++;
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return found;
        }

        public static int CheckLoopbackPorts(int? preferredPid, Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var targetPids = new HashSet<int>();
                if (preferredPid.HasValue && preferredPid.Value > 0)
                {
                    targetPids.Add(preferredPid.Value);
                }

                foreach (var p in Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java")))
                {
                    targetPids.Add(p.Id);
                }

                if (targetPids.Count == 0) return 0;

                var psi = new ProcessStartInfo
                {
                    FileName = "netstat",
                    Arguments = "-ano -p tcp",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using (var proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(3000);

                    using (var reader = new StringReader(output))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (!line.StartsWith("TCP", StringComparison.OrdinalIgnoreCase)) continue;

                            string[] parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length < 5) continue;

                            string localAddr = parts[1];
                            string remoteAddr = parts[2];
                            string state = parts[3];
                            string pidStr = parts[4];

                            if (int.TryParse(pidStr, out int pid) && targetPids.Contains(pid))
                            {
                                if (state.Equals("LISTENING", StringComparison.OrdinalIgnoreCase) && (localAddr.StartsWith("127.0.0.1:") || localAddr.StartsWith("[::1]:")))
                                {
                                    string port = localAddr.Substring(localAddr.LastIndexOf(':') + 1);
                                    log?.Invoke($"Обнаружен активный порт IPC Doomsday в процессе PID {pid}: {localAddr}");
                                    banReasons.Add($"Скрытый локальный порт Doomsday (127.0.0.1:{port} в PID {pid})");
                                    found++;
                                }

                                if (remoteAddr.StartsWith("172.67.138.") || remoteAddr.StartsWith("104.21.48.") || remoteAddr.StartsWith("165.22.196."))
                                {
                                    log?.Invoke($"Обнаружено сетевое подключение Java к серверу Doomsday (PID {pid} -> {remoteAddr}, {state})");
                                    banReasons.Add($"Сетевое подключение Java к серверу Doomsday ({remoteAddr} в PID {pid}, {state})");
                                    found++;
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            return found;
        }

        public static int CheckJvmMemory(int? preferredPid, Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var targetPids = new List<int>();
                if (preferredPid.HasValue && preferredPid.Value > 0)
                {
                    targetPids.Add(preferredPid.Value);
                }

                foreach (var p in Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java")))
                {
                    if (!targetPids.Contains(p.Id))
                        targetPids.Add(p.Id);
                }

                if (targetPids.Count == 0) return 0;

                foreach (int pid in targetPids)
                {
                    IntPtr hProcess = IntPtr.Zero;
                    try
                    {
                        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                        if (hProcess == IntPtr.Zero) continue;

                        long maxAddress = 0x7FFFFFFF0000;
                        long currentAddress = 0;
                        byte[] buffer = new byte[262144];
                        var detectedInPid = new HashSet<string>();
                        var sw = Stopwatch.StartNew();

                        while (currentAddress < maxAddress)
                        {
                            if (detectedInPid.Count >= 5 || sw.ElapsedMilliseconds > 3500) break;

                            MEMORY_BASIC_INFORMATION mbi;
                            int res = VirtualQueryEx(hProcess, new IntPtr(currentAddress), out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                            if (res == 0) break;

                            long regionBytes = mbi.RegionSize.ToInt64();
                            if (regionBytes <= 0) break;

                            if (mbi.State == MEM_COMMIT &&
                                (mbi.Protect & PAGE_GUARD) == 0 &&
                                (mbi.Protect & PAGE_NOACCESS) == 0 &&
                                ((mbi.Protect & PAGE_READONLY) != 0 ||
                                 (mbi.Protect & PAGE_READWRITE) != 0 ||
                                 (mbi.Protect & PAGE_EXECUTE_READ) != 0 ||
                                 (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0))
                            {
                                long bytesToRead = Math.Min(regionBytes, 67108864);
                                long offset = 0;

                                while (offset < bytesToRead)
                                {
                                    if (detectedInPid.Count >= 5 || sw.ElapsedMilliseconds > 3500) break;

                                    int chunk = (int)Math.Min((long)buffer.Length, bytesToRead - offset);
                                    IntPtr readAddr = new IntPtr(mbi.BaseAddress.ToInt64() + offset);

                                    if (ReadProcessMemory(hProcess, readAddr, buffer, chunk, out IntPtr readCount))
                                    {
                                        int readLen = readCount.ToInt32();
                                        if (readLen > 0)
                                        {
                                            bool hasAnyAnchor = false;
                                            for (int a = 0; a < MemoryAnchors.Length; a++)
                                            {
                                                if (ContainsAsciiCaseInsensitive(buffer, readLen, MemoryAnchors[a]) ||
                                                    ContainsUnicodeCaseInsensitive(buffer, readLen, MemoryAnchors[a]))
                                                {
                                                    hasAnyAnchor = true;
                                                    break;
                                                }
                                            }

                                            if (hasAnyAnchor)
                                            {
                                                for (int i = 0; i < JvmMemorySignatures.Length; i++)
                                                {
                                                    var sig = JvmMemorySignatures[i];
                                                    if (detectedInPid.Contains(sig.Pattern)) continue;

                                                    if (ContainsAsciiCaseInsensitive(buffer, readLen, sig.LowerAscii) ||
                                                        ContainsUnicodeCaseInsensitive(buffer, readLen, sig.LowerAscii))
                                                    {
                                                        detectedInPid.Add(sig.Pattern);
                                                        string desc;
                                                        if (sig.Category == "font")
                                                            desc = $"Сетевая загрузка шрифтов Doomsday в Java ({sig.Pattern} в PID {pid})";
                                                        else if (sig.Category == "network")
                                                            desc = $"Сетевое обращение Java к серверу Doomsday ({sig.Pattern} в PID {pid})";
                                                        else if (sig.Category == "class")
                                                            desc = $"Класс чита Doomsday в памяти Java ({sig.Pattern} в PID {pid})";
                                                        else
                                                            desc = $"След чита Doomsday в памяти Java ({sig.Pattern} в PID {pid})";

                                                        log?.Invoke(desc);
                                                        banReasons.Add(desc);
                                                        found++;
                                                        if (detectedInPid.Count >= 5) break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    int step = Math.Max(chunk - 256, 1);
                                    offset += step;
                                }
                            }

                            currentAddress = mbi.BaseAddress.ToInt64() + regionBytes;
                        }
                    }
                    catch { }
                    finally
                    {
                        if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                    }
                }
            }
            catch { }

            return found;
        }

        public static int CheckFileSystemTraces(Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var dirsToCheck = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    Path.GetTempPath()
                };

                try
                {
                    foreach (var drive in DriveInfo.GetDrives())
                    {
                        if (drive.IsReady && (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable))
                        {
                            string r = drive.RootDirectory.FullName;
                            string dl1 = Path.Combine(r, "Downloads");
                            if (Directory.Exists(dl1)) dirsToCheck.Add(dl1);
                            string dl2 = Path.Combine(r, "Загрузки");
                            if (Directory.Exists(dl2)) dirsToCheck.Add(dl2);
                            string dt1 = Path.Combine(r, "Desktop");
                            if (Directory.Exists(dt1)) dirsToCheck.Add(dt1);
                            string dt2 = Path.Combine(r, "Рабочий стол");
                            if (Directory.Exists(dt2)) dirsToCheck.Add(dt2);
                        }
                    }
                }
                catch { }

                foreach (var dir in dirsToCheck)
                {
                    if (!Directory.Exists(dir)) continue;

                    try
                    {
                        var files = Directory.GetFiles(dir);
                        foreach (var f in files)
                        {
                            try
                            {
                                var fi = new FileInfo(f);
                                if (fi.Length < 20000 || fi.Length > 50 * 1024 * 1024) continue;

                                if (CheckFile(fi, out string reason))
                                {
                                    log?.Invoke($"Найден чит Doomsday: {Path.GetFileName(f)} ({reason}) [{f}]");
                                    banReasons.Add($"Найден чит Doomsday - {f} ({reason})");
                                    found++;
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return found;
        }

        private static readonly object _findingsLock = new object();
        private static readonly List<string> _lastDetailedFindings = new List<string>();

        public static List<string> GetLastDetailedFindings()
        {
            lock (_findingsLock)
            {
                return new List<string>(_lastDetailedFindings);
            }
        }

        public static string EnrichSavedLog(string originalLog)
        {
            if (string.IsNullOrWhiteSpace(originalLog)) return originalLog;

            List<string> details = GetLastDetailedFindings();
            if (details == null || details.Count == 0) return originalLog;

            var sb = new StringBuilder();
            using (var reader = new StringReader(originalLog))
            {
                string line;
                bool bodyDetailsInserted = false;
                bool inSummary = false;

                while ((line = reader.ReadLine()) != null)
                {
                    if (line.Contains("Итоги:"))
                    {
                        inSummary = true;
                    }

                    if (!bodyDetailsInserted && !inSummary && line.Contains("Инжект думика обнаружен"))
                    {
                        sb.AppendLine(line);
                        bodyDetailsInserted = true;
                        foreach (var det in details)
                        {
                            sb.AppendLine($"           -> Найден след: {det}");
                        }
                        continue;
                    }

                    if (inSummary && line.Contains("Инжект думика обнаружен"))
                    {
                        sb.AppendLine(line + ":");
                        foreach (var det in details)
                        {
                            sb.AppendLine($"  * {det}");
                        }
                        continue;
                    }

                    sb.AppendLine(line);
                }
            }

            return sb.ToString();
        }

        public static async Task<int> RunDoomsdayCheckAsync(Action<string> log, List<string> banReasons, int? targetPid = null)
        {
            log?.Invoke("Проверка doomsday");

            int totalFound = 0;
            var internalReasons = new List<string>();

            await Task.Run(() =>
            {
                totalFound += CheckActiveProcesses(null, internalReasons);
                totalFound += CheckJnaModules(targetPid, null, internalReasons);
                totalFound += CheckLoopbackPorts(targetPid, null, internalReasons);
                totalFound += CheckConhostMemory(null, internalReasons);
                totalFound += CheckJvmAttach(null, internalReasons);
                totalFound += CheckJvmMemory(targetPid, null, internalReasons);
                totalFound += CheckFileSystemTraces(null, internalReasons);

                var dnsReasons = new List<string>();
                int dnsFound = CheckDnsCache(null, dnsReasons);
                if (internalReasons.Count > 0 && dnsFound > 0)
                {
                    internalReasons.AddRange(dnsReasons);
                    totalFound += dnsFound;
                }
            });

            if (totalFound > 0 || internalReasons.Count > 0)
            {
                lock (_findingsLock)
                {
                    _lastDetailedFindings.Clear();
                    _lastDetailedFindings.AddRange(internalReasons.Distinct());
                }
                log?.Invoke("Инжект думика обнаружен");
                banReasons.Add("Инжект думика обнаружен");
                return Math.Max(totalFound, internalReasons.Count);
            }
            else
            {
                lock (_findingsLock)
                {
                    _lastDetailedFindings.Clear();
                }
                log?.Invoke("Инжект думика не обнаружен");
                return 0;
            }
        }

        private static bool ContainsAsciiCaseInsensitive(byte[] buffer, int length, byte[] lowerPattern)
        {
            if (lowerPattern == null || lowerPattern.Length == 0 || length < lowerPattern.Length) return false;
            byte first = lowerPattern[0];
            int max = length - lowerPattern.Length;
            for (int i = 0; i <= max; i++)
            {
                byte b = buffer[i];
                if (b >= 65 && b <= 90) b = (byte)(b + 32);
                if (b == first)
                {
                    bool match = true;
                    for (int j = 1; j < lowerPattern.Length; j++)
                    {
                        byte bj = buffer[i + j];
                        if (bj >= 65 && bj <= 90) bj = (byte)(bj + 32);
                        if (bj != lowerPattern[j])
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

        private static bool ContainsUnicodeCaseInsensitive(byte[] buffer, int length, byte[] lowerPattern)
        {
            if (lowerPattern == null || lowerPattern.Length == 0) return false;
            int patLen = lowerPattern.Length;
            int unicodeBytesLen = patLen * 2;
            if (length < unicodeBytesLen) return false;

            byte first = lowerPattern[0];
            int max = length - unicodeBytesLen;
            for (int i = 0; i <= max; i++)
            {
                if (i + 1 < length && buffer[i + 1] == 0)
                {
                    byte b = buffer[i];
                    if (b >= 65 && b <= 90) b = (byte)(b + 32);
                    if (b == first)
                    {
                        bool match = true;
                        for (int j = 1; j < patLen; j++)
                        {
                            int idx = i + j * 2;
                            if (idx + 1 >= length || buffer[idx + 1] != 0) { match = false; break; }
                            byte bj = buffer[idx];
                            if (bj >= 65 && bj <= 90) bj = (byte)(bj + 32);
                            if (bj != lowerPattern[j])
                            {
                                match = false;
                                break;
                            }
                        }
                        if (match) return true;
                    }
                }
            }
            return false;
        }
    }
}
