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
using AngelMineChecker.Services;

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

        private static bool IsReadablePage(uint protect)
        {
            if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0)
                return false;

            return (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        }

        private static readonly string[] DoomsdayConhostSignatures = new[]
        {
            "doomsday loaded successfully",
            "starting inject shellcode",
            "injected! loading...",
            "failed to inject jvmti agent"
        };

        private class MemorySignature
        {
            public string Pattern { get; }
            public string Category { get; }
            public byte[] AsciiBytes { get; }
            public byte[] UnicodeBytes { get; }
            public byte[] LowerAscii { get; }
            public bool IsCaseSensitive { get; }

            public MemorySignature(string pattern, string category, bool caseSensitive = true)
            {
                Pattern = pattern;
                Category = category;
                IsCaseSensitive = caseSensitive;
                AsciiBytes = Encoding.ASCII.GetBytes(pattern);
                UnicodeBytes = Encoding.Unicode.GetBytes(pattern);
                LowerAscii = Encoding.ASCII.GetBytes(pattern.ToLowerInvariant());
            }
        }

        public static readonly string[] DoomsdayStrings = new[]
        {
            "qngOR4LLGyKpHanrK8257iBxbxMLILqj",
            "pOWYffAhUci9yTiGHi1bSrpFaRLbK6ZDT4vIk7vHrvEsDBcD6QT7POsEbLU9p0Ht",
            "3cZ8yz8CJ9uuhbLGNoP8WK",
            "65kB6yOHkqyIVHie0aJz",
            "77X7GjcoO4ls1YMc7VN7Fh1AWV7exvj",
            "Be83IIp7HqD0FnuT6cMRXWq3ITh",
            "BwXrWWLndVgXP3nCjl2T7",
            "E1aTaHoeCvF0jiUMjljhOySuCDeDNiofTP0",
            "KCfcPreShXlnj2mM7opNnNXU1",
            "M0aJQ9EgVBLjLlADgBC5JfMjvLS8CNvgZB",
            "N09dquWSSCG9ynxpcMggwnJ",
            "N1Yer2oZeGUJqxIm04nrCNmwq",
            "PqbsqY27KTVTy1Xqb5Qu9FC0",
            "YMJ5m3rttKKSpwwLcVNd",
            "YWCmzr2hnYumBIQi6Z6tiB",
            "aBhR9NFYh42RCOhGjEshc3vy8ySusnMCg",
            "cGJHcgcMLH16Zu5IMk7UYIewjrKj01poctpG",
            "dmFcvYcNaY3KuzlCh2DK0BIAWIjN8",
            "gg2v3Oa3pmFXxSSWbvF0",
            "ggQK7smmxq7LeCmYbDKROn6S4XHo",
            "i7S0WoWzDer3BYyRXFGq8",
            "lIjhTaufwBC3j8y4YP0ih5nyp",
            "nlGrUNIITzTtE5hCWN31Ft1MUuFoFnJC4QjaeEAM",
            "plwGne3k2xIRR9ylbugeaJRSsTRa7ZKdOgV",
            "qyTc3jia9nMEVCjA6BHsYId",
            "s5h9gkjvwLCo2xSO0XE8Y9jz5CZa",
            "sMxo38AGCNB483R4CPUZmxYJ17hwqUyBu",
            "sv6yaeCLf6G7VKHbnEBUVCrU",
            "uaVGhewx0602RnDcS9esl2PStmbAVr",
            "vgLxlB1s5LnZi9QdMdFIPtn6TD5AH4a8w7z11Or",
            "y3426mpn375PMaoxUvKH",
            "yBFeXFluO2kzpPtm6ANtUX"
        };

        private static readonly MemorySignature[] JvmMemorySignatures = BuildMemorySignatures();

        private static MemorySignature[] BuildMemorySignatures()
        {
            var list = new List<MemorySignature>
            {
                new MemorySignature("com/doomsday/tweaker", "class", false),
                new MemorySignature("com/doomsday", "class", false),
                new MemorySignature("doomsdayclient.xyz", "network", false),
                new MemorySignature("doomsdayclient.com", "network", false),
                new MemorySignature("doomsdayclient", "cheat", false),
                new MemorySignature("doomsday", "cheat", false),
                new MemorySignature("host: doomsdayclient.xyz", "network", false),
                new MemorySignature("host: doomsdayclient.com", "network", false),
                new MemorySignature("https://doomsdayclient.xyz", "network", false),
                new MemorySignature("http://doomsdayclient.xyz", "network", false),
                new MemorySignature("doomsday loaded successfully", "cheat", false),
                new MemorySignature("starting inject shellcode", "cheat", false),
                new MemorySignature("injected! loading...", "cheat", false),
                new MemorySignature("--doomsdayargs", "cheat", false),
                new MemorySignature("--doomsdayversion", "cheat", false),
                new MemorySignature("--clickguikey", "cheat", false),
                new MemorySignature("failed to inject jvmti agent", "cheat", false),
                new MemorySignature("z4mfltptb", "cheat", false),
                new MemorySignature("arial_3_128_2.png", "font", false),
                new MemorySignature("ru/bcloader", "class", false),
                new MemorySignature("bcloader", "cheat", false)
            };

            foreach (var str in DoomsdayStrings)
            {
                list.Add(new MemorySignature(str, "string", true));
            }

            return list.ToArray();
        }

        public static bool CheckFile(FileInfo file, out string reason)
        {
            reason = "";
            if (file == null || !file.Exists) return false;

            try
            {
                long len = file.Length;
                if (len == 0 || len > 50 * 1024 * 1024) return false;
                if (file.Name.Equals("launcher.jar", StringComparison.OrdinalIgnoreCase)) return false;

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
                                    eName == "net/java/r.class" || eName == "net/java/h.class" ||
                                    eName == "net/java/g.class" || eName == "net/java/l.class")
                                {
                                    hasNetJava = true;
                                }

                                if ((eName.Contains("doomsday") || eName.Contains("doomday")) &&
                                    !eName.Contains("doomsdaymanager") && !eName.Contains("legacylauncher"))
                                {
                                    hasDoomsdayPath = true;
                                }

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

                        if (hasNetJava && (hasFabricJsonDd || hasModsTomlDd || hasMcmodInfoDd))
                        {
                            reason = "сигнатура Doomsday (net/java + mod metadata dd)";
                            return true;
                        }

                        if (hasDoomsdayPath)
                        {
                            reason = "внутренние пути Doomsday в архиве";
                            return true;
                        }

                        if (file.Name.IndexOf("z4mfltptb", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            reason = "сигнатура сборки Doomsday (z4mfltptb)";
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
                                cmdLower.Contains("duckduckgo.com") || cmdLower.Contains("where-object") ||
                                cmdLower.Contains("get-dnsclientcache") || cmdLower.Contains("resolve-dnsname") ||
                                cmdLower.Contains("get-nettcpconnection") || cmdLower.Contains("findstr") ||
                                cmdLower.Contains("select-string") || cmdLower.Contains("get-winevent") ||
                                cmdLower.Contains("format-table"))
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

                            if (cmdLower.Contains("-jar "))
                            {
                                int jarIdx = cmd.IndexOf("-jar ", StringComparison.OrdinalIgnoreCase);
                                if (jarIdx >= 0)
                                {
                                    string remainder = cmd.Substring(jarIdx + 5).Trim();
                                    string jarTarget = "";
                                    if (remainder.StartsWith("\""))
                                    {
                                        int endQuote = remainder.IndexOf('"', 1);
                                        if (endQuote > 1) jarTarget = remainder.Substring(1, endQuote - 1);
                                    }
                                    else
                                    {
                                        int spaceIdx = remainder.IndexOf(' ');
                                        jarTarget = spaceIdx > 0 ? remainder.Substring(0, spaceIdx) : remainder;
                                    }

                                    if (!string.IsNullOrEmpty(jarTarget) && File.Exists(jarTarget))
                                    {
                                        try
                                        {
                                            var fi = new FileInfo(jarTarget);
                                            if (CheckFile(fi, out string jarReason))
                                            {
                                                log?.Invoke($"Найден активный процесс чита Doomsday ({fi.Name}): {pName} (PID {pid}) -> {cleanCmd}");
                                                banReasons.Add($"Активный процесс Doomsday (PID {pid}, {fi.Name}: {jarReason})");
                                                threats++;
                                                continue;
                                            }
                                        }
                                        catch { }
                                    }
                                }
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
                        if (string.IsNullOrWhiteSpace(trimmed)) continue;

                        if (lower.Contains("angelminechecker") || lower.Contains("checkdoomsday") ||
                            lower.Contains("select-string") || lower.Contains("findstr") || lower.Contains("grep") ||
                            lower.Contains("get-help") || lower.Contains("search") || lower.Contains("where-object") ||
                            lower.Contains("select-object") || lower.Contains("format-table") || lower.Contains("out-string") ||
                            lower.Contains("get-dnsclientcache") || lower.Contains("resolve-dnsname") ||
                            lower.Contains("get-nettcpconnection") || lower.Contains("test-netconnection") ||
                            lower.Contains("get-winevent") || lower.Contains("get-process") || lower.Contains("get-item") ||
                            lower.Contains("get-childitem") || lower.Contains("get-content") || lower.Contains("get-filehash") ||
                            lower.Contains("gci ") || lower.Contains("dir ") || lower.Contains("ls ") ||
                            lower.Contains("ping ") || lower.Contains("nslookup") || lower.Contains("ipconfig") ||
                            lower.Contains("curl ") || lower.Contains("echo ") || lower.Contains("write-host") ||
                            lower.Contains("write-output"))
                        {
                            continue;
                        }

                        string cleanLine = trimmed.Replace("\r", " ").Replace("\n", " ").Trim();
                        if (cleanLine.Length > 110) cleanLine = cleanLine.Substring(0, 107) + "...";

                        bool isCheatLaunch = false;
                        if (lower.Contains("doomsday.exe") || lower.Contains("doomday.exe") ||
                            lower.Contains("start doomsday") || lower.Contains("start doomday") ||
                            (lower.Contains("--doomsday") || lower.Contains("com.doomsday")) ||
                            (lower.Contains("inject") && (lower.Contains("doomsday") || lower.Contains("doomday") || lower.Contains("shellcode"))) ||
                            (lower.Contains("java") && lower.Contains("-jar") && (lower.Contains("doomsday") || lower.Contains("doomday"))))
                        {
                            isCheatLaunch = true;
                        }

                        if (isCheatLaunch)
                        {
                            log?.Invoke($"Найден след запуска Doomsday в истории PowerShell: {cleanLine}");
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
                var asciiPatterns = DoomsdayConhostSignatures.Select(s => Encoding.ASCII.GetBytes(s)).ToList();
                var uniPatterns = DoomsdayConhostSignatures.Select(s => Encoding.Unicode.GetBytes(s)).ToList();

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
                                            for (int i = 0; i < asciiPatterns.Count; i++)
                                            {
                                                string patName = DoomsdayConhostSignatures[i];
                                                if (detectedInProc.Contains(patName)) continue;

                                                if (ContainsSequence(buffer, readLen, asciiPatterns[i]) ||
                                                    ContainsSequence(buffer, readLen, uniPatterns[i]))
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
                                string fileName = Path.GetFileName(af);
                                if (int.TryParse(fileName.Replace(".attach_pid", ""), out int afPid))
                                {
                                    lock (_findingsLock)
                                    {
                                        if (_jcmdQueriedPids.Contains(afPid)) continue;
                                    }
                                }

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

                var targetPids = MinecraftProcessDetector.GetAllMinecraftPids();
                foreach (int pid in targetPids)
                {
                    try
                    {
                        var proc = Process.GetProcessById(pid);
                        foreach (ProcessModule mod in proc.Modules)
                        {
                            if (string.Equals(mod.ModuleName, "attach.dll", StringComparison.OrdinalIgnoreCase))
                            {
                                log?.Invoke($"Обнаружен инжект через Attach API: attach.dll загружен в процесс {proc.ProcessName} (PID {proc.Id})");
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

        public static int CheckInjectedClassLoaders(int? preferredPid, Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var targetPids = MinecraftProcessDetector.GetAllMinecraftPids(preferredPid);
                if (targetPids.Count == 0) return 0;

                string FindJcmd(Process proc)
                {
                    try
                    {
                        string procExe = proc.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(procExe))
                        {
                            string dir = Path.GetDirectoryName(procExe);
                            string jcmdCandidate = Path.Combine(dir, "jcmd.exe");
                            if (File.Exists(jcmdCandidate)) return jcmdCandidate;
                        }
                    }
                    catch { }

                    string jh = Environment.GetEnvironmentVariable("JAVA_HOME");
                    if (!string.IsNullOrEmpty(jh))
                    {
                        string jcmdJh = Path.Combine(jh, "bin", "jcmd.exe");
                        if (File.Exists(jcmdJh)) return jcmdJh;
                    }

                    string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                    string javaDir = Path.Combine(pf, "Java");
                    if (Directory.Exists(javaDir))
                    {
                        try
                        {
                            foreach (var jdk in Directory.GetDirectories(javaDir))
                            {
                                string jcmdPf = Path.Combine(jdk, "bin", "jcmd.exe");
                                if (File.Exists(jcmdPf)) return jcmdPf;
                            }
                        }
                        catch { }
                    }

                    return "jcmd.exe";
                }

                foreach (int pid in targetPids)
                {
                    try
                    {
                        Process proc = null;
                        try { proc = Process.GetProcessById(pid); } catch { }
                        if (proc == null || proc.HasExited) continue;

                        string jcmdPath = FindJcmd(proc);

                        var psi = new ProcessStartInfo
                        {
                            FileName = jcmdPath,
                            Arguments = $"{pid} VM.classloader_stats",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        };

                        using (var p = Process.Start(psi))
                        {
                            string output = p.StandardOutput.ReadToEnd();
                            p.WaitForExit(3500);

                            lock (_findingsLock)
                            {
                                _jcmdQueriedPids.Add(pid);
                            }
                            try
                            {
                                string attachPath = Path.Combine(Path.GetTempPath(), $".attach_pid{pid}");
                                if (File.Exists(attachPath)) File.Delete(attachPath);
                            }
                            catch { }

                            if (string.IsNullOrEmpty(output)) continue;

                            using (var reader = new StringReader(output))
                            {
                                string line;
                                while ((line = reader.ReadLine()) != null)
                                {
                                    string trimmed = line.Trim();
                                    if (string.IsNullOrEmpty(trimmed)) continue;

                                    if (trimmed.Contains("<boot class loader>") || trimmed.Contains("<bootstrap>") ||
                                        trimmed.StartsWith("0x0000000000000000") || !trimmed.StartsWith("0x") ||
                                        trimmed.StartsWith("Total") || trimmed.StartsWith("ClassLoader"))
                                    {
                                        continue;
                                    }

                                    if (trimmed.Contains("jdk.") || trimmed.Contains("java.") || trimmed.Contains("sun.") ||
                                        trimmed.Contains("com.sun.") || trimmed.Contains("net.fabricmc.") ||
                                        trimmed.Contains("cpw.mods.") || trimmed.Contains("net.minecraftforge.") ||
                                        trimmed.Contains("org.spongepowered.") || trimmed.Contains("net.minecraft.") ||
                                        trimmed.Contains("com.mojang.") || trimmed.Contains("org.bukkit.") ||
                                        trimmed.Contains("net.md_5.") || trimmed.Contains("io.papermc.") ||
                                        trimmed.Contains("org.apache.") || trimmed.Contains("org.slf4j.") ||
                                        trimmed.Contains("org.springframework.") || trimmed.Contains("net.legacylauncher.") ||
                                        trimmed.Contains("org.tlauncher.") || trimmed.Contains("kotlin.") ||
                                        trimmed.Contains("scala.") || trimmed.Contains("groovy.") ||
                                        trimmed.Contains("ch.qos.logback.") || trimmed.Contains("org.lwjgl."))
                                    {
                                        continue;
                                    }

                                    bool isSus = false;
                                    string clInfo = "";

                                    if (trimmed.IndexOf("doomsday", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        trimmed.IndexOf("z4mfltptb", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        isSus = true;
                                        clInfo = trimmed;
                                    }
                                    else
                                    {
                                        string[] cols = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                                        if (cols.Length >= 4 && int.TryParse(cols[3], out int classCount) && classCount >= 1000)
                                        {
                                            if (trimmed.Contains("/0x") || trimmed.Contains(" . ") || trimmed.Contains("  "))
                                            {
                                                isSus = true;
                                                clInfo = trimmed;
                                            }
                                        }
                                    }

                                    if (isSus)
                                    {
                                        string cleanLoader = clInfo;
                                        string[] colsParts = clInfo.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                                        if (colsParts.Length > 0)
                                        {
                                            string lastPart = colsParts[colsParts.Length - 1];
                                            int slashIdx = lastPart.IndexOf('/');
                                            string name = (slashIdx > 0) ? lastPart.Substring(0, slashIdx) : lastPart;
                                            if (!string.IsNullOrEmpty(name))
                                            {
                                                cleanLoader = name;
                                            }
                                        }

                                        log?.Invoke($"Обнаружен внедрённый ClassLoader Doomsday в процессе Java (PID {pid}): {cleanLoader}");
                                        banReasons.Add($"Инжект Doomsday в процесс PID {pid} (внедрённый ClassLoader чита: {cleanLoader})");
                                        found++;
                                        break;
                                    }
                                }
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
            }
            catch { }

            return found;
        }

        public static int CheckJnaModules(int? preferredPid, Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var targetPids = MinecraftProcessDetector.GetAllMinecraftPids(preferredPid);
                if (targetPids.Count == 0) return 0;

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

                        var suspiciousModules = new List<string>();

                        for (int i = 0; i < jnaModules.Count; i++)
                        {
                            var mod = jnaModules[i];
                            string modName = "unknown";
                            string filePath = "";

                            try { modName = mod.ModuleName ?? "jna_module"; } catch { }
                            try { filePath = mod.FileName ?? ""; } catch { }

                            if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
                            {
                                try
                                {
                                    var fi = new FileInfo(filePath);
                                    if (fi.Length > 0 && fi.Length < 25 * 1024 * 1024)
                                    {
                                        byte[] fileBytes = File.ReadAllBytes(filePath);
                                        string content = Encoding.ASCII.GetString(fileBytes).ToLowerInvariant();

                                        bool hasDoomsdaySig = content.Contains("doomsdayclient") ||
                                                              content.Contains("doomsday") ||
                                                              content.Contains("doomday") ||
                                                              content.Contains("z4mfltptb") ||
                                                              content.Contains("inject shellcode") ||
                                                              content.Contains("com/doomsday") ||
                                                              content.Contains("--doomsday");

                                        if (hasDoomsdaySig)
                                        {
                                            string sizeStr = $"{fi.Length / 1024} КБ";
                                            string timeStr = fi.CreationTime.ToString("dd.MM.yyyy HH:mm:ss");
                                            suspiciousModules.Add($"{modName} [{filePath}] ({sizeStr}, {timeStr}, сигнатура Doomsday в коде)");
                                        }
                                    }
                                }
                                catch { }
                            }
                        }

                        if (suspiciousModules.Count > 0)
                        {
                            log?.Invoke($"Обнаружен инжект Doomsday через нативный модуль в процессе PID {pid}:");
                            foreach (var md in suspiciousModules)
                            {
                                log?.Invoke($"  -> {md}");
                                banReasons.Add($"Инжект Doomsday в процесс PID {pid} ({md})");
                            }
                            found += suspiciousModules.Count;
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
                var targetPids = new HashSet<int>(MinecraftProcessDetector.GetAllMinecraftPids(preferredPid));
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
                                if (remoteAddr.StartsWith("172.67.138.") || remoteAddr.StartsWith("104.21.48.") || remoteAddr.StartsWith("165.22.196."))
                                {
                                    if (state.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase) || state.Equals("SYN_SENT", StringComparison.OrdinalIgnoreCase))
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
            }
            catch { }

            return found;
        }

        public static int CheckJvmMemory(int? preferredPid, Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var targetPids = MinecraftProcessDetector.GetAllMinecraftPids(preferredPid);
                if (targetPids.Count == 0) return 0;

                foreach (int pid in targetPids)
                {
                    IntPtr hProcess = IntPtr.Zero;
                    try
                    {
                        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                        if (hProcess == IntPtr.Zero) continue;

                        string procName = "Minecraft";
                        try { procName = Process.GetProcessById(pid).ProcessName; } catch { }
                        log?.Invoke($"Сканирование памяти процесса {procName} (PID {pid}) на сигнатуры Doomsday...");

                        var imageMappedRegions = new List<MEMORY_BASIC_INFORMATION>();
                        var privateRegions = new List<MEMORY_BASIC_INFORMATION>();

                        long maxAddress = 0x7FFFFFFF0000;
                        long currentAddress = 0;

                        while (currentAddress < maxAddress)
                        {
                            MEMORY_BASIC_INFORMATION mbi;
                            int res = VirtualQueryEx(hProcess, new IntPtr(currentAddress), out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                            if (res == 0) break;

                            long regionBytes = mbi.RegionSize.ToInt64();
                            if (regionBytes <= 0) break;

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

                            long nextAddr = mbi.BaseAddress.ToInt64() + regionBytes;
                            if (nextAddr <= currentAddress) break;
                            currentAddress = nextAddr;
                        }

                        byte[] buffer = new byte[2097152];
                        var detectedInPid = new HashSet<string>();

                        // Pass 1: MEM_IMAGE and MEM_MAPPED (Process Hacker strings mode: Private unchecked, Image & Mapped checked)
                        // Total memory ~50-150MB, executes in <200ms, complete coverage without timeout
                        foreach (var mbi in imageMappedRegions)
                        {
                            if (detectedInPid.Count >= 10) break;
                            ScanJvmRegion(hProcess, mbi, buffer, detectedInPid, pid, ref found, log, banReasons);
                        }

                        // Pass 2: MEM_PRIVATE (JVM heap / stack), with a 5 second time budget
                        if (detectedInPid.Count < 10)
                        {
                            var swPrivate = Stopwatch.StartNew();
                            foreach (var mbi in privateRegions)
                            {
                                if (detectedInPid.Count >= 10 || swPrivate.ElapsedMilliseconds > 5000) break;
                                ScanJvmRegion(hProcess, mbi, buffer, detectedInPid, pid, ref found, log, banReasons);
                            }
                        }
                    }
                    catch { }
                    finally
                    {
                        if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                    }

                    if (found > 0) break;
                }
            }
            catch { }

            return found;
        }

        private static void ScanJvmRegion(IntPtr hProcess, MEMORY_BASIC_INFORMATION mbi, byte[] buffer,
            HashSet<string> detectedInPid, int pid, ref int found, Action<string> log, List<string> banReasons)
        {
            long regionBytes = mbi.RegionSize.ToInt64();
            long bytesToRead = Math.Min(regionBytes, 33554432);
            long offset = 0;

            while (offset < bytesToRead)
            {
                if (detectedInPid.Count >= 10) break;

                int chunk = (int)Math.Min((long)buffer.Length, bytesToRead - offset);
                IntPtr readAddr = new IntPtr(mbi.BaseAddress.ToInt64() + offset);

                if (ReadProcessMemory(hProcess, readAddr, buffer, chunk, out IntPtr readCount))
                {
                    int readLen = readCount.ToInt32();
                    if (readLen > 0)
                    {
                        for (int i = 0; i < JvmMemorySignatures.Length; i++)
                        {
                            var sig = JvmMemorySignatures[i];
                            if (detectedInPid.Contains(sig.Pattern)) continue;

                            int matchIdx = -1;
                            if (sig.IsCaseSensitive)
                            {
                                matchIdx = FindSequence(buffer, readLen, sig.AsciiBytes);
                                if (matchIdx < 0)
                                    matchIdx = FindSequence(buffer, readLen, sig.UnicodeBytes);
                            }
                            else
                            {
                                matchIdx = FindSequenceIgnoreCaseAscii(buffer, readLen, sig.LowerAscii);
                                if (matchIdx < 0)
                                    matchIdx = FindSequenceIgnoreCaseUnicode(buffer, readLen, sig.LowerAscii);
                            }

                            if (matchIdx >= 0)
                            {
                                detectedInPid.Add(sig.Pattern);
                                long matchAddr = readAddr.ToInt64() + matchIdx;
                                string desc;
                                if (sig.Category == "classloader")
                                    desc = $"Инжект Doomsday: внедрённый ClassLoader в Java ({sig.Pattern} в PID {pid}, адрес 0x{matchAddr:X})";
                                else if (sig.Category == "font")
                                    desc = $"Инжект Doomsday: сетевая загрузка шрифтов в Java ({sig.Pattern} в PID {pid}, адрес 0x{matchAddr:X})";
                                else if (sig.Category == "network")
                                    desc = $"Инжект Doomsday: сетевое обращение к серверу ({sig.Pattern} в PID {pid}, адрес 0x{matchAddr:X})";
                                else if (sig.Category == "class")
                                    desc = $"Инжект Doomsday: класс чита в памяти Java ({sig.Pattern} в PID {pid}, адрес 0x{matchAddr:X})";
                                else if (sig.Category == "string")
                                    desc = $"Инжект Doomsday: строка чита в памяти Java ({sig.Pattern} в PID {pid}, адрес 0x{matchAddr:X})";
                                else
                                    desc = $"Инжект Doomsday: след чита в памяти Java ({sig.Pattern} в PID {pid}, адрес 0x{matchAddr:X})";

                                log?.Invoke(desc);
                                string phGuide = ScanSummaryFormatter.GetProcessHackerGuide(desc);
                                if (!string.IsNullOrEmpty(phGuide))
                                {
                                    log?.Invoke($"   -> [Process Hacker] {phGuide}");
                                }
                                banReasons.Add(desc);
                                found++;
                                if (detectedInPid.Count >= 10) break;
                            }
                        }
                    }
                }

                int step = Math.Max(chunk - 512, 1);
                offset += step;
            }
        }

        public static int CheckFileSystemTraces(Action<string> log, List<string> banReasons)
        {
            int found = 0;
            try
            {
                var scannedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var foundCheats = new List<string>();

                void ScanCandidateFile(string filePath)
                {
                    if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return;
                    lock (scannedFiles)
                    {
                        if (!scannedFiles.Add(filePath)) return;
                    }

                    try
                    {
                        var fi = new FileInfo(filePath);
                        long len = fi.Length;
                        if (len < 20000 || len > 15 * 1024 * 1024) return;

                        if (CheckFile(fi, out string reason))
                        {
                            string desc = $"Найден чит Doomsday: {fi.Name} ({reason}) [{fi.FullName}]";
                            lock (foundCheats)
                            {
                                foundCheats.Add(desc);
                            }
                            log?.Invoke(desc);
                            banReasons.Add($"Найден чит Doomsday - {fi.FullName} ({reason})");
                        }
                    }
                    catch { }
                }

                string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var userSearchDirs = new List<string>
                {
                    Path.Combine(userProfile, "Downloads"),
                    Path.Combine(userProfile, "Загрузки"),
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    Path.Combine(userProfile, "Рабочий стол"),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Path.Combine(userProfile, "Документы"),
                    Path.Combine(userProfile, "Pictures"),
                    Path.Combine(userProfile, "Изображения"),
                    Path.Combine(userProfile, "Рисунки"),
                    Path.Combine(userProfile, "Videos"),
                    Path.Combine(userProfile, "Видео"),
                    Path.Combine(userProfile, "Music"),
                    Path.Combine(userProfile, "Музыка"),
                    Path.Combine(userProfile, "Saved Games"),
                    Path.Combine(userProfile, "Сохраненные игры"),
                    Path.Combine(userProfile, "Favorites"),
                    Path.Combine(userProfile, "Links"),
                    Path.Combine(userProfile, "Contacts"),
                    Path.Combine(userProfile, "Searches"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".minecraft"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".tlauncher"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".lunarclient"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".feather"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrismLauncher"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ModrinthApp"),
                    Path.GetTempPath(),
                    @"C:\Temp"
                };

                try
                {
                    if (Directory.Exists(userProfile))
                    {
                        foreach (var d in Directory.GetDirectories(userProfile))
                        {
                            string dn = Path.GetFileName(d);
                            if (!dn.Equals("AppData", StringComparison.OrdinalIgnoreCase) &&
                                !dn.StartsWith(".") && !dn.StartsWith("$"))
                            {
                                userSearchDirs.Add(d);
                            }
                        }

                        foreach (var f in Directory.GetFiles(userProfile))
                        {
                            ScanCandidateFile(f);
                        }
                    }
                }
                catch { }

                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable))
                    {
                        string r = drive.RootDirectory.FullName;
                        string t = Path.Combine(r, "Temp");
                        if (Directory.Exists(t)) userSearchDirs.Add(t);
                        string g = Path.Combine(r, "Games");
                        if (Directory.Exists(g)) userSearchDirs.Add(g);
                        string mc = Path.Combine(r, "Minecraft");
                        if (Directory.Exists(mc)) userSearchDirs.Add(mc);
                    }
                }

                var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".jar", ".zip", ".dll", ".disabled", ".bak", ".dat", ".bin" };

                void ScanDirectoryRecursive(string dirPath, int maxDepth, int currentDepth = 0)
                {
                    if (currentDepth > maxDepth || !Directory.Exists(dirPath)) return;

                    string dirName = Path.GetFileName(dirPath);
                    if (dirName.Equals("Windows", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Program Files", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Program Files (x86)", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Packages", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("Package", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals("node_modules", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals(".git", StringComparison.OrdinalIgnoreCase) ||
                        dirName.StartsWith("$"))
                    {
                        return;
                    }

                    try
                    {
                        foreach (var f in Directory.GetFiles(dirPath))
                        {
                            try
                            {
                                string ext = Path.GetExtension(f);
                                if (exts.Contains(ext) || f.IndexOf("doomsday", StringComparison.OrdinalIgnoreCase) >= 0 || f.IndexOf("z4mfltptb", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    ScanCandidateFile(f);
                                }
                                else
                                {
                                    var fi = new FileInfo(f);
                                    if (fi.Length >= 1024 * 1024 && fi.Length <= 10 * 1024 * 1024)
                                    {
                                        ScanCandidateFile(f);
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }

                    if (currentDepth < maxDepth)
                    {
                        try
                        {
                            foreach (var subDir in Directory.GetDirectories(dirPath))
                            {
                                ScanDirectoryRecursive(subDir, maxDepth, currentDepth + 1);
                            }
                        }
                        catch { }
                    }
                }

                var parallelTasks = new List<Task>();
                foreach (var dir in userSearchDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    if (Directory.Exists(dir))
                    {
                        parallelTasks.Add(Task.Run(() => ScanDirectoryRecursive(dir, 4, 0)));
                    }
                }

                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable))
                    {
                        string r = drive.RootDirectory.FullName;
                        parallelTasks.Add(Task.Run(() =>
                        {
                            try
                            {
                                foreach (var f in Directory.GetFiles(r))
                                {
                                    string ext = Path.GetExtension(f);
                                    if (exts.Contains(ext))
                                    {
                                        ScanCandidateFile(f);
                                    }
                                    else
                                    {
                                        var fi = new FileInfo(f);
                                        if (fi.Length >= 1024 * 1024 && fi.Length <= 10 * 1024 * 1024)
                                        {
                                            ScanCandidateFile(f);
                                        }
                                    }
                                }
                            }
                            catch { }

                            try
                            {
                                foreach (var d in Directory.GetDirectories(r))
                                {
                                    string dn = Path.GetFileName(d);
                                    if (dn.Equals("Windows", StringComparison.OrdinalIgnoreCase) ||
                                        dn.Equals("Program Files", StringComparison.OrdinalIgnoreCase) ||
                                        dn.Equals("Program Files (x86)", StringComparison.OrdinalIgnoreCase) ||
                                        dn.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
                                        dn.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase) ||
                                        dn.StartsWith("$"))
                                    {
                                        continue;
                                    }
                                    ScanDirectoryRecursive(d, 3, 0);
                                }
                            }
                            catch { }
                        }));
                    }
                }

                Task.WaitAll(parallelTasks.ToArray(), 15000);
                found = foundCheats.Count;
            }
            catch { }

            return found;
        }

        private static readonly object _findingsLock = new object();
        private static readonly List<string> _lastDetailedFindings = new List<string>();
        private static readonly HashSet<int> _jcmdQueriedPids = new HashSet<int>();

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

                    bool matchesHeading = line.Contains("Инжект думика обнаружен") || line.Contains("Следы Doomsday обнаружены");

                    if (!bodyDetailsInserted && !inSummary && matchesHeading && !originalLog.Contains("           -> Найден след:"))
                    {
                        sb.AppendLine(line);
                        bodyDetailsInserted = true;
                        foreach (var det in details)
                        {
                            sb.AppendLine($"           -> Найден след: {det}");
                            string phGuide = ScanSummaryFormatter.GetProcessHackerGuide(det);
                            if (!string.IsNullOrEmpty(phGuide))
                            {
                                sb.AppendLine($"              [Process Hacker]: {phGuide}");
                            }
                        }
                        continue;
                    }

                    if (inSummary && matchesHeading)
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
            log?.Invoke("Поиск инжектов думика");

            lock (_findingsLock)
            {
                _jcmdQueriedPids.Clear();
            }

            int totalFound = 0;
            var internalReasons = new List<string>();

            await Task.Run(() =>
            {
                totalFound += CheckActiveProcesses(null, internalReasons);
                totalFound += CheckInjectedClassLoaders(targetPid, null, internalReasons);
                totalFound += CheckJnaModules(targetPid, null, internalReasons);
                totalFound += CheckLoopbackPorts(targetPid, null, internalReasons);
                totalFound += CheckJvmAttach(null, internalReasons);
                totalFound += CheckJvmMemory(targetPid, null, internalReasons);
                totalFound += CheckConhostMemory(null, internalReasons);
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
                var distinctReasons = internalReasons.Distinct().ToList();
                lock (_findingsLock)
                {
                    _lastDetailedFindings.Clear();
                    _lastDetailedFindings.AddRange(distinctReasons);
                }
                log?.Invoke("Инжект думика обнаружен");
                foreach (var reason in distinctReasons)
                {
                    log?.Invoke($"           -> Найден след: {reason}");
                    string phGuide = ScanSummaryFormatter.GetProcessHackerGuide(reason);
                    if (!string.IsNullOrEmpty(phGuide))
                    {
                        log?.Invoke($"              [Process Hacker]: {phGuide}");
                    }
                }
                foreach (var reason in distinctReasons)
                {
                    banReasons.Add(reason);
                }
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

        private static int FindSequence(byte[] buffer, int length, byte[] pattern)
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

        private static int FindSequenceIgnoreCaseAscii(byte[] buffer, int length, byte[] lowerPattern)
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

        private static int FindSequenceIgnoreCaseUnicode(byte[] buffer, int length, byte[] lowerPattern)
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

        private static bool ContainsSequence(byte[] buffer, int length, byte[] pattern)
        {
            return FindSequence(buffer, length, pattern) >= 0;
        }
    }
}
