using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using AngelMineChecker.Services;

namespace AngelMineChecker
{
    public static class CheckSystemDLC
    {
        public static readonly string[] Signatures = new[]
        {
            DecodeSig("NjdjZnVlZ3UwcDhybQ=="),
            DecodeSig("QVJST1dfUklHSFRaT05UQUw="),
            DecodeSig("RFJPUERPV05fU1VDQ0VTUw=="),
            DecodeSig("dG9vbHRpcF9hcnJvd191cA=="),
            DecodeSig("TjFZMEc2emZ6MEVTSm9DSQ=="),
            DecodeSig("YXJTQnFCUWZiVW5GUFRHZQ=="),
            DecodeSig("dX1weG10aG9iaV1kWF5SWExSRkxARjo/MzgsMSYq")
        };

        public static readonly string[] PythonInjectionSignatures = new[]
        {
            "msc.systemdlc.com",
            "systemdlc.com",
            "/instruction.txt",
            "Control your system",
            "Loader Panel",
            "7d07ec9c9054e7",
            "1>Jeh{W~;G7ZSI@>OXtX",
            "vars(__import__(('builtin','s')",
            "('d','ecompress')",
            "('operato'+'r')",
            "chr(101)+chr(120)+chr(101)+chr(99)",
            "chr(97)+chr(116)+chr(116)+chr(114)+chr(103)+chr(101)+chr(116)+chr(116)+chr(101)+chr(114)",
            "chr(122)+chr(108)+chr(105)+chr(98)",
            "chr(98)+chr(56)+chr(53)+chr(100)+chr(101)+chr(99)+chr(111)+chr(100)+chr(101)"
        };

        public static readonly string[] KnownSystemDlcIps = new[]
        {
            "31.77.78.109",
            "172.67.178.",
            "104.21.18."
        };

        private static string DecodeSig(string b64)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        }

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

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint PAGE_NOACCESS = 0x01;
        private const uint PAGE_GUARD = 0x100;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint CF_UNICODETEXT = 13;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseClipboard();

        [DllImport("user32.dll")]
        private static extern IntPtr GetClipboardData(uint uFormat);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GlobalLock(IntPtr hMem);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalUnlock(IntPtr hMem);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);

        private static readonly HashSet<string> ScriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".txt", ".py", ".pyw", ".bat", ".cmd", ".ps1", ".vbs", ".log", ".tmp", ".cfg", ".ini", ".json"
        };

        public static bool CheckInFile(FileInfo file, out string foundSig)
        {
            foundSig = "";
            if (file == null || !file.Exists) return false;
            if (QuickScanner.IsCheckerOrSelf(file.FullName)) return false;

            string nameLower = file.Name.ToLowerInvariant();
            string ext = file.Extension.ToLowerInvariant();
            if (nameLower.StartsWith("+~jf") || ext == ".ttf" || ext == ".otf" || ext == ".woff" || ext == ".woff2")
                return false;

            if (!ScriptExtensions.Contains(ext) && !nameLower.Contains("dlc") && !nameLower.Contains("system") && !nameLower.Contains("jlivef"))
                return false;

            try
            {
                long len = file.Length;
                if (len == 0 || len > 10 * 1024 * 1024) return false;

                using (var fs = file.OpenRead())
                {
                    byte[] buf = new byte[Math.Min((int)len, 512 * 1024)];
                    int read = fs.Read(buf, 0, buf.Length);
                    if (read <= 0) return false;

                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (var sig in Signatures)
                    {
                        if (content.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            foundSig = sig;
                            return true;
                        }
                    }

                    foreach (var sig in PythonInjectionSignatures)
                    {
                        if (content.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            foundSig = sig;
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        public static void Scan(Action<string> log, List<string> banReasons, int? targetMinecraftPid = null)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var extraPids = new HashSet<int>();

            CheckActiveWindows(log, banReasons, seen, extraPids);

            CheckClipboard(log, banReasons, seen);

            CheckGraphicsPipelineHooks(targetMinecraftPid, log, banReasons, seen);

            ScanProcessesMemory(targetMinecraftPid, extraPids, log, banReasons, seen);

            CheckNetworkConnections(log, banReasons, seen, extraPids);

            CheckDnsCache(log, banReasons, seen);

            ScanFilesAndHistory(log, banReasons, seen);

            CheckPrefetch(log, banReasons, seen);
        }

        private static void CheckActiveWindows(Action<string> log, List<string> banReasons, HashSet<string> seen, HashSet<int> extraPids)
        {
            try
            {
                EnumWindows((hWnd, lParam) =>
                {
                    try
                    {
                        if (IsWindowVisible(hWnd))
                        {
                            var sb = new StringBuilder(512);
                            int len = GetWindowText(hWnd, sb, sb.Capacity);
                            if (len > 0)
                            {
                                string title = sb.ToString().Trim();
                                string titleLower = title.ToLowerInvariant();

                                if (titleLower == "loader panel" || titleLower.Contains("loader panel") ||
                                    titleLower.Contains("control your system") ||
                                    titleLower.Contains("system dlc") || titleLower.Contains("systemdlc"))
                                {
                                    GetWindowThreadProcessId(hWnd, out uint pid);
                                    if (pid > 0) extraPids?.Add((int)pid);

                                    string procName = "Неизвестно";
                                    try { procName = Process.GetProcessById((int)pid).ProcessName; } catch { }

                                    string key = $"win_{pid}_{title}";
                                    if (seen.Add(key))
                                    {
                                        log?.Invoke($"Обнаружено активное окно лоадера SystemDLC: \"{title}\" (процесс {procName}.exe, PID {pid})");
                                        banReasons.Add($"Найден активный лоадер SystemDLC (окно \"{title}\" в процессе {procName}.exe PID {pid})");
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                    return true;
                }, IntPtr.Zero);
            }
            catch { }
        }

        private static void CheckClipboard(Action<string> log, List<string> banReasons, HashSet<string> seen)
        {
            try
            {
                string text = GetClipboardTextSafe();
                if (!string.IsNullOrEmpty(text))
                {
                    foreach (var sig in PythonInjectionSignatures)
                    {
                        if (text.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            if (seen.Add("clip_sysdlc"))
                            {
                                log?.Invoke($"Обнаружена команда инжектора SystemDLC в буфере обмена (сигнатура: {sig})");
                                banReasons.Add($"Команда инжектора SystemDLC в буфере обмена (сигнатура: {sig})");
                            }
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        private static string GetClipboardTextSafe()
        {
            try
            {
                if (!OpenClipboard(IntPtr.Zero)) return null;
                try
                {
                    IntPtr handle = GetClipboardData(CF_UNICODETEXT);
                    if (handle == IntPtr.Zero) return null;
                    IntPtr pointer = GlobalLock(handle);
                    if (pointer == IntPtr.Zero) return null;
                    try
                    {
                        return Marshal.PtrToStringUni(pointer);
                    }
                    finally
                    {
                        GlobalUnlock(handle);
                    }
                }
                finally
                {
                    CloseClipboard();
                }
            }
            catch { return null; }
        }

        private static void CheckGraphicsPipelineHooks(int? targetMinecraftPid, Action<string> log, List<string> banReasons, HashSet<string> seen)
        {
            var pids = MinecraftProcessDetector.GetAllMinecraftPids(targetMinecraftPid);
            if (pids.Count == 0) return;

            IntPtr hOpengl = GetModuleHandle("opengl32.dll");
            if (hOpengl == IntPtr.Zero) hOpengl = LoadLibrary("opengl32.dll");
            if (hOpengl == IntPtr.Zero) return;

            IntPtr pSwapBuffers = GetProcAddress(hOpengl, "wglSwapBuffers");
            if (pSwapBuffers == IntPtr.Zero) return;

            foreach (int pid in pids)
            {
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                    if (hProcess == IntPtr.Zero) continue;

                    byte[] buf = new byte[16];
                    if (ReadProcessMemory(hProcess, pSwapBuffers, buf, 16, out IntPtr bytesRead) && bytesRead.ToInt32() >= 5)
                    {
                        bool isHooked = false;
                        long targetAddr = 0;

                        if (buf[0] == 0xE9)
                        {
                            int rel = BitConverter.ToInt32(buf, 1);
                            targetAddr = pSwapBuffers.ToInt64() + 5 + rel;
                            isHooked = true;
                        }
                        else if (buf[0] == 0x48 && buf[1] == 0xB8 && bytesRead.ToInt32() >= 12 && buf[10] == 0xFF && buf[11] == 0xE0)
                        {
                            targetAddr = BitConverter.ToInt64(buf, 2);
                            isHooked = true;
                        }
                        else if (buf[0] == 0xFF && buf[1] == 0x25 && bytesRead.ToInt32() >= 6)
                        {
                            int ripOffset = BitConverter.ToInt32(buf, 2);
                            IntPtr ptrAddr = new IntPtr(pSwapBuffers.ToInt64() + 6 + ripOffset);
                            byte[] deref = new byte[8];
                            if (ReadProcessMemory(hProcess, ptrAddr, deref, 8, out IntPtr dRead) && dRead.ToInt32() == 8)
                            {
                                targetAddr = BitConverter.ToInt64(deref, 0);
                                isHooked = true;
                            }
                        }

                        if (isHooked && targetAddr != 0)
                        {
                            MEMORY_BASIC_INFORMATION mbi;
                            if (VirtualQueryEx(hProcess, new IntPtr(targetAddr), out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
                            {
                                if (mbi.Type == MEM_PRIVATE || (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == 0x20))
                                {
                                    string key = $"hook_wgl_{pid}_{targetAddr:X}";
                                    if (seen.Add(key))
                                    {
                                        log?.Invoke($"Обнаружен перехват графического конвейера игры (хук wglSwapBuffers -> 0x{targetAddr:X} в немодульной памяти)");
                                        banReasons.Add($"Внедрен графический оверлей чита (хук wglSwapBuffers в PID {pid}, адрес 0x{targetAddr:X})");
                                    }
                                }
                            }
                        }
                    }
                }
                catch { }
                finally
                {
                    if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                }
            }
        }

        private static void ScanProcessesMemory(int? targetMinecraftPid, HashSet<int> extraPids, Action<string> log, List<string> banReasons, HashSet<string> seen)
        {
            var targetPids = new HashSet<int>();

            if (targetMinecraftPid.HasValue && targetMinecraftPid.Value > 0)
            {
                targetPids.Add(targetMinecraftPid.Value);
            }

            foreach (var pid in MinecraftProcessDetector.GetAllMinecraftPids(targetMinecraftPid))
            {
                targetPids.Add(pid);
            }

            if (extraPids != null)
            {
                foreach (var ep in extraPids)
                {
                    if (ep > 0) targetPids.Add(ep);
                }
            }

            string[] hostNames = new[] { "python", "pythonw", "telegram", "discord" };
            foreach (var hName in hostNames)
            {
                try
                {
                    foreach (var p in Process.GetProcessesByName(hName))
                    {
                        try
                        {
                            if (!p.HasExited) targetPids.Add(p.Id);
                        }
                        catch { }
                    }
                }
                catch { }
            }

            var allSignatures = Signatures.Concat(PythonInjectionSignatures).Distinct().ToList();

            foreach (int pid in targetPids)
            {
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    Process proc;
                    try { proc = Process.GetProcessById(pid); } catch { continue; }
                    if (proc.HasExited) continue;

                    string procName = proc.ProcessName.ToLowerInvariant();

                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                    if (hProcess == IntPtr.Zero) continue;

                    long maxAddress = 0x7FFFFFFF0000;
                    long currentAddress = 0;
                    byte[] buffer = new byte[1024 * 1024];

                    bool foundInProcess = false;
                    var sw = Stopwatch.StartNew();

                    while (currentAddress < maxAddress && !foundInProcess)
                    {
                        if (sw.ElapsedMilliseconds > 3000) break;

                        MEMORY_BASIC_INFORMATION mbi;
                        int res = VirtualQueryEx(hProcess, new IntPtr(currentAddress), out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                        if (res == 0) break;

                        long regionBytes = mbi.RegionSize.ToInt64();
                        if (regionBytes <= 0) break;

                        if (mbi.State == MEM_COMMIT && IsReadablePage(mbi.Protect))
                        {
                            if ((procName.Contains("python") || procName.Contains("telegram") || procName.Contains("discord")) &&
                                mbi.Type == MEM_PRIVATE && (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == 0x20) &&
                                regionBytes >= 256 * 1024)
                            {
                                string unbackedKey = $"unbacked_rwx_{pid}_{currentAddress:X}";
                                if (seen.Add(unbackedKey))
                                {
                                    log?.Invoke($"Обнаружен подозрительный RWX регион инжекта в процессе {proc.ProcessName} (PID {pid}, адрес 0x{currentAddress:X}, размер {regionBytes / 1024} КБ)");
                                    if (procName.Contains("python"))
                                    {
                                        banReasons.Add($"Обнаружен исполняемый шеллкод инжектора в памяти {proc.ProcessName}.exe (PID {pid}, немодульный RWX регион {regionBytes / 1024} КБ)");
                                    }
                                }
                            }

                            if (mbi.Type == MEM_PRIVATE && (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == 0x20 || mbi.Protect == 0x04) && regionBytes >= 64 * 1024)
                            {
                                byte[] peHdr = new byte[512];
                                if (ReadProcessMemory(hProcess, new IntPtr(currentAddress), peHdr, 512, out IntPtr peRead) && peRead.ToInt32() >= 256)
                                {
                                    if (peHdr[0] == 0x4D && peHdr[1] == 0x5A)
                                    {
                                        int e_lfanew = BitConverter.ToInt32(peHdr, 0x3C);
                                        if (e_lfanew >= 0x40 && e_lfanew <= 0x300 && e_lfanew + 4 <= peHdr.Length)
                                        {
                                            if (peHdr[e_lfanew] == 0x50 && peHdr[e_lfanew + 1] == 0x45 &&
                                                peHdr[e_lfanew + 2] == 0 && peHdr[e_lfanew + 3] == 0)
                                            {
                                                string peKey = $"mmap_{pid}_{currentAddress:X}";
                                                if (seen.Add(peKey))
                                                {
                                                    log?.Invoke($"Обнаружена скрыто внедренная библиотека (Manual Map PE в {proc.ProcessName}.exe PID {pid}, адрес 0x{currentAddress:X})");
                                                    if (procName.Contains("python"))
                                                    {
                                                        banReasons.Add($"Внедрен лоадер чита в память {proc.ProcessName}.exe (Manual Map PE в PID {pid})");
                                                    }
                                                    else if (procName.Contains("telegram") || procName.Contains("discord"))
                                                    {
                                                        banReasons.Add($"Инжект чита в {proc.ProcessName}.exe (Manual Map PE в PID {pid})");
                                                    }
                                                    else
                                                    {
                                                        banReasons.Add($"Скрытый инжект библиотеки чита в процесс игры (Manual Map PE в PID {pid})");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            long bytesToRead = Math.Min(regionBytes, 4 * 1024 * 1024);
                            long offset = 0;
                            while (offset < bytesToRead && !foundInProcess)
                            {
                                if (sw.ElapsedMilliseconds > 3000) break;

                                int toRead = (int)Math.Min((long)buffer.Length, bytesToRead - offset);
                                IntPtr readAddr = new IntPtr(currentAddress + offset);

                                if (ReadProcessMemory(hProcess, readAddr, buffer, toRead, out IntPtr bytesRead) && bytesRead.ToInt32() > 0)
                                {
                                    int readCount = bytesRead.ToInt32();

                                    foreach (var sig in allSignatures)
                                    {
                                        if (ContainsString(buffer, readCount, sig))
                                        {
                                            string key = $"mem_{pid}_{sig}";
                                            if (seen.Add(key))
                                            {
                                                long foundAddr = currentAddress + offset;
                                                log?.Invoke($"Обнаружена сигнатура SystemDLC в памяти процесса {proc.ProcessName} PID {pid} (адрес 0x{foundAddr:X}): {sig}");

                                                if (procName.Contains("python"))
                                                {
                                                    banReasons.Add($"Инжект SystemDLC через Python IDLE (PID {pid}, сигнатура: {sig})");
                                                }
                                                else if (procName.Contains("telegram") || procName.Contains("discord"))
                                                {
                                                    banReasons.Add($"Инжект лоадера SystemDLC в {proc.ProcessName}.exe (PID {pid}, сигнатура: {sig})");
                                                }
                                                else
                                                {
                                                    banReasons.Add($"Найден инжект SystemDLC в памяти процесса Minecraft PID {pid} (сигнатура: {sig})");
                                                }
                                                foundInProcess = true;
                                                break;
                                            }
                                        }
                                    }
                                }

                                offset += toRead;
                            }
                        }

                        currentAddress += regionBytes;
                    }
                }
                catch { }
                finally
                {
                    if (hProcess != IntPtr.Zero)
                    {
                        CloseHandle(hProcess);
                    }
                }
            }
        }

        private static bool IsReadablePage(uint protect)
        {
            if ((protect & PAGE_NOACCESS) != 0 || (protect & PAGE_GUARD) != 0)
                return false;
            return (protect & 0x02) != 0 ||
                   (protect & 0x04) != 0 ||
                   (protect & 0x20) != 0 ||
                   (protect & 0x40) != 0;
        }

        private static bool ContainsString(byte[] buffer, int length, string search)
        {
            if (buffer == null || length <= 0 || string.IsNullOrEmpty(search)) return false;

            byte[] ascii = Encoding.ASCII.GetBytes(search);
            if (IndexOfAsciiIgnoreCase(buffer, length, ascii) >= 0) return true;

            if (IndexOfUnicodeIgnoreCase(buffer, length, search) >= 0) return true;

            return false;
        }

        private static int IndexOfAsciiIgnoreCase(byte[] source, int sourceLen, byte[] pattern)
        {
            if (pattern.Length == 0 || sourceLen < pattern.Length) return -1;
            byte first = pattern[0];
            byte firstLower = (first >= (byte)'A' && first <= (byte)'Z') ? (byte)(first + 32) : first;
            byte firstUpper = (first >= (byte)'a' && first <= (byte)'z') ? (byte)(first - 32) : first;

            for (int i = 0; i <= sourceLen - pattern.Length; i++)
            {
                byte b = source[i];
                if (b != firstLower && b != firstUpper) continue;

                bool match = true;
                for (int j = 1; j < pattern.Length; j++)
                {
                    byte s = source[i + j];
                    byte p = pattern[j];
                    if (s != p)
                    {
                        byte sLow = (s >= (byte)'A' && s <= (byte)'Z') ? (byte)(s + 32) : s;
                        byte pLow = (p >= (byte)'A' && p <= (byte)'Z') ? (byte)(p + 32) : p;
                        if (sLow != pLow)
                        {
                            match = false;
                            break;
                        }
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        private static int IndexOfUnicodeIgnoreCase(byte[] source, int sourceLen, string pattern)
        {
            if (string.IsNullOrEmpty(pattern)) return -1;
            int patByteLen = pattern.Length * 2;
            if (sourceLen < patByteLen) return -1;

            string patLower = pattern.ToLowerInvariant();
            char firstChar = patLower[0];

            for (int i = 0; i <= sourceLen - patByteLen; i += 2)
            {
                char c = (char)(source[i] | (source[i + 1] << 8));
                if (char.ToLowerInvariant(c) != firstChar) continue;

                bool match = true;
                for (int j = 1; j < patLower.Length; j++)
                {
                    char sc = (char)(source[i + j * 2] | (source[i + j * 2 + 1] << 8));
                    if (char.ToLowerInvariant(sc) != patLower[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        private static void CheckDnsCache(Action<string> log, List<string> banReasons, HashSet<string> seen)
        {
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

                    if (output.IndexOf("systemdlc.com", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        output.IndexOf("msc.systemdlc.com", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        if (seen.Add("dns_systemdlc"))
                        {
                            log?.Invoke("Обнаружен след обращения к серверу SystemDLC в DNS кэше (msc.systemdlc.com / systemdlc.com)");
                            banReasons.Add("След запуска инжектора SystemDLC в DNS кэше (msc.systemdlc.com / systemdlc.com)");
                        }
                    }
                }
            }
            catch { }
        }

        private static readonly HashSet<string> CommonWebApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "opera", "brave", "yandex", "vivaldi", "tor",
            "spotify", "steam", "epicgameslauncher", "medal"
        };

        private static void CheckNetworkConnections(Action<string> log, List<string> banReasons, HashSet<string> seen, HashSet<int> extraPids = null)
        {
            try
            {
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

                            string remoteAddr = parts[2];
                            string state = parts[3];
                            string pidStr = parts[4];

                            foreach (var ipPrefix in KnownSystemDlcIps)
                            {
                                if (remoteAddr.StartsWith(ipPrefix, StringComparison.OrdinalIgnoreCase))
                                {
                                    string procName = "unknown";
                                    int npid = 0;
                                    if (int.TryParse(pidStr, out npid) && npid > 0)
                                    {
                                        try { procName = Process.GetProcessById(npid).ProcessName.ToLowerInvariant(); } catch { }
                                    }

                                    bool isCloudflare = remoteAddr.StartsWith("172.67.178.", StringComparison.OrdinalIgnoreCase) ||
                                                        remoteAddr.StartsWith("104.21.18.", StringComparison.OrdinalIgnoreCase);

                                    bool isDedicatedCheatHost = remoteAddr.StartsWith("31.77.78.109", StringComparison.OrdinalIgnoreCase);

                                    if (isCloudflare && CommonWebApps.Contains(procName))
                                    {
                                        continue;
                                    }

                                    if (npid > 0)
                                    {
                                        extraPids?.Add(npid);
                                    }

                                    string key = $"net_{remoteAddr}_{pidStr}";
                                    if (seen.Add(key))
                                    {
                                        if (isDedicatedCheatHost)
                                        {
                                            log?.Invoke($"Обнаружено прямое подключение к серверу SystemDLC: {remoteAddr} (процесс {procName}.exe PID {pidStr}, {state})");
                                            banReasons.Add($"Сетевое подключение к серверу SystemDLC ({remoteAddr} в {procName}.exe PID {pidStr})");
                                        }
                                        else if (procName.Contains("python") || procName.Contains("javaw") || procName.Contains("pulse"))
                                        {
                                            log?.Invoke($"Обнаружено сетевое подключение чита: {remoteAddr} (процесс {procName}.exe PID {pidStr}, {state})");
                                            banReasons.Add($"Инжектор SystemDLC держит сетевое подключение ({remoteAddr} в {procName}.exe PID {pidStr})");
                                        }
                                        else
                                        {
                                            log?.Invoke($"Сетевая активность на адресах SystemDLC: {remoteAddr} ({procName}.exe, PID {pidStr})");
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private static void ScanFilesAndHistory(Action<string> log, List<string> banReasons, HashSet<string> seen)
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            try
            {
                string pyHistory = Path.Combine(userProfile, ".python_history");
                if (File.Exists(pyHistory))
                {
                    var fi = new FileInfo(pyHistory);
                    if (fi.Length > 0 && fi.Length <= 10 * 1024 * 1024)
                    {
                        string historyContent = File.ReadAllText(pyHistory, Encoding.UTF8);
                        foreach (var sig in PythonInjectionSignatures)
                        {
                            if (historyContent.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                if (seen.Add("py_history_sysdlc"))
                                {
                                    log?.Invoke($"Обнаружена команда запуска SystemDLC в истории Python (.python_history, сигнатура: {sig})");
                                    banReasons.Add($"Команда инжектора SystemDLC в .python_history (сигнатура: {sig})");
                                }
                                break;
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                string idlercRecent = Path.Combine(userProfile, ".idlerc", "recent-files.lst");
                if (File.Exists(idlercRecent))
                {
                    string idlercContent = File.ReadAllText(idlercRecent, Encoding.UTF8);
                    if (idlercContent.IndexOf("system", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        idlercContent.IndexOf("dlc", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        if (seen.Add("idlerc_recent"))
                        {
                            log?.Invoke($"Обнаружен запуск подозрительного файла в истории Python IDLE (.idlerc/recent-files.lst)");
                            banReasons.Add("Подозрительный запуск скрипта в истории Python IDLE");
                        }
                    }
                }
            }
            catch { }

            string[] probeDirs = new[]
            {
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Documents"),
                Path.Combine(userProfile, ".idlerc"),
                Path.GetTempPath()
            };

            foreach (var dir in probeDirs)
            {
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var sub in Directory.GetDirectories(dir))
                    {
                        if (QuickScanner.IsCheckerOrSelf(sub)) continue;
                        string subName = Path.GetFileName(sub).ToLowerInvariant();
                        if (subName.Contains("jlivef") || subName.Contains("systemdlc"))
                        {
                            if (seen.Add(sub))
                            {
                                log?.Invoke($"Найден: Папка {Path.GetFileName(sub)} ({sub})");
                                banReasons.Add($"Найдена папка чита - {Path.GetFileName(sub)} ({sub})");
                            }
                        }
                    }
                }
                catch { }

                try
                {
                    foreach (var f in Directory.GetFiles(dir))
                    {
                        if (QuickScanner.IsCheckerOrSelf(f)) continue;
                        string fName = Path.GetFileName(f).ToLowerInvariant();

                        if (fName.Contains("jlivef") || fName.Contains("systemdlc") || fName.Contains("psexec"))
                        {
                            if (seen.Add(f))
                            {
                                log?.Invoke($"Найден: Файл {Path.GetFileName(f)} ({f})");
                                banReasons.Add($"Найден файл чита - {Path.GetFileName(f)} ({f})");
                            }
                        }

                        try
                        {
                            var fi = new FileInfo(f);
                            if (fi.Length > 0 && fi.Length <= 35 * 1024 * 1024)
                            {
                                if (CheckInFile(fi, out string foundSig))
                                {
                                    if (seen.Add(f))
                                    {
                                        log?.Invoke($"Найден след SystemDLC в файле: {Path.GetFileName(f)} (сигнатура {foundSig})");
                                        banReasons.Add($"Найден файл/скрипт SystemDLC - {Path.GetFileName(f)} (сигнатура: {foundSig})");
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        private static void CheckPrefetch(Action<string> log, List<string> banReasons, HashSet<string> seen)
        {
            try
            {
                string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                if (Directory.Exists(prefetchDir))
                {
                    foreach (var pf in Directory.GetFiles(prefetchDir, "*.pf"))
                    {
                        string pfName = Path.GetFileName(pf).ToLowerInvariant();
                        if (pfName.Contains("jlivef") || pfName.Contains("systemdlc") || pfName.Contains("psexec"))
                        {
                            var fi = new FileInfo(pf);
                            if (seen.Add(fi.Name))
                            {
                                log?.Invoke($"Найден запуск в Prefetch: {fi.Name} (время: {fi.LastWriteTime:dd.MM.yyyy HH:mm:ss})");
                                banReasons.Add($"Найден запуск чита в Prefetch - {fi.Name}");
                            }
                        }
                        else if (pfName.StartsWith("idle.exe") || pfName.StartsWith("python.exe") || pfName.StartsWith("pythonw.exe"))
                        {
                            var fi = new FileInfo(pf);
                            if ((DateTime.Now - fi.LastWriteTime).TotalHours <= 6)
                            {
                                if (seen.Add(fi.Name))
                                {
                                    log?.Invoke($"Зафиксирован недавний запуск Python / IDLE в Prefetch: {fi.Name} (время: {fi.LastWriteTime:dd.MM.yyyy HH:mm:ss})");
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }
    }
}
