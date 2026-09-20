using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace AngelMineChecker.Services
{
    public class MinecraftProcessInfo
    {
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public string WindowTitle { get; set; }
        public long MemoryMb { get; set; }
        public string ExecutablePath { get; set; }
        public int Score { get; set; }
        public bool IsGame { get; set; }
        public string DisplayText { get; set; }
    }

    public static class MinecraftProcessDetector
    {
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        public static Dictionary<int, List<string>> GetAllProcessWindows()
        {
            var map = new Dictionary<int, List<string>>();

            try
            {
                EnumWindows((hWnd, lParam) =>
                {
                    try
                    {
                        if (IsWindowVisible(hWnd))
                        {
                            int len = GetWindowTextLength(hWnd);
                            if (len > 0)
                            {
                                var sb = new StringBuilder(len + 2);
                                GetWindowText(hWnd, sb, sb.Capacity);
                                string text = sb.ToString().Trim();
                                if (!string.IsNullOrEmpty(text))
                                {
                                    GetWindowThreadProcessId(hWnd, out uint pid);
                                    int p = (int)pid;
                                    if (!map.ContainsKey(p))
                                    {
                                        map[p] = new List<string>();
                                    }
                                    map[p].Add(text);
                                }
                            }
                        }
                    }
                    catch { }
                    return true;
                }, IntPtr.Zero);
            }
            catch { }

            return map;
        }

        public static List<MinecraftProcessInfo> FindCandidates()
        {
            var list = new List<MinecraftProcessInfo>();

            var windowMap = GetAllProcessWindows();

            var wmiCmdMap = new Dictionary<int, string>();
            var wmiExeMap = new Dictionary<int, string>();

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT ProcessId, Name, CommandLine, ExecutablePath FROM Win32_Process"))
                using (var objects = searcher.Get())
                {
                    foreach (ManagementObject obj in objects)
                    {
                        try
                        {
                            int pid = Convert.ToInt32(obj["ProcessId"]);
                            string cmd = obj["CommandLine"] as string ?? "";
                            string exe = obj["ExecutablePath"] as string ?? "";
                            wmiCmdMap[pid] = cmd;
                            wmiExeMap[pid] = exe;
                        }
                        catch { }
                    }
                }
            }
            catch { }

            Process[] processes;
            try
            {
                processes = Process.GetProcesses();
            }
            catch
            {
                return list;
            }

            int currentPid = Process.GetCurrentProcess().Id;

            foreach (var p in processes)
            {
                try
                {
                    if (p.Id == currentPid || p.HasExited) continue;

                    string pName = (p.ProcessName ?? "").ToLowerInvariant();

                    windowMap.TryGetValue(p.Id, out var windows);
                    windows = windows ?? new List<string>();

                    string mainTitle = "";
                    try { mainTitle = p.MainWindowTitle ?? ""; } catch { }
                    if (!string.IsNullOrEmpty(mainTitle) && !windows.Contains(mainTitle))
                    {
                        windows.Add(mainTitle);
                    }

                    wmiCmdMap.TryGetValue(p.Id, out string cmdLine);
                    cmdLine = cmdLine ?? "";
                    string cmdLower = cmdLine.ToLowerInvariant();

                    wmiExeMap.TryGetValue(p.Id, out string exePath);
                    exePath = exePath ?? "";
                    if (string.IsNullOrEmpty(exePath))
                    {
                        try { exePath = p.MainModule?.FileName ?? ""; } catch { }
                    }

                    string fileDesc = "";
                    string prodName = "";
                    try
                    {
                        fileDesc = (p.MainModule?.FileVersionInfo?.FileDescription ?? "").ToLowerInvariant();
                        prodName = (p.MainModule?.FileVersionInfo?.ProductName ?? "").ToLowerInvariant();
                    }
                    catch { }

                    long memBytes = 0;
                    try { memBytes = p.WorkingSet64; } catch { }
                    long memMb = memBytes / (1024 * 1024);

                    int score = 0;
                    bool hasGameWindow = false;
                    string bestTitle = mainTitle;

                    foreach (var win in windows)
                    {
                        string wLower = win.ToLowerInvariant();

                        if (wLower.Contains("minecraft") ||
                            Regex.IsMatch(win, @"\b1\.\d{1,2}(?:\.\d{1,2})?\b"))
                        {
                            score += 1000;
                            hasGameWindow = true;
                            bestTitle = win;
                        }

                        if (wLower.Contains("сетевая игра") || wLower.Contains("одиночная игра") ||
                            wLower.Contains("multiplayer") || wLower.Contains("singleplayer"))
                        {
                            score += 500;
                            if (string.IsNullOrEmpty(bestTitle)) bestTitle = win;
                        }

                        if (wLower.Contains("lunar client") || wLower.Contains("badlion client") ||
                            wLower.Contains("feather client"))
                        {
                            score += 400;
                        }
                    }

                    if (pName == "pulse_launcher" || pName == "pulselauncher" || pName == "pulse")
                    {
                        score += 800;
                    }
                    else if (pName == "javaw")
                    {
                        score += 350;
                    }
                    else if (pName == "java")
                    {
                        score += 250;
                    }
                    else if (pName.Contains("craft") || pName.Contains("lunar") || pName.Contains("badlion"))
                    {
                        score += 300;
                    }

                    if (fileDesc.Contains("alaber") || fileDesc.Contains("pulse") || prodName.Contains("pulse") || prodName.Contains("alaber"))
                    {
                        score += 400;
                    }

                    if (cmdLower.Contains("net.minecraft.client.main.main") ||
                        cmdLower.Contains("knotclient") ||
                        cmdLower.Contains("fmlclientlaunchhandler") ||
                        cmdLower.Contains("bootstraplauncher") ||
                        cmdLower.Contains("net.minecraft.launchwrapper.launch"))
                    {
                        score += 600;
                        hasGameWindow = true;
                    }

                    if (cmdLower.Contains("--gamedir") || cmdLower.Contains("--assetsdir"))
                    {
                        score += 200;
                    }

                    if (cmdLower.Contains("org.tlauncher") || cmdLower.Contains("ru.turikhay") ||
                        cmdLower.Contains("tlauncher.jar") || cmdLower.Contains("launcher.jar") ||
                        cmdLower.Contains("tl.exe"))
                    {
                        if (!hasGameWindow) score -= 300;
                    }

                    if (memMb >= 4000) score += 400;
                    else if (memMb >= 2000) score += 300;
                    else if (memMb >= 1000) score += 200;
                    else if (memMb >= 500) score += 100;
                    else if (memMb < 150 && !hasGameWindow) score -= 150;

                    bool isRelevant = score > 100 ||
                                      hasGameWindow ||
                                      pName == "pulse_launcher" ||
                                      pName == "pulselauncher" ||
                                      pName == "javaw" ||
                                      pName == "java";

                    if (isRelevant)
                    {
                        bool isGame = hasGameWindow || memMb >= 600 || pName == "pulse_launcher" || pName == "javaw";

                        string tag = "";
                        if (hasGameWindow)
                        {
                            tag = " — Minecraft [Игра]";
                        }
                        else if (pName.Contains("launcher") && memMb < 500)
                        {
                            tag = " — Лаунчер";
                        }
                        else
                        {
                            tag = " — Minecraft";
                        }

                        string titleSnippet = "";
                        if (!string.IsNullOrEmpty(bestTitle))
                        {
                            titleSnippet = $" (\"{bestTitle}\")";
                        }

                        string display = $"{p.ProcessName}.exe (PID: {p.Id}, {memMb} МБ){tag}{titleSnippet}";

                        list.Add(new MinecraftProcessInfo
                        {
                            Pid = p.Id,
                            ProcessName = p.ProcessName,
                            WindowTitle = bestTitle ?? "",
                            MemoryMb = memMb,
                            ExecutablePath = exePath,
                            Score = score,
                            IsGame = isGame,
                            DisplayText = display
                        });
                    }
                }
                catch { }
            }

            return list.OrderByDescending(c => c.Score).ThenByDescending(c => c.MemoryMb).ToList();
        }

        public static List<int> GetAllMinecraftPids(int? preferredPid = null)
        {
            var pids = new List<int>();

            if (preferredPid.HasValue && preferredPid.Value > 0)
            {
                try
                {
                    var p = Process.GetProcessById(preferredPid.Value);
                    if (!p.HasExited)
                    {
                        pids.Add(preferredPid.Value);
                    }
                }
                catch { }
            }

            var candidates = FindCandidates();
            foreach (var c in candidates)
            {
                if (!pids.Contains(c.Pid))
                {
                    pids.Add(c.Pid);
                }
            }

            foreach (var p in Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java")).Concat(Process.GetProcessesByName("pulse_launcher")))
            {
                try
                {
                    if (!p.HasExited && !pids.Contains(p.Id))
                    {
                        pids.Add(p.Id);
                    }
                }
                catch { }
            }

            return pids;
        }

        public static string GetMinecraftProcessPath(int? preferredPid = null)
        {
            if (preferredPid.HasValue && preferredPid.Value > 0)
            {
                try
                {
                    var p = Process.GetProcessById(preferredPid.Value);
                    if (!p.HasExited && !string.IsNullOrEmpty(p.MainModule?.FileName))
                    {
                        return p.MainModule.FileName;
                    }
                }
                catch { }
            }

            var candidates = FindCandidates();
            var best = candidates.FirstOrDefault(c => !string.IsNullOrEmpty(c.ExecutablePath));
            return best?.ExecutablePath ?? "";
        }
    }
}
