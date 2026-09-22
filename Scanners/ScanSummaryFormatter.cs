using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace AngelMineChecker
{
    public static class ScanSummaryFormatter
    {
        public static void PrintSummary(List<string> banReasons, IEnumerable<string> deletedFiles, Action<string> log)
        {
            var cheats = new List<string>();
            var manualChecks = new List<string>();
            var warnings = new List<string>();

            var seenCheats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenManual = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (banReasons != null)
            {
                foreach (var raw in banReasons)
                {
                    if (string.IsNullOrWhiteSpace(raw)) continue;
                    string trimmed = raw.Trim();
                    while (trimmed.StartsWith("*") || trimmed.StartsWith("-") || trimmed.StartsWith("•") || trimmed.StartsWith("->"))
                    {
                        trimmed = trimmed.Substring(trimmed.StartsWith("->") ? 2 : 1).Trim();
                    }

                    string lower = trimmed.ToLowerInvariant();

                    if (lower == "инжект думика обнаружен" ||
                        lower == "инжект думика не обнаружен" ||
                        lower == "следы doomsday обнаружены" ||
                        lower == "обнаружен след запрещенного по" ||
                        lower == "итоги:" ||
                        lower == "итоги проверки:" ||
                        lower.StartsWith("нарушений не обнаружено") ||
                        lower.StartsWith("удаленные exe / jar") ||
                        lower.StartsWith("[process hacker]"))
                    {
                        continue;
                    }

                    if (IsWarning(lower))
                    {
                        string warn = FormatWarning(trimmed);
                        if (seenWarnings.Add(warn))
                        {
                            warnings.Add(warn);
                        }
                        continue;
                    }

                    if (IsManualCheckTrace(lower))
                    {
                        if (seenManual.Add(trimmed))
                        {
                            manualChecks.Add(trimmed);
                        }
                        continue;
                    }

                    if (lower.Contains("папка чита") || lower.StartsWith("найдена папка"))
                    {
                        string folderLine = FormatFolder(trimmed);
                        if (seenCheats.Add(folderLine))
                        {
                            cheats.Add(folderLine);
                        }
                        continue;
                    }

                    if (seenCheats.Add(trimmed))
                    {
                        cheats.Add(trimmed);
                    }
                }
            }

            log("");
            log("Итоги проверки:");

            if (cheats.Count > 0)
            {
                log("");
                log("Читы и инжекты:");
                foreach (var c in cheats)
                {
                    log($"   • {c}");
                }
            }

            if (manualChecks.Count > 0)
            {
                log("");
                log("Следы и подозрительные модули (Проверь руками):");
                foreach (var m in manualChecks)
                {
                    log($"   • {m}");
                    string guide = GetProcessHackerGuide(m);
                    if (!string.IsNullOrEmpty(guide))
                    {
                        log($"     -> [Process Hacker] {guide}");
                    }
                }
            }

            if (warnings.Count > 0)
            {
                log("");
                log("Предупреждения:");
                foreach (var w in warnings)
                {
                    log($"   • {w}");
                }
            }

            if (cheats.Count == 0 && manualChecks.Count == 0 && warnings.Count == 0)
            {
                log("");
                log("Чисто: Запрещённого ПО и нарушений не обнаружено");
            }

            log("");
            log("JournalTrace:");
            var delList = deletedFiles?.ToList();
            if (delList != null && delList.Count > 0)
            {
                foreach (var f in delList)
                {
                    log($"   • {f}");
                }
            }
            else
            {
                log("   • Не обнаружено");
            }

            log("");
            if (cheats.Count > 0)
            {
                log("Вердикт: Бан");
            }
            else if (manualChecks.Count > 0 || warnings.Count > 0 || (delList != null && delList.Count > 0))
            {
                log("Вердикт: Проверь руками");
            }
            else
            {
                log("Вердикт: Чист");
            }
            log("");
        }

        public static string GetProcessHackerGuide(string item)
        {
            if (string.IsNullOrWhiteSpace(item)) return "";
            string lower = item.ToLowerInvariant();

            if (lower.Contains("подозрительный инжект dll") || (lower.Contains(".dll") && lower.Contains("инжект")))
            {
                string dllName = "";
                var m = Regex.Match(item, @"(?:-\s*|DLL:\s*)([^\s\(\)]+\.dll)", RegexOptions.IgnoreCase);
                if (m.Success) dllName = m.Groups[1].Value;

                if (!string.IsNullOrEmpty(dllName))
                    return $"Process Hacker -> javaw.exe -> вкладка Modules -> найти \"{dllName}\" (проверить путь и цифровую подпись)";
                return "Process Hacker -> javaw.exe -> вкладка Modules -> найти DLL (проверить путь и цифровую подпись)";
            }

            if (lower.Contains("памяти java") || lower.Contains("след чита в памяти") || lower.Contains("строка чита в памяти") || lower.Contains("адрес 0x"))
            {
                string pidStr = "";
                string addrStr = "";
                string patternStr = "";

                var pidMatch = Regex.Match(item, @"PID\s+(\d+)", RegexOptions.IgnoreCase);
                if (pidMatch.Success) pidStr = pidMatch.Groups[1].Value;

                var addrMatch = Regex.Match(item, @"адрес\s+(0x[0-9A-Fa-f]+)", RegexOptions.IgnoreCase);
                if (addrMatch.Success) addrStr = addrMatch.Groups[1].Value;

                var patMatch = Regex.Match(item, @"\((.+?)\s+в\s+PID", RegexOptions.IgnoreCase);
                if (patMatch.Success) patternStr = patMatch.Groups[1].Value.Trim();

                string target = !string.IsNullOrEmpty(pidStr) ? $"javaw.exe (PID {pidStr})" : "javaw.exe";
                string filterPart = !string.IsNullOrEmpty(patternStr) ? $" -> Strings... -> Filter: \"{patternStr}\"" : " -> Strings...";
                string addrPart = !string.IsNullOrEmpty(addrStr) ? $" (или Ctrl+G: {addrStr})" : "";

                return $"Process Hacker -> {target} -> вкладка Memory{filterPart}{addrPart}";
            }

            if (lower.Contains("regedit =") || lower.Contains("userassist") || lower.Contains("appswitched") || lower.Contains("bam ="))
            {
                string exeName = "";
                var m = Regex.Match(item, @"([a-zA-Z0-9_\-\.]+\.exe)", RegexOptions.IgnoreCase);
                if (m.Success) exeName = m.Groups[1].Value;

                if (!string.IsNullOrEmpty(exeName))
                    return $"Process Hacker -> нажать Ctrl+F -> проверить запущен ли \"{exeName}\", проверить наличие файла на диске и в корзине";
                return "Process Hacker -> нажать Ctrl+F -> проверить процессы чита по имени, проверить наличие файла на диске";
            }

            if (lower.Contains("сетевое подключение") || lower.Contains("сетевое обращение"))
            {
                return "Process Hacker -> вкладка Network -> проверить активные сетевые подключения процесса javaw.exe";
            }

            if (lower.Contains("внедрен поток") || lower.Contains("поток чита"))
            {
                var tidMatch = Regex.Match(item, @"TID\s+(\d+)", RegexOptions.IgnoreCase);
                string tid = tidMatch.Success ? $"TID {tidMatch.Groups[1].Value}" : "поток";
                return $"Process Hacker -> javaw.exe -> вкладка Threads -> найти {tid} (проверить адрес в немодульной памяти MEM_PRIVATE)";
            }

            if (lower.Contains("перехвачены оконные сообщения") || lower.Contains("wndproc"))
            {
                return "Process Hacker -> javaw.exe -> вкладка Windows -> Properties окна -> поле WndProc (проверить адрес хука)";
            }

            if (lower.Contains("dns-кэш") || lower.Contains("dns кэш") || lower.Contains("в dns кэше"))
            {
                return "Командная строка (cmd) -> выполнить: ipconfig /displaydns (проверить кэш DNS на домены чита)";
            }

            if (lower.Contains("prefetch"))
            {
                return "Проверить папку C:\\Windows\\Prefetch на дату и время запуска лоадера";
            }

            if (lower.Contains("attach api") || lower.Contains("attach.dll"))
            {
                return "Process Hacker -> javaw.exe -> вкладка Modules -> проверить наличие attach.dll";
            }

            return "";
        }

        private static bool IsManualCheckTrace(string lower)
        {
            if (lower.Contains("подозрительный инжект dll"))
                return true;

            if (lower.Contains("след чита в памяти") ||
                lower.Contains("строка чита в памяти") ||
                lower.Contains("класс чита в памяти") ||
                lower.Contains("сетевая загрузка шрифтов") ||
                lower.Contains("след чита в памяти java"))
                return true;

            if (lower.Contains("regedit =") ||
                lower.Contains("userassist") ||
                lower.Contains("appswitched") ||
                lower.Contains("bam =") ||
                lower.Contains("opensavepidlmru") ||
                lower.Contains("muicache"))
                return true;

            if (lower.Contains("dns-кэш") ||
                lower.Contains("dns кэш") ||
                lower.Contains("в dns кэше"))
                return true;

            if (lower.Contains("буфер консоли") ||
                lower.Contains("буфере консоли") ||
                lower.Contains("буфер обмена") ||
                lower.Contains("буфере обмена") ||
                lower.Contains("powershell") ||
                lower.Contains(".python_history") ||
                lower.Contains("истории python") ||
                lower.Contains("python idle") ||
                lower.Contains("prefetch"))
                return true;

            if (lower.Contains("attach api") ||
                lower.Contains("attach.dll"))
                return true;

            return false;
        }

        private static bool IsWarning(string lower)
        {
            return lower.Contains("остановлен сервис") ||
                   lower.Contains("служба") ||
                   lower.Contains("pcasvc") ||
                   lower.Contains("dps") ||
                   lower.Contains("sysmain") ||
                   lower.Contains("отключен драйвер bam") ||
                   lower.Contains("драйвер bam") ||
                   lower.Contains("usn journal отключен") ||
                   lower.Contains("отключен") ||
                   lower.Contains("очищен") ||
                   lower.Contains("отчищен") ||
                   lower.Contains("обфускация") ||
                   lower.Contains("корзина была очищена") ||
                   lower.Contains("prefetch пустая");
        }

        private static string FormatFolder(string s)
        {
            int dashIdx = s.IndexOf('-');
            if (dashIdx >= 0)
            {
                string info = s.Substring(dashIdx + 1).Trim();
                return $"Найдена папка чита: {info}";
            }
            if (s.StartsWith("Найдена папка чита", StringComparison.OrdinalIgnoreCase))
            {
                return s;
            }
            return $"Найдена папка чита: {s}";
        }

        private static string FormatWarning(string s)
        {
            return s;
        }
    }
}
