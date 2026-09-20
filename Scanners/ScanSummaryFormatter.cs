using System;
using System.Collections.Generic;
using System.Linq;

namespace AngelMineChecker
{
    public static class ScanSummaryFormatter
    {
        public static void PrintSummary(List<string> banReasons, IEnumerable<string> deletedFiles, Action<string> log)
        {
            bool hasDoomsdayInject = false;
            bool hasDoomsdayLoader = false;
            bool hasCortexInject = false;
            bool hasCortexLoader = false;
            bool hasSystemDLCInject = false;
            bool hasSystemDLCLoader = false;
            bool hasLuminarInject = false;
            bool hasLuminarLoader = false;

            var folders = new List<string>();
            var otherCheats = new List<string>();
            var warnings = new List<string>();
            var seenWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenOther = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
                        lower.StartsWith("удаленные exe / jar"))
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

                    if (lower.Contains("папка чита") || lower.StartsWith("найдена папка"))
                    {
                        string folderLine = FormatFolder(trimmed);
                        if (seenFolders.Add(folderLine))
                        {
                            folders.Add(folderLine);
                        }
                        continue;
                    }

                    if (lower.Contains("doomsday") || lower.Contains("думик"))
                    {
                        if (IsInject(lower))
                        {
                            hasDoomsdayInject = true;
                        }
                        else
                        {
                            hasDoomsdayLoader = true;
                        }
                        continue;
                    }

                    if (lower.Contains("cortex"))
                    {
                        if (IsInject(lower))
                        {
                            hasCortexInject = true;
                        }
                        else
                        {
                            hasCortexLoader = true;
                        }
                        continue;
                    }

                    if (lower.Contains("systemdlc"))
                    {
                        if (IsInject(lower))
                        {
                            hasSystemDLCInject = true;
                        }
                        else
                        {
                            hasSystemDLCLoader = true;
                        }
                        continue;
                    }

                    if (lower.Contains("luminar"))
                    {
                        if (IsInject(lower))
                        {
                            hasLuminarInject = true;
                        }
                        else
                        {
                            hasLuminarLoader = true;
                        }
                        continue;
                    }

                    if (seenOther.Add(trimmed))
                    {
                        otherCheats.Add(trimmed);
                    }
                }
            }

            var cheats = new List<string>();

            if (hasDoomsdayInject) cheats.Add("Найден инжект Doomsday");
            if (hasDoomsdayLoader) cheats.Add("Найден Loader Doomsday");

            if (hasSystemDLCInject) cheats.Add("Найден инжект SystemDLC");
            if (hasSystemDLCLoader) cheats.Add("Найден Loader SystemDLC");

            if (hasCortexInject) cheats.Add("Найден инжект Cortex");
            if (hasCortexLoader) cheats.Add("Найден Loader Cortex");

            if (hasLuminarInject) cheats.Add("Найден инжект Luminar");
            if (hasLuminarLoader) cheats.Add("Найден Loader Luminar");

            foreach (var f in folders)
            {
                cheats.Add(f);
            }

            foreach (var o in otherCheats)
            {
                cheats.Add(o);
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

            if (warnings.Count > 0)
            {
                log("");
                log("Предупреждения:");
                foreach (var w in warnings)
                {
                    log($"   • {w}");
                }
            }

            if (cheats.Count == 0 && warnings.Count == 0)
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
            else if (warnings.Count > 0 || (delList != null && delList.Count > 0))
            {
                log("Вердикт: Продолжи дальше руками:)");
            }
            else
            {
                log("Вердикт: Чист");
            }
            log("");
        }

        private static bool IsInject(string lower)
        {
            return lower.Contains("инжект") ||
                   lower.Contains("памяти") ||
                   lower.Contains("строка") ||
                   lower.Contains("сетевое") ||
                   lower.Contains("classloader") ||
                   lower.Contains("attach") ||
                   lower.Contains("dns") ||
                   lower.Contains("буфер");
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
