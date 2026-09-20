using System;
using System.Collections.Generic;
using System.Linq;

namespace AngelMineChecker
{
    public static class ScanSummaryFormatter
    {
        public static void PrintSummary(List<string> banReasons, IEnumerable<string> deletedFiles, Action<string> log)
        {
            var cheats = new List<string>();
            var warnings = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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
                        lower.StartsWith("нарушений не обнаружено") ||
                        lower.StartsWith("удаленные exe / jar"))
                    {
                        continue;
                    }

                    string normalizedKey = NormalizeKey(trimmed);
                    if (!seen.Add(normalizedKey)) continue;

                    if (IsWarning(lower))
                    {
                        warnings.Add(FormatWarning(trimmed));
                    }
                    else
                    {
                        cheats.Add(FormatCheat(trimmed));
                    }
                }
            }

            log("");
            log("==================== [ ИТОГИ ПРОВЕРКИ ] ====================");
            log("");

            if (cheats.Count > 0)
            {
                log($"[🔴 ЧИТЫ И ИНЖЕКТЫ]: ОБНАРУЖЕНО ({cheats.Count})");
                foreach (var c in cheats)
                {
                    log($"   • {c}");
                }
                log("");
            }

            if (warnings.Count > 0)
            {
                log($"[⚠️ СЛУЖБЫ И СИСТЕМА]: ПРЕДУПРЕЖДЕНИЯ ({warnings.Count})");
                foreach (var w in warnings)
                {
                    log($"   • {w}");
                }
                log("");
            }

            if (cheats.Count == 0 && warnings.Count == 0)
            {
                log("✅ [ЧИСТО]: Запрещённого ПО и системных нарушений не обнаружено!");
                log("");
            }

            log("[📁 УДАЛЕННЫЕ EXE / JAR ЗА 30 МИН (JournalTrace)]:");
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

            log("============================================================");
        }

        private static string NormalizeKey(string s)
        {
            string lower = s.ToLowerInvariant();
            if (lower.Contains("строка чита doomsday") || lower.Contains("ymj5m3rttkkspwwlcvnd"))
            {
                int pidIdx = lower.IndexOf("pid");
                if (pidIdx > 0)
                {
                    return "doomsday_string_" + lower.Substring(pidIdx);
                }
                return "doomsday_string";
            }
            if (lower.Contains("classloader") && (lower.Contains("doomsday") || lower.Contains("инжект")))
            {
                return "doomsday_classloader";
            }
            return lower;
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
                   lower.Contains("usn journal отключен");
        }

        private static string FormatWarning(string s)
        {
            return s;
        }

        private static string FormatCheat(string s)
        {
            string lower = s.ToLowerInvariant();
            if (lower.Contains("doomsday") || lower.Contains("думик"))
            {
                if (!s.StartsWith("Doomsday:", StringComparison.OrdinalIgnoreCase))
                {
                    if (s.StartsWith("Инжект Doomsday", StringComparison.OrdinalIgnoreCase))
                    {
                        return $"Doomsday: {s.Substring(8).Trim()}";
                    }
                    if (s.StartsWith("Строка чита Doomsday", StringComparison.OrdinalIgnoreCase))
                    {
                        return $"Doomsday: {s.Substring(12).Trim()}";
                    }
                    if (s.StartsWith("Найден чит Doomsday", StringComparison.OrdinalIgnoreCase))
                    {
                        string rest = s.Substring(19).Trim();
                        if (rest.StartsWith("-")) rest = rest.Substring(1).Trim();
                        return $"Doomsday: {rest}";
                    }
                }
            }
            return s;
        }
    }
}
