using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace AngelMineChecker
{
    public class ReportModel
    {
        public string ReportId { get; set; }
        public string ScanType { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration => EndTime - StartTime;
        public int? TargetPid { get; set; }
        public string TargetProcessName { get; set; }
        public ScanOptions Options { get; set; } = new ScanOptions();
        public List<string> BanReasons { get; set; } = new List<string>();
        public List<string> Logs { get; set; } = new List<string>();
        public List<AccountRecord> Accounts { get; set; } = new List<AccountRecord>();
    }

    public static class HtmlReportGenerator
    {
        private static string GenerateReportId()
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            var rnd = new Random();
            var sb = new StringBuilder(8);
            for (int i = 0; i < 8; i++)
            {
                sb.Append(chars[rnd.Next(chars.Length)]);
            }
            return $"AM-{sb}";
        }

        private static string GetOsName()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT Caption, CSDVersion, OSArchitecture, Version FROM Win32_OperatingSystem"))
                {
                    foreach (var os in searcher.Get())
                    {
                        string caption = os["Caption"]?.ToString() ?? "Windows";
                        string arch = os["OSArchitecture"]?.ToString() ?? "64-bit";
                        string ver = os["Version"]?.ToString() ?? "";
                        return $"{caption.Trim()} ({arch}, build {ver})";
                    }
                }
            }
            catch { }
            return Environment.OSVersion.VersionString;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        private static (string bootTime, string uptime) GetBootAndUptime()
        {
            try
            {
                ulong ticks = GetTickCount64();
                var up = TimeSpan.FromMilliseconds(ticks);
                var boot = DateTime.Now - up;
                string upStr = $"{(int)up.TotalHours} ч. {up.Minutes} мин.";
                return (boot.ToString("dd.MM.yyyy HH:mm:ss"), upStr);
            }
            catch
            {
                return ("-", "-");
            }
        }

        public static string GenerateHtml(ReportModel model)
        {
            if (string.IsNullOrEmpty(model.ReportId))
            {
                model.ReportId = GenerateReportId();
            }

            bool isCheating = model.BanReasons != null && model.BanReasons.Count > 0;
            string verdictBadge = isCheating ? "CHEATING" : "CLEAN";
            string verdictColor = isCheating ? "#FF4D6D" : "#10B981";
            string verdictBg = isCheating ? "#3B1219" : "#0F291E";
            string verdictBorder = isCheating ? "#7F1D1D" : "#065F46";
            string verdictSubtitle = isCheating
                ? "Обнаружены следы использования запрещенного ПО или активных модификаций"
                : "В ходе проверки вредоносного ПО, инжектов и запрещенных модов не обнаружено";

            string osInfo = GetOsName();
            var (bootTime, uptime) = GetBootAndUptime();
            var (installDate, _) = AccountScanner.GetWindowsInstallDate();

            string pidDisplay = model.TargetPid.HasValue && model.TargetPid.Value > 0
                ? $"{model.TargetProcessName ?? "javaw.exe"} (PID: {model.TargetPid.Value})"
                : "Процесс не выбран / Все процессы";

            var distinctBans = (model.BanReasons ?? new List<string>()).Distinct().ToList();

            var sb = new StringBuilder();

            sb.Append("<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n");
            sb.Append("<meta charset=\"UTF-8\">\n");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
            sb.Append($"<title>AngelMine Scan Report - {WebUtility.HtmlEncode(model.ReportId)}</title>\n");
            sb.Append("<style>\n");
            sb.Append(@"
:root {
    --bg-main: #0A0D14;
    --bg-card: #11141E;
    --bg-card-alt: #0E1119;
    --border-card: #1C2234;
    --border-highlight: #28324C;
    --accent-orange: #FF6B00;
    --accent-orange-grad: linear-gradient(135deg, #FF7A00 0%, #FF5500 100%);
    --color-cheating: #FF4D6D;
    --bg-cheating: #3B1219;
    --border-cheating: #7F1D1D;
    --color-clean: #10B981;
    --bg-clean: #0F291E;
    --border-clean: #065F46;
    --color-warn: #F59E0B;
    --bg-warn: #2E200B;
    --text-main: #F1F5F9;
    --text-muted: #8F9CAE;
    --text-subtle: #576375;
}
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}
body {
    background-color: var(--bg-main);
    color: var(--text-main);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.5;
    padding: 24px;
}
.container {
    max-width: 1180px;
    margin: 0 auto;
}
.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    border-radius: 14px;
    padding: 20px 28px;
    margin-bottom: 20px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}
.brand-title {
    font-size: 22px;
    font-weight: 900;
    letter-spacing: 0.5px;
    color: #FFFFFF;
}
.brand-title span {
    color: var(--accent-orange);
}
.brand-subtitle {
    font-size: 12.5px;
    color: var(--text-muted);
    margin-top: 3px;
    letter-spacing: 0.3px;
}
.header-right {
    display: flex;
    align-items: center;
    gap: 16px;
}
.report-id-pill {
    background: #171C2B;
    border: 1px solid #28324C;
    padding: 7px 14px;
    border-radius: 8px;
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 13px;
    font-weight: 700;
    color: #CBD5E1;
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    transition: all 0.2s ease;
}
.report-id-pill:hover {
    border-color: var(--accent-orange);
    color: #FFFFFF;
}
.verdict-pill {
    padding: 8px 22px;
    border-radius: 8px;
    font-weight: 900;
    font-size: 14px;
    letter-spacing: 1px;
    text-transform: uppercase;
}
.verdict-banner {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 16px 24px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 16px;
}
.verdict-banner.cheating {
    border: 1px solid var(--border-cheating);
    background: linear-gradient(90deg, rgba(59, 18, 25, 0.6) 0%, rgba(17, 20, 30, 0.95) 100%);
}
.verdict-banner.clean {
    border: 1px solid var(--border-clean);
    background: linear-gradient(90deg, rgba(15, 41, 30, 0.6) 0%, rgba(17, 20, 30, 0.95) 100%);
}
.verdict-icon {
    font-size: 28px;
    line-height: 1;
}
.verdict-text-box h3 {
    font-size: 16px;
    font-weight: 700;
    margin-bottom: 2px;
}
.verdict-text-box p {
    font-size: 13px;
    color: var(--text-muted);
}
.section-title {
    font-size: 15px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: #FFFFFF;
    margin: 26px 0 14px 0;
    display: flex;
    align-items: center;
    gap: 10px;
}
.section-title::before {
    content: '';
    display: inline-block;
    width: 4px;
    height: 16px;
    background: var(--accent-orange);
    border-radius: 2px;
}
.meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
}
.meta-card {
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    border-radius: 10px;
    padding: 14px 18px;
}
.meta-label {
    font-size: 11px;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 6px;
}
.meta-value {
    font-size: 13.5px;
    font-weight: 600;
    color: #FFFFFF;
    word-break: break-word;
}
.threats-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.threat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-cheating);
    border-left: 4px solid var(--color-cheating);
    border-radius: 10px;
    padding: 14px 18px;
    box-shadow: 0 2px 10px rgba(255, 77, 109, 0.08);
}
.threat-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}
.threat-name {
    font-size: 14px;
    font-weight: 700;
    color: #FFFFFF;
}
.threat-badge {
    background: var(--bg-cheating);
    color: var(--color-cheating);
    border: 1px solid var(--border-cheating);
    font-size: 11px;
    font-weight: 800;
    padding: 3px 8px;
    border-radius: 5px;
    letter-spacing: 0.5px;
}
.threat-detail {
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 12px;
    color: #CBD5E1;
    background: #080A10;
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid #1E2333;
    word-break: break-all;
}
.clean-banner {
    background: var(--bg-card);
    border: 1px solid var(--border-clean);
    border-left: 4px solid var(--color-clean);
    border-radius: 10px;
    padding: 18px 20px;
    color: #CBD5E1;
    font-size: 13.5px;
    display: flex;
    align-items: center;
    gap: 12px;
}
.modules-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 12px;
}
.module-card {
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    border-radius: 10px;
    padding: 14px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    transition: transform 0.15s ease, border-color 0.15s ease;
}
.module-card:hover {
    border-color: var(--border-highlight);
    transform: translateY(-1px);
}
.module-info h4 {
    font-size: 13px;
    font-weight: 700;
    color: #FFFFFF;
    margin-bottom: 2px;
}
.module-info p {
    font-size: 11px;
    color: var(--text-muted);
}
.module-status {
    font-size: 11px;
    font-weight: 800;
    padding: 4px 10px;
    border-radius: 6px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}
.status-clean {
    background: var(--bg-clean);
    color: var(--color-clean);
    border: 1px solid var(--border-clean);
}
.status-detected {
    background: var(--bg-cheating);
    color: var(--color-cheating);
    border: 1px solid var(--border-cheating);
}
.status-skipped {
    background: #171B26;
    color: var(--text-muted);
    border: 1px solid #232A3B;
}
.accounts-container {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.account-card {
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    border-radius: 8px;
    padding: 10px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
}
.account-nick {
    font-size: 13px;
    font-weight: 700;
    color: #FFFFFF;
}
.account-source {
    font-size: 11px;
    color: var(--text-muted);
    background: #151928;
    padding: 2px 8px;
    border-radius: 4px;
}
.terminal-window {
    background: #07090F;
    border: 1px solid #1A2033;
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 24px;
    box-shadow: 0 6px 24px rgba(0,0,0,0.5);
}
.terminal-header {
    background: #0F1320;
    border-bottom: 1px solid #1A2033;
    padding: 10px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.terminal-dots {
    display: flex;
    gap: 7px;
}
.dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
}
.dot.red { background: #EF4444; }
.dot.yellow { background: #F59E0B; }
.dot.green { background: #10B981; }
.terminal-title {
    font-size: 11.5px;
    font-weight: 700;
    color: var(--text-muted);
    letter-spacing: 0.6px;
    text-transform: uppercase;
}
.btn-copy {
    background: #181E2E;
    border: 1px solid #2A354E;
    color: #CBD5E1;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 5px;
    cursor: pointer;
    transition: all 0.2s ease;
}
.btn-copy:hover {
    background: #232C42;
    color: #FFFFFF;
    border-color: var(--accent-orange);
}
.terminal-body {
    padding: 14px 18px;
    max-height: 440px;
    overflow-y: auto;
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 11.5px;
    line-height: 1.6;
}
.terminal-body::-webkit-scrollbar {
    width: 6px;
}
.terminal-body::-webkit-scrollbar-thumb {
    background: #1C2337;
    border-radius: 3px;
}
.log-line {
    word-break: break-all;
    white-space: pre-wrap;
}
.log-ts { color: #526079; }
.log-warn { color: #F59E0B; }
.log-alert { color: #FF4D6D; font-weight: 600; }
.log-ok { color: #10B981; }
.log-info { color: #8F9CAE; }

.footer {
    text-align: center;
    border-top: 1px solid #161A28;
    padding-top: 24px;
    margin-top: 20px;
    color: var(--text-subtle);
    font-size: 11.5px;
}
.footer p { margin-bottom: 4px; }
.footer strong { color: var(--text-muted); }
</style>\n");
            sb.Append("</head>\n<body>\n");

            sb.Append("<div class=\"container\">\n");

            // Header
            sb.Append("<header class=\"header\">\n");
            sb.Append("  <div>\n");
            sb.Append("    <div class=\"brand-title\">ANGELMINE <span>CHECKER</span></div>\n");
            sb.Append("    <div class=\"brand-subtitle\">System Scan Analysis Report &bull; Forensic Minecraft Anti-Cheat</div>\n");
            sb.Append("  </div>\n");
            sb.Append("  <div class=\"header-right\">\n");
            sb.Append($"    <div class=\"report-id-pill\" onclick=\"copyText('{model.ReportId}', this)\" title=\"Нажмите для копирования\">\n");
            sb.Append($"      <span>ID: {WebUtility.HtmlEncode(model.ReportId)}</span>\n");
            sb.Append("      <span style=\"font-size:10px; opacity:0.6;\">📋</span>\n");
            sb.Append("    </div>\n");
            sb.Append($"    <div class=\"verdict-pill\" style=\"background:{verdictBg}; color:{verdictColor}; border:1px solid {verdictBorder};\">{verdictBadge}</div>\n");
            sb.Append("  </div>\n");
            sb.Append("</header>\n");

            // Verdict Banner
            string bannerClass = isCheating ? "cheating" : "clean";
            string bannerIcon = isCheating ? "⚠️" : "🛡️";
            string bannerTitle = isCheating ? "ОБНАРУЖЕНЫ НАРУШЕНИЯ" : "СИСТЕМА ЧИСТА";
            sb.Append($"<div class=\"verdict-banner {bannerClass}\">\n");
            sb.Append($"  <div class=\"verdict-icon\">{bannerIcon}</div>\n");
            sb.Append("  <div class=\"verdict-text-box\">\n");
            sb.Append($"    <h3 style=\"color:{verdictColor};\">{bannerTitle}</h3>\n");
            sb.Append($"    <p>{verdictSubtitle}</p>\n");
            sb.Append("  </div>\n");
            sb.Append("</div>\n");

            // PC Information Grid
            sb.Append("<div class=\"section-title\">Информация о системе и сканировании</div>\n");
            sb.Append("<div class=\"meta-grid\">\n");

            sb.Append("  <div class=\"meta-card\">\n");
            sb.Append("    <div class=\"meta-label\">Операционная система</div>\n");
            sb.Append($"    <div class=\"meta-value\">{WebUtility.HtmlEncode(osInfo)}</div>\n");
            sb.Append("  </div>\n");

            sb.Append("  <div class=\"meta-card\">\n");
            sb.Append("    <div class=\"meta-label\">Запуск ПК & Uptime</div>\n");
            sb.Append($"    <div class=\"meta-value\">{WebUtility.HtmlEncode(bootTime)} (работает {WebUtility.HtmlEncode(uptime)})</div>\n");
            sb.Append("  </div>\n");

            sb.Append("  <div class=\"meta-card\">\n");
            sb.Append("    <div class=\"meta-label\">Целевой процесс / PID</div>\n");
            sb.Append($"    <div class=\"meta-value\">{WebUtility.HtmlEncode(pidDisplay)}</div>\n");
            sb.Append("  </div>\n");

            sb.Append("  <div class=\"meta-card\">\n");
            sb.Append("    <div class=\"meta-label\">Режим сканирования</div>\n");
            sb.Append($"    <div class=\"meta-value\">{WebUtility.HtmlEncode(model.ScanType ?? "Стандартная проверка")}</div>\n");
            sb.Append("  </div>\n");

            sb.Append("  <div class=\"meta-card\">\n");
            sb.Append("    <div class=\"meta-label\">Время проведения</div>\n");
            sb.Append($"    <div class=\"meta-value\">{model.StartTime:dd.MM.yyyy HH:mm:ss} &bull; Длительность: {model.Duration.TotalSeconds:F1} сек.</div>\n");
            sb.Append("  </div>\n");

            sb.Append("  <div class=\"meta-card\">\n");
            sb.Append("    <div class=\"meta-label\">Дата установки Windows</div>\n");
            sb.Append($"    <div class=\"meta-value\">{WebUtility.HtmlEncode(installDate ?? "-")}</div>\n");
            sb.Append("  </div>\n");

            sb.Append("</div>\n");

            // Detection Results Section
            sb.Append($"<div class=\"section-title\">Результаты обнаружения ({distinctBans.Count})</div>\n");
            if (distinctBans.Count > 0)
            {
                sb.Append("<div class=\"threats-list\">\n");
                foreach (var ban in distinctBans)
                {
                    string badge = "DETECTED";
                    string banLower = ban.ToLower();
                    if (banLower.Contains("памяти") || banLower.Contains("jvm") || banLower.Contains("classloader") || banLower.Contains("инжект"))
                    {
                        badge = "MEMORY TRACE";
                    }
                    else if (banLower.Contains("prefetch"))
                    {
                        badge = "PREFETCH";
                    }
                    else if (banLower.Contains("папка") || banLower.Contains("файл"))
                    {
                        badge = "ON DISK";
                    }
                    else if (banLower.Contains("процесс"))
                    {
                        badge = "IN INSTANCE";
                    }
                    else if (banLower.Contains("сетевое") || banLower.Contains("ip"))
                    {
                        badge = "NETWORK C2";
                    }

                    sb.Append("  <div class=\"threat-card\">\n");
                    sb.Append("    <div class=\"threat-header\">\n");
                    sb.Append("      <span class=\"threat-name\">Обнаружен след запрещенного ПО</span>\n");
                    sb.Append($"      <span class=\"threat-badge\">{badge}</span>\n");
                    sb.Append("    </div>\n");
                    sb.Append($"    <div class=\"threat-detail\">{WebUtility.HtmlEncode(ban)}</div>\n");
                    sb.Append("  </div>\n");
                }
                sb.Append("</div>\n");
            }
            else
            {
                sb.Append("<div class=\"clean-banner\">\n");
                sb.Append("  <span style=\"font-size:22px;\">🛡️</span>\n");
                sb.Append("  <div>\n");
                sb.Append("    <strong style=\"color:#FFFFFF; font-size:14px;\">Нарушений не обнаружено</strong><br/>\n");
                sb.Append("    Все проверенные области памяти JVM, файловые сигнатуры, процессы и журналы Windows чисты.\n");
                sb.Append("  </div>\n");
                sb.Append("</div>\n");
            }

            // Checked Modules Grid
            sb.Append("<div class=\"section-title\">Проверенные модули и детекторы</div>\n");
            sb.Append("<div class=\"modules-grid\">\n");

            bool HasBan(string keyword) => distinctBans.Any(b => b.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0);

            void AppendModule(string title, string desc, bool enabled, bool detected)
            {
                string statusText, statusClass;
                if (!enabled)
                {
                    statusText = "ПРОПУЩЕН";
                    statusClass = "status-skipped";
                }
                else if (detected)
                {
                    statusText = "НАРУШЕНИЕ";
                    statusClass = "status-detected";
                }
                else
                {
                    statusText = "ЧИСТО";
                    statusClass = "status-clean";
                }

                sb.Append("  <div class=\"module-card\">\n");
                sb.Append("    <div class=\"module-info\">\n");
                sb.Append($"      <h4>{WebUtility.HtmlEncode(title)}</h4>\n");
                sb.Append($"      <p>{WebUtility.HtmlEncode(desc)}</p>\n");
                sb.Append("    </div>\n");
                sb.Append($"    <div class=\"module-status {statusClass}\">{statusText}</div>\n");
                sb.Append("  </div>\n");
            }

            AppendModule("Doomsday Scanner", "32 нитки, JVM инжекты, C2 сервер", model.Options.CheckDoomsday, HasBan("Doomsday"));
            AppendModule("SystemDLC Checker", "Сигнатуры памяти, Prefetch, файлы", model.Options.CheckSystemDlc, HasBan("SystemDLC") || HasBan("jlivef"));
            AppendModule("Cortex Scanner", "Папки, процессы, Prefetch, файлы", model.Options.CheckCortex, HasBan("Cortex"));
            AppendModule("Luminar Scanner", "Клиент, конфиги, Prefetch, процессы", model.Options.CheckLuminar, HasBan("Luminar"));
            AppendModule("Pulse Visual", "Папки %appdata%, процессы, Prefetch", true, HasBan("Pulse"));
            AppendModule("Memory & Injects", "JDWP агент, DLL инжекты, хуки", true, HasBan("инжект") || HasBan("jdwp") || HasBan("dll"));
            AppendModule("Prefetch & USN Journal", "История запусков, удаленные файлы", true, HasBan("Prefetch") || HasBan("Journal"));
            AppendModule("Minecraft Environment", "Папка mods, логи, проверка очистки", true, HasBan("мод") || HasBan("лог") || HasBan("очистк"));

            sb.Append("</div>\n");

            // Accounts section
            if (model.Accounts != null && model.Accounts.Count > 0)
            {
                sb.Append("<div class=\"section-title\">Найденные аккаунты Minecraft</div>\n");
                sb.Append("<div class=\"accounts-container\">\n");
                foreach (var acc in model.Accounts)
                {
                    sb.Append("  <div class=\"account-card\">\n");
                    sb.Append($"    <span class=\"account-nick\">🎮 {WebUtility.HtmlEncode(acc.Nickname)}</span>\n");
                    sb.Append($"    <span class=\"account-source\">{WebUtility.HtmlEncode(acc.SourceDisplay)}</span>\n");
                    sb.Append("  </div>\n");
                }
                sb.Append("</div>\n");
            }

            // Terminal Logs
            sb.Append("<div class=\"section-title\">Консольный лог сканирования</div>\n");
            sb.Append("<div class=\"terminal-window\">\n");
            sb.Append("  <div class=\"terminal-header\">\n");
            sb.Append("    <div class=\"terminal-dots\">\n");
            sb.Append("      <div class=\"dot red\"></div>\n");
            sb.Append("      <div class=\"dot yellow\"></div>\n");
            sb.Append("      <div class=\"dot green\"></div>\n");
            sb.Append("    </div>\n");
            sb.Append("    <div class=\"terminal-title\">ANGELMINE SCAN CONSOLE</div>\n");
            sb.Append("    <button class=\"btn-copy\" onclick=\"copyConsoleLogs()\">Скопировать лог</button>\n");
            sb.Append("  </div>\n");
            sb.Append("  <div class=\"terminal-body\" id=\"consoleLogs\">\n");

            if (model.Logs != null)
            {
                foreach (var line in model.Logs)
                {
                    string safeLine = WebUtility.HtmlEncode(line);
                    string lineClass = "log-info";
                    string lLower = line.ToLower();

                    if (lLower.Contains("найден") || lLower.Contains("инжект") || lLower.Contains("чит") || lLower.Contains("бан") || lLower.Contains("doomsday") || lLower.Contains("systemdlc"))
                    {
                        lineClass = "log-alert";
                    }
                    else if (lLower.Contains("предупреждение") || lLower.Contains("внимание") || lLower.Contains("очистк") || lLower.Contains("warn"))
                    {
                        lineClass = "log-warn";
                    }
                    else if (lLower.Contains("чисто") || lLower.Contains("нарушений не обнаружено") || lLower.Contains("успешно"))
                    {
                        lineClass = "log-ok";
                    }

                    sb.Append($"    <div class=\"log-line {lineClass}\">{safeLine}</div>\n");
                }
            }

            sb.Append("  </div>\n");
            sb.Append("</div>\n");

            // Footer
            sb.Append("<footer class=\"footer\">\n");
            sb.Append("  <p><strong>AngelMine Anti-Cheat Forensic Report</strong> &bull; Версия 1.0.0</p>\n");
            sb.Append($"  <p>Данный отчет сгенерирован автоматически в целях проверки игроков на сервере AngelMine. Код отчета: {WebUtility.HtmlEncode(model.ReportId)}</p>\n");
            sb.Append("</footer>\n");

            sb.Append("</div>\n"); // .container

            // Vanilla JS
            sb.Append("<script>\n");
            sb.Append(@"
function copyText(text, elem) {
    navigator.clipboard.writeText(text).then(function() {
        const orig = elem.innerHTML;
        elem.innerHTML = '<span>Скопировано!</span>';
        setTimeout(() => { elem.innerHTML = orig; }, 1500);
    });
}
function copyConsoleLogs() {
    const el = document.getElementById('consoleLogs');
    if (!el) return;
    const text = el.innerText;
    navigator.clipboard.writeText(text).then(function() {
        alert('Консольный лог скопирован в буфер обмена!');
    });
}
</script>\n");

            sb.Append("</body>\n</html>");

            return sb.ToString();
        }

        public static string SaveReport(ReportModel model)
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string logsDir = Path.Combine(baseDir, "logs");
                if (!Directory.Exists(logsDir))
                {
                    Directory.CreateDirectory(logsDir);
                }

                string fileName = $"Report_{DateTime.Now:yyyyMMdd_HHmmss}_{model.ReportId ?? "AM"}.html";
                string fullPath = Path.Combine(logsDir, fileName);

                string html = GenerateHtml(model);
                File.WriteAllText(fullPath, html, Encoding.UTF8);
                return fullPath;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to save HTML report: {ex.Message}");
                return null;
            }
        }

        public static void OpenReportInBrowser(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return;
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = filePath,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to open HTML report: {ex.Message}");
            }
        }

        public static void GenerateAndOpen(ReportModel model)
        {
            string path = SaveReport(model);
            if (!string.IsNullOrEmpty(path))
            {
                OpenReportInBrowser(path);
            }
        }
    }
}
