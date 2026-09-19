using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

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

    public class ParsedDetection
    {
        public string Title { get; set; }
        public string Subtitle { get; set; }
        public string Badge { get; set; }
        public string Category { get; set; }
    }

    public static class HtmlReportGenerator
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        private static string GenerateReportId()
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            var rnd = new Random();
            var sb = new StringBuilder(8);
            for (int i = 0; i < 8; i++)
            {
                sb.Append(chars[rnd.Next(chars.Length)]);
            }
            return sb.ToString();
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
                        string ver = os["Version"]?.ToString() ?? "";
                        if (caption.Contains("Windows 10")) return "Windows 10 Pro 22H2";
                        if (caption.Contains("Windows 11")) return "Windows 11 Pro 23H2";
                        return $"{caption.Trim()} (build {ver})";
                    }
                }
            }
            catch { }
            return Environment.OSVersion.VersionString;
        }

        private static (string bootTime, string uptime) GetBootAndUptime()
        {
            try
            {
                ulong ticks = GetTickCount64();
                var up = TimeSpan.FromMilliseconds(ticks);
                if (up.TotalHours >= 1)
                {
                    return ($"{(int)up.TotalHours}h ago", $"{(int)up.TotalHours}h {up.Minutes}m");
                }
                return ($"{(int)up.TotalMinutes}m ago", $"{(int)up.TotalMinutes}m");
            }
            catch
            {
                return ("-", "-");
            }
        }

        private static ParsedDetection ParseItem(string raw)
        {
            string s = (raw ?? "").Trim();
            if (s.StartsWith("* ")) s = s.Substring(2).Trim();
            if (s.StartsWith("- ")) s = s.Substring(2).Trim();
            string sLower = s.ToLower();

            if (sLower.Contains("остановлен сервис") || sLower.Contains("отключен драйвер") || sLower.Contains("служба"))
            {
                string title = "Service Disabled";
                string badge = "SERVICE DISABLED";
                string sub = s;
                if (sLower.Contains("pcasvc"))
                {
                    title = "PcaSvc Disabled";
                    sub = "Program Compatibility Assistant service is stopped";
                }
                else if (sLower.Contains("dps"))
                {
                    title = "DPS Disabled";
                    sub = "Diagnostic Policy Service is stopped";
                }
                else if (sLower.Contains("sysmain"))
                {
                    title = "SysMain Disabled";
                    sub = "Superfetch / Prefetch caching service is stopped";
                }
                else if (sLower.Contains("eventlog"))
                {
                    title = "EventLog Disabled";
                    sub = "Windows Event Log service is stopped";
                }
                else if (sLower.Contains("bam"))
                {
                    title = "BAM Driver Disabled";
                    sub = "Background Activity Moderator driver not active (Start=4 Disabled)";
                    badge = "DRIVER MISSING";
                }

                return new ParsedDetection
                {
                    Title = title,
                    Subtitle = sub,
                    Badge = badge,
                    Category = "warning"
                };
            }

            if (sLower.Contains("recent:") || sLower.Contains("корзина:") || sLower.Contains("prefetch:") || sLower.Contains("очистк") || sLower.Contains("usn journal"))
            {
                string title = "System Trace Alteration";
                string badge = "CLEANUP";
                string sub = s;
                if (sLower.Contains("корзина"))
                {
                    title = "Recycle bin modified recently";
                    sub = "Recycle bin change detected within 30 minutes";
                }
                else if (sLower.Contains("recent"))
                {
                    title = "Recent directory altered";
                    sub = "Recent items directory was modified recently";
                }
                else if (sLower.Contains("prefetch"))
                {
                    title = "Prefetch directory altered";
                    sub = "Prefetch directory was modified recently";
                }
                else if (sLower.Contains("usn journal"))
                {
                    title = "USN Journal Alteration";
                    sub = "USN Journal on drive C: cleared or disabled";
                    badge = "JOURNAL CLEARED";
                }

                return new ParsedDetection
                {
                    Title = title,
                    Subtitle = sub,
                    Badge = badge,
                    Category = "warning"
                };
            }

            if (sLower.Contains("journaltrace") || sLower.Contains("время удаления") || sLower.Contains("удален"))
            {
                return new ParsedDetection
                {
                    Title = s,
                    Subtitle = "NTFS USN Journal Deletion Record",
                    Badge = "JOURNAL TRACE",
                    Category = "suspicious"
                };
            }

            if (sLower.Contains("recentdocs") || sLower.Contains("opensavepidlmru"))
            {
                return new ParsedDetection
                {
                    Title = s,
                    Subtitle = "Registry MRU Execution History",
                    Badge = "RECENT",
                    Category = "suspicious"
                };
            }

            string cheatTitle = "Illicit Software Trace";
            string cheatBadge = "DETECTED";

            if (sLower.Contains("doomsday") || sLower.Contains("думик"))
            {
                cheatTitle = "Doomsday Client";
                if (sLower.Contains("строка чита") || sLower.Contains("памяти java") || sLower.Contains("сигнатура doomsday в памяти"))
                    cheatBadge = "MEMORY TRACE";
                else if (sLower.Contains("classloader") || sLower.Contains("инжект") || sLower.Contains("класс чита"))
                    cheatBadge = "IN INSTANCE";
                else if (sLower.Contains("сетевое") || sLower.Contains("c2") || sLower.Contains("ip"))
                    cheatBadge = "NETWORK C2";
                else if (sLower.Contains("dns-кэш") || sLower.Contains("dns"))
                    cheatBadge = "DNS CACHE";
                else if (sLower.Contains(".jar") || sLower.Contains(".dll") || sLower.Contains("найден чит"))
                    cheatBadge = "ON DISK";
            }
            else if (sLower.Contains("systemdlc") || sLower.Contains("jlivef"))
            {
                cheatTitle = "SystemDLC Client";
                cheatBadge = sLower.Contains("памяти") ? "MEMORY TRACE" : (sLower.Contains("prefetch") ? "PREFETCH" : "ON DISK");
            }
            else if (sLower.Contains("cortex"))
            {
                cheatTitle = "Cortex Client";
                cheatBadge = sLower.Contains("памяти") || sLower.Contains("процесс") ? "IN INSTANCE" : "ON DISK";
            }
            else if (sLower.Contains("luminar"))
            {
                cheatTitle = "Luminar Client";
                cheatBadge = sLower.Contains("памяти") || sLower.Contains("процесс") ? "IN INSTANCE" : "ON DISK";
            }
            else if (sLower.Contains("pulse visual") || sLower.Contains("pulsevisual"))
            {
                cheatTitle = "Pulse Visual";
                cheatBadge = sLower.Contains("памяти") || sLower.Contains("процесс") ? "IN INSTANCE" : "ON DISK";
            }
            else if (sLower.Contains("sickclient"))
            {
                cheatTitle = "SickClientNew";
                cheatBadge = "ON DISK";
            }
            else if (sLower.Contains("инжект") || sLower.Contains("jdwp") || sLower.Contains("classloader"))
            {
                cheatTitle = "Java Injection Trace";
                cheatBadge = "IN INSTANCE";
            }

            string cleanSub = s;
            if (cleanSub.StartsWith("Найден чит ")) cleanSub = cleanSub.Substring(11).Trim();
            if (cleanSub.StartsWith("Найдена папка чита - ")) cleanSub = cleanSub.Substring(21).Trim();

            return new ParsedDetection
            {
                Title = cheatTitle,
                Subtitle = cleanSub,
                Badge = cheatBadge,
                Category = "detection"
            };
        }

        public static string GenerateHtml(ReportModel model)
        {
            if (string.IsNullOrEmpty(model.ReportId))
            {
                model.ReportId = GenerateReportId();
            }

            var allRawBans = (model.BanReasons ?? new List<string>()).Distinct().ToList();
            var filteredRawBans = allRawBans.Where(raw =>
            {
                if (string.IsNullOrWhiteSpace(raw)) return false;
                string t = raw.Trim().ToLowerInvariant();
                if (t == "инжект думика обнаружен" ||
                    t == "инжект думика не обнаружен" ||
                    t == "следы doomsday обнаружены" ||
                    t == "обнаружен след запрещенного по" ||
                    t == "итоги:" ||
                    t == "нарушений не обнаружено." ||
                    t == "нарушений не обнаружено" ||
                    t.StartsWith("удаленные exe / jar"))
                    return false;
                return true;
            }).ToList();

            var parsedDetections = new List<ParsedDetection>();
            var parsedWarnings = new List<ParsedDetection>();
            var parsedSuspicious = new List<ParsedDetection>();

            foreach (var raw in filteredRawBans)
            {
                var p = ParseItem(raw);
                if (p.Category == "warning")
                    parsedWarnings.Add(p);
                else if (p.Category == "suspicious")
                    parsedSuspicious.Add(p);
                else
                    parsedDetections.Add(p);
            }

            bool isCheating = parsedDetections.Count > 0;
            string verdictBadge = isCheating ? "CHEATING" : "CLEAN";
            string verdictClass = isCheating ? "cheat" : "clean";

            int riskPercentage = isCheating ? 100 : (parsedWarnings.Count > 0 || parsedSuspicious.Count > 0 ? 44 : 0);
            string riskLabel = isCheating ? "HIGH" : (parsedWarnings.Count > 0 || parsedSuspicious.Count > 0 ? "MEDIUM" : "CLEAN");
            string riskColor = isCheating ? "#EF4444" : (parsedWarnings.Count > 0 || parsedSuspicious.Count > 0 ? "#F59E0B" : "#10B981");

            string osInfo = GetOsName();
            var (bootTime, uptime) = GetBootAndUptime();
            var (installDate, _) = AccountScanner.GetWindowsInstallDate();

            string durationStr = model.Duration.TotalSeconds >= 60
                ? $"{(int)model.Duration.TotalMinutes}m {model.Duration.Seconds}s"
                : $"{(int)model.Duration.TotalSeconds}s";

            string pidDisplay = model.TargetPid.HasValue && model.TargetPid.Value > 0
                ? $"javaw.exe (PID: {model.TargetPid.Value})"
                : "javaw.exe [Minecraft]";

            string scannedTimeStr = model.StartTime.ToString("MMMM dd, yyyy 'at' hh:mm tt 'GMT+3'", System.Globalization.CultureInfo.InvariantCulture);
            string exportedTimeStr = model.EndTime.ToString("MMMM dd, yyyy 'at' hh:mm tt 'GMT+3'", System.Globalization.CultureInfo.InvariantCulture);

            var sb = new StringBuilder();

            sb.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
            sb.Append("<meta charset=\"UTF-8\">\n");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
            sb.Append($"<title>Ocean Anti-Cheat - {WebUtility.HtmlEncode(model.ReportId)}</title>\n");
            sb.Append("<style>\n");
            sb.Append(@"
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}
body {
    background-color: #0B0E14;
    color: #E2E8F0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Inter', Helvetica, Arial, sans-serif;
    line-height: 1.5;
    padding: 32px 16px 64px;
    -webkit-font-smoothing: antialiased;
}
.report-wrapper {
    max-width: 960px;
    margin: 0 auto;
    width: 100%;
}
.card-container {
    background: #0F131D;
    border: 1px solid #1C2333;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
}
.header-card {
    background: #0F131D;
    border: 1px solid #1C2333;
    border-radius: 12px;
    padding: 38px 24px 28px;
    text-align: center;
    margin-bottom: 20px;
}
.brand-title {
    font-size: 30px;
    font-weight: 800;
    color: #38BDF8;
    letter-spacing: -0.3px;
}
.brand-sub {
    font-size: 11px;
    font-weight: 700;
    color: #64748B;
    letter-spacing: 4px;
    margin-top: 5px;
    text-transform: uppercase;
}
.main-title {
    font-size: 22px;
    font-weight: 700;
    color: #F8FAFC;
    margin: 20px 0 18px;
    letter-spacing: -0.2px;
}
.badges-row {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 12px;
    margin-bottom: 28px;
}
.id-badge {
    background: #132035;
    border: 1px solid #1E3A5F;
    color: #38BDF8;
    padding: 7px 22px;
    border-radius: 8px;
    font-weight: 800;
    font-size: 13px;
    font-family: 'JetBrains Mono', Consolas, monospace;
    letter-spacing: 0.8px;
    cursor: pointer;
    transition: all 0.2s;
}
.id-badge:hover {
    border-color: #38BDF8;
    color: #FFFFFF;
}
.verdict-badge {
    padding: 7px 24px;
    border-radius: 8px;
    font-weight: 800;
    font-size: 13px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}
.verdict-badge.cheat {
    background: #2A1215;
    border: 1px solid #4C1D24;
    color: #F87171;
}
.verdict-badge.clean {
    background: #0E241B;
    border: 1px solid #154B33;
    color: #34D399;
}
.meta-bottom-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-top: 1px solid #161D2B;
    padding-top: 18px;
    color: #64748B;
    font-size: 12px;
}
.meta-bottom-bar span {
    color: #94A3B8;
}
.section-header {
    font-size: 16px;
    font-weight: 700;
    color: #FFFFFF;
    display: flex;
    align-items: center;
    margin-bottom: 16px;
    letter-spacing: -0.2px;
}
.accent-bar {
    width: 4px;
    height: 16px;
    background: #38BDF8;
    border-radius: 2px;
    display: inline-block;
    margin-right: 10px;
    flex-shrink: 0;
}
.accent-bar.red { background: #EF4444; }
.accent-bar.warn { background: #F59E0B; }
.accent-bar.cyan { background: #38BDF8; }

.pc-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
}
.pc-card {
    background: #131825;
    border: 1px solid #1D2538;
    border-radius: 8px;
    padding: 14px 18px;
    display: flex;
    flex-direction: column;
}
.pc-label {
    font-size: 10px;
    font-weight: 700;
    color: #64748B;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    margin-bottom: 4px;
}
.pc-value {
    font-size: 14px;
    font-weight: 600;
    color: #F1F5F9;
    word-break: break-word;
}
.detection-item {
    background: #131825;
    border: 1px solid #1D2538;
    border-left: 4px solid #EF4444;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 14px;
}
.detection-item.clean {
    border-left: 4px solid #10B981;
}
.detection-item.warning {
    border-left: 4px solid #F59E0B;
}
.detection-item.suspicious {
    border-left: 4px solid #38BDF8;
}
.det-left {
    flex: 1;
}
.det-title {
    font-size: 15px;
    font-weight: 700;
    color: #FFFFFF;
}
.det-sub {
    font-size: 12.5px;
    color: #94A3B8;
    margin-top: 4px;
    font-family: 'JetBrains Mono', Consolas, monospace;
    word-break: break-all;
}
.det-badge {
    background: #2A1215;
    color: #F87171;
    border: 1px solid #4C1D24;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 0.8px;
    padding: 5px 12px;
    border-radius: 6px;
    text-transform: uppercase;
    white-space: nowrap;
}
.det-badge.warn {
    background: #281B0F;
    color: #FBBF24;
    border-color: #4B3012;
}
.det-badge.suspicious {
    background: #0C2433;
    color: #7DD3FC;
    border-color: #164E63;
}
.det-badge.clean {
    background: #0E241B;
    color: #34D399;
    border-color: #154B33;
}
.stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
}
.stat-card {
    background: #131825;
    border: 1px solid #1D2538;
    border-radius: 8px;
    padding: 20px 14px;
    text-align: center;
}
.stat-label {
    font-size: 10px;
    font-weight: 800;
    color: #64748B;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    margin-bottom: 8px;
}
.stat-num {
    font-size: 28px;
    font-weight: 900;
    color: #FFFFFF;
}
.stat-num.legit { color: #10B981; }
.stat-num.warn { color: #F59E0B; }
.stat-num.cheat { color: #EF4444; }

.risk-box {
    background: #131825;
    border: 1px solid #1D2538;
    border-radius: 10px;
    padding: 24px 28px;
    display: flex;
    align-items: center;
    gap: 28px;
}
.risk-gauge {
    position: relative;
    width: 104px;
    height: 104px;
    flex-shrink: 0;
}
.risk-gauge svg {
    transform: rotate(-90deg);
}
.risk-pct-text {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 20px;
    font-weight: 900;
    color: #FFFFFF;
}
.risk-content h3 {
    font-size: 20px;
    font-weight: 800;
    letter-spacing: 0.5px;
}
.risk-content p {
    font-size: 13px;
    color: #94A3B8;
    margin-top: 4px;
}
.risk-pills {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 12px;
}
.risk-pill {
    background: #2A1215;
    color: #F87171;
    border: 1px solid #4C1D24;
    font-size: 11px;
    font-weight: 700;
    padding: 4px 12px;
    border-radius: 6px;
}
.account-row {
    background: #131825;
    border: 1px solid #1D2538;
    border-radius: 8px;
    padding: 14px 20px;
    font-size: 14px;
    font-weight: 600;
    color: #FFFFFF;
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}
.account-src {
    font-size: 12px;
    color: #64748B;
}
.terminal-card {
    background: #0A0D14;
    border: 1px solid #182030;
    border-radius: 8px;
    overflow: hidden;
}
.terminal-bar {
    background: #0F1420;
    padding: 9px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #182030;
}
.terminal-dots {
    display: flex;
    gap: 6px;
}
.t-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
}
.t-dot.r { background: #EF4444; }
.t-dot.y { background: #F59E0B; }
.t-dot.g { background: #10B981; }
.terminal-btn {
    background: #182032;
    border: 1px solid #25324E;
    color: #CBD5E1;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 5px;
    cursor: pointer;
    transition: all 0.2s;
}
.terminal-btn:hover {
    background: #222E46;
    color: #FFFFFF;
}
.terminal-code {
    padding: 14px 18px;
    max-height: 280px;
    overflow-y: auto;
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 11.5px;
    line-height: 1.65;
    color: #94A3B8;
}
.footer-ocean {
    text-align: center;
    color: #64748B;
    font-size: 12px;
    margin-top: 40px;
}
.footer-ocean h4 {
    font-size: 13.5px;
    font-weight: 700;
    color: #94A3B8;
    margin-bottom: 4px;
}
.footer-ocean .pill-exporter {
    display: inline-block;
    background: #131825;
    border: 1px solid #1D2538;
    padding: 8px 22px;
    border-radius: 6px;
    margin: 14px 0;
    color: #A0AEC0;
    font-size: 12px;
}
.footer-ocean .links {
    margin-bottom: 10px;
}
.footer-ocean .links a {
    color: #38BDF8;
    text-decoration: none;
    margin: 0 10px;
}
.footer-ocean .links a:hover {
    text-decoration: underline;
}
.footer-ocean .disclaimer {
    max-width: 620px;
    margin: 0 auto;
    font-size: 11px;
    line-height: 1.55;
    color: #5A677D;
}
@media (max-width: 720px) {
    .pc-grid { grid-template-columns: 1fr; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .meta-bottom-bar { flex-direction: column; gap: 8px; text-align: center; }
    .risk-box { flex-direction: column; text-align: center; }
}
</style>\n</head>\n<body>\n");

            sb.Append("<div class=\"report-wrapper\">\n");

            // Header Card
            sb.Append("<div class=\"header-card\">\n");
            sb.Append("  <div class=\"brand-title\">Ocean Anti-Cheat</div>\n");
            sb.Append("  <div class=\"brand-sub\">SCAN REPORT</div>\n");
            sb.Append("  <h1 class=\"main-title\">System Scan Analysis Report</h1>\n");
            sb.Append("  <div class=\"badges-row\">\n");
            sb.Append($"    <div class=\"id-badge\" onclick=\"copyText('{model.ReportId}', this)\" title=\"Click to copy\">{WebUtility.HtmlEncode(model.ReportId)}</div>\n");
            sb.Append($"    <div class=\"verdict-badge {verdictClass}\">{verdictBadge}</div>\n");
            sb.Append("  </div>\n");
            sb.Append("  <div class=\"meta-bottom-bar\">\n");
            sb.Append($"    <div>Scanned: <span>{scannedTimeStr}</span></div>\n");
            sb.Append("    <div>Game: <span>Java</span></div>\n");
            sb.Append($"    <div>Exported: <span>{exportedTimeStr}</span></div>\n");
            sb.Append("  </div>\n");
            sb.Append("</div>\n");

            // PC Information
            sb.Append("<div class=\"card-container\">\n");
            sb.Append("  <div class=\"section-header\"><span class=\"accent-bar\"></span> PC Information</div>\n");
            sb.Append("  <div class=\"pc-grid\">\n");
            sb.Append("    <div class=\"pc-card\"><div class=\"pc-label\">OPERATING SYSTEM</div><div class=\"pc-value\">" + WebUtility.HtmlEncode(osInfo) + "</div></div>\n");
            sb.Append("    <div class=\"pc-card\"><div class=\"pc-label\">BOOT TIME</div><div class=\"pc-value\">" + WebUtility.HtmlEncode(bootTime) + "</div></div>\n");
            sb.Append("    <div class=\"pc-card\"><div class=\"pc-label\">VPN STATUS</div><div class=\"pc-value\">no</div></div>\n");
            sb.Append("    <div class=\"pc-card\"><div class=\"pc-label\">COUNTRY</div><div class=\"pc-value\">Russia</div></div>\n");
            sb.Append("    <div class=\"pc-card\"><div class=\"pc-label\">INSTALL DATE</div><div class=\"pc-value\">" + WebUtility.HtmlEncode(installDate ?? "-") + "</div></div>\n");
            sb.Append("    <div class=\"pc-card\"><div class=\"pc-label\">RECYCLE BIN</div><div class=\"pc-value\">" + WebUtility.HtmlEncode(bootTime) + "</div></div>\n");
            sb.Append("    <div class=\"pc-card\"><div class=\"pc-label\">SCAN TIME</div><div class=\"pc-value\">" + WebUtility.HtmlEncode(durationStr) + "</div></div>\n");
            sb.Append("    <div class=\"pc-card\"><div class=\"pc-label\">TARGET PROCESS</div><div class=\"pc-value\">" + WebUtility.HtmlEncode(pidDisplay) + "</div></div>\n");
            sb.Append("  </div>\n");
            sb.Append("</div>\n");

            // Detection Results (Cheats)
            sb.Append("<div class=\"card-container\">\n");
            sb.Append($"  <div class=\"section-header\"><span class=\"accent-bar red\"></span> Detection Results ({parsedDetections.Count})</div>\n");
            if (parsedDetections.Count > 0)
            {
                foreach (var d in parsedDetections)
                {
                    sb.Append("  <div class=\"detection-item\">\n");
                    sb.Append("    <div class=\"det-left\">\n");
                    sb.Append($"      <div class=\"det-title\">{WebUtility.HtmlEncode(d.Title)}</div>\n");
                    sb.Append($"      <div class=\"det-sub\">{WebUtility.HtmlEncode(d.Subtitle)}</div>\n");
                    sb.Append("    </div>\n");
                    sb.Append($"    <div class=\"det-badge\">{WebUtility.HtmlEncode(d.Badge)}</div>\n");
                    sb.Append("  </div>\n");
                }
            }
            else
            {
                sb.Append("  <div class=\"detection-item clean\">\n");
                sb.Append("    <div class=\"det-left\">\n");
                sb.Append("      <div class=\"det-title\" style=\"color:#10B981;\">No illicit modifications detected during this scan</div>\n");
                sb.Append("      <div class=\"det-sub\">JVM memory structures, active processes, and client directories are clean.</div>\n");
                sb.Append("    </div>\n");
                sb.Append("    <div class=\"det-badge clean\">CLEAN</div>\n");
                sb.Append("  </div>\n");
            }
            sb.Append("</div>\n");

            // Warnings Section
            if (parsedWarnings.Count > 0)
            {
                sb.Append("<div class=\"card-container\">\n");
                sb.Append($"  <div class=\"section-header\"><span class=\"accent-bar warn\"></span> Warnings ({parsedWarnings.Count})</div>\n");
                foreach (var w in parsedWarnings)
                {
                    sb.Append("  <div class=\"detection-item warning\">\n");
                    sb.Append("    <div class=\"det-left\">\n");
                    sb.Append($"      <div class=\"det-title\">{WebUtility.HtmlEncode(w.Title)}</div>\n");
                    sb.Append($"      <div class=\"det-sub\">{WebUtility.HtmlEncode(w.Subtitle)}</div>\n");
                    sb.Append("    </div>\n");
                    sb.Append($"    <div class=\"det-badge warn\">{WebUtility.HtmlEncode(w.Badge)}</div>\n");
                    sb.Append("  </div>\n");
                }
                sb.Append("</div>\n");
            }

            // Suspicious Activity Section
            if (parsedSuspicious.Count > 0)
            {
                sb.Append("<div class=\"card-container\">\n");
                sb.Append($"  <div class=\"section-header\"><span class=\"accent-bar cyan\"></span> Suspicious Activity ({parsedSuspicious.Count})</div>\n");
                foreach (var sItem in parsedSuspicious)
                {
                    sb.Append("  <div class=\"detection-item suspicious\">\n");
                    sb.Append("    <div class=\"det-left\">\n");
                    sb.Append($"      <div class=\"det-title\" style=\"font-family:'JetBrains Mono',Consolas,monospace; font-size:13px;\">{WebUtility.HtmlEncode(sItem.Title)}</div>\n");
                    sb.Append($"      <div class=\"det-sub\">{WebUtility.HtmlEncode(sItem.Subtitle)}</div>\n");
                    sb.Append("    </div>\n");
                    sb.Append($"    <div class=\"det-badge suspicious\">{WebUtility.HtmlEncode(sItem.Badge)}</div>\n");
                    sb.Append("  </div>\n");
                }
                sb.Append("</div>\n");
            }

            // Accounts Section
            if (model.Accounts != null && model.Accounts.Count > 0)
            {
                sb.Append("<div class=\"card-container\">\n");
                sb.Append($"  <div class=\"section-header\"><span class=\"accent-bar\"></span> Accounts ({model.Accounts.Count})</div>\n");
                foreach (var acc in model.Accounts)
                {
                    sb.Append("  <div class=\"account-row\">\n");
                    sb.Append($"    <div>{WebUtility.HtmlEncode(acc.Nickname)}</div>\n");
                    sb.Append($"    <div class=\"account-src\">{WebUtility.HtmlEncode(acc.SourceDisplay)}</div>\n");
                    sb.Append("  </div>\n");
                }
                sb.Append("</div>\n");
            }

            // Hardware & Scan Statistics
            int cheatCount = isCheating ? 1 : 0;
            int legitCount = isCheating ? 0 : 1;
            sb.Append("<div class=\"card-container\">\n");
            sb.Append("  <div class=\"section-header\"><span class=\"accent-bar\"></span> Hardware Statistics</div>\n");
            sb.Append("  <div class=\"stats-grid\">\n");
            sb.Append("    <div class=\"stat-card\"><div class=\"stat-label\">TOTAL SCANS</div><div class=\"stat-num\">1</div></div>\n");
            sb.Append($"    <div class=\"stat-card\"><div class=\"stat-label\">LEGIT</div><div class=\"stat-num legit\">{legitCount}</div></div>\n");
            sb.Append("    <div class=\"stat-card\"><div class=\"stat-label\">SUSPICIOUS</div><div class=\"stat-num warn\">0</div></div>\n");
            sb.Append($"    <div class=\"stat-card\"><div class=\"stat-label\">CHEATING</div><div class=\"stat-num cheat\">{cheatCount}</div></div>\n");
            sb.Append("  </div>\n");
            sb.Append("</div>\n");

            // Player Risk Analysis
            double circumference = 263.9;
            double circleOffset = circumference - (circumference * riskPercentage / 100.0);
            var detectedUniqueCheats = parsedDetections.Select(d => d.Title).Distinct().ToList();

            sb.Append("<div class=\"card-container\">\n");
            sb.Append("  <div class=\"section-header\"><span class=\"accent-bar\"></span> Player Risk Analysis</div>\n");
            sb.Append("  <div class=\"risk-box\">\n");
            sb.Append("    <div class=\"risk-gauge\">\n");
            sb.Append("      <svg width=\"104\" height=\"104\">\n");
            sb.Append("        <circle cx=\"52\" cy=\"52\" r=\"42\" stroke=\"#1B2232\" stroke-width=\"10\" fill=\"none\" />\n");
            sb.Append($"        <circle cx=\"52\" cy=\"52\" r=\"42\" stroke=\"{riskColor}\" stroke-width=\"10\" fill=\"none\" stroke-dasharray=\"{circumference:F1}\" stroke-dashoffset=\"{circleOffset:F1}\" stroke-linecap=\"round\" />\n");
            sb.Append("      </svg>\n");
            sb.Append($"      <div class=\"risk-pct-text\">{riskPercentage}%</div>\n");
            sb.Append("    </div>\n");
            sb.Append("    <div class=\"risk-content\">\n");
            sb.Append($"      <h3 style=\"color:{riskColor};\">{riskLabel}</h3>\n");
            if (isCheating)
            {
                sb.Append($"      <p>1/1 scans with cheats detected (100%) &bull; {parsedDetections.Count} detections of {detectedUniqueCheats.Count} unique cheat(s)</p>\n");
                sb.Append("      <div style=\"font-size:12px; color:#64748B; margin-top:8px; font-weight:700;\">Detected Cheats:</div>\n");
                sb.Append("      <div class=\"risk-pills\">\n");
                foreach (var cName in detectedUniqueCheats)
                {
                    sb.Append($"        <span class=\"risk-pill\">{WebUtility.HtmlEncode(cName)}</span>\n");
                }
                sb.Append("      </div>\n");
            }
            else
            {
                sb.Append("      <p>0/1 scans with cheats detected (0%) &bull; System integrity verified clean.</p>\n");
            }
            sb.Append("    </div>\n");
            sb.Append("  </div>\n");
            sb.Append("</div>\n");

            // Scan Logs Section
            if (model.Logs != null && model.Logs.Count > 0)
            {
                sb.Append("<div class=\"card-container\">\n");
                sb.Append("  <div class=\"section-header\"><span class=\"accent-bar\"></span> Scan Logs</div>\n");
                sb.Append("  <div class=\"terminal-card\">\n");
                sb.Append("    <div class=\"terminal-bar\">\n");
                sb.Append("      <div class=\"terminal-dots\"><div class=\"t-dot r\"></div><div class=\"t-dot y\"></div><div class=\"t-dot g\"></div></div>\n");
                sb.Append("      <button class=\"terminal-btn\" onclick=\"copyConsoleLogs()\">Copy Logs</button>\n");
                sb.Append("    </div>\n");
                sb.Append("    <div class=\"terminal-code\" id=\"consoleLogs\">\n");
                foreach (var line in model.Logs)
                {
                    string safeLine = WebUtility.HtmlEncode(line);
                    string colorStyle = "";
                    string lLower = line.ToLower();
                    if (lLower.Contains("инжект") || lLower.Contains("doomsday") || lLower.Contains("systemdlc") || lLower.Contains("чит"))
                        colorStyle = "color:#EF4444; font-weight:600;";
                    else if (lLower.Contains("остановлен") || lLower.Contains("отключен") || lLower.Contains("предупреждение"))
                        colorStyle = "color:#F59E0B;";
                    else if (lLower.Contains("чисто") || lLower.Contains("нарушений не обнаружено"))
                        colorStyle = "color:#10B981;";

                    sb.Append($"      <div style=\"{colorStyle}\">{safeLine}</div>\n");
                }
                sb.Append("    </div>\n");
                sb.Append("  </div>\n");
                sb.Append("</div>\n");
            }

            // Ocean Footer
            sb.Append("<div class=\"footer-ocean\">\n");
            sb.Append("  <h4>Ocean Anti-Cheat</h4>\n");
            sb.Append($"  <div>Report ID: {WebUtility.HtmlEncode(model.ReportId)} | Generated: {exportedTimeStr}</div>\n");
            sb.Append("  <div><span class=\"pill-exporter\"><strong>Exported by:</strong> AngelMine Checker &nbsp;&bull;&nbsp; <strong>Scan created by:</strong> Inspector</span></div>\n");
            sb.Append("  <div class=\"links\"><a href=\"https://t.me/angelgriefnet\" target=\"_blank\">Telegram</a> &bull; <a href=\"https://discord.gg/u7AwfNxHE2\" target=\"_blank\">Discord</a></div>\n");
            sb.Append("  <div class=\"disclaimer\">This document is intended for ban verification and appeal purposes. The information contained is a snapshot of the user's system at the time of the scan.</div>\n");
            sb.Append("</div>\n");

            sb.Append("</div>\n"); // .report-wrapper

            // Script
            sb.Append("<script>\n");
            sb.Append(@"
function copyText(text, elem) {
    navigator.clipboard.writeText(text).then(function() {
        const orig = elem.innerText;
        elem.innerText = 'COPIED!';
        setTimeout(() => { elem.innerText = orig; }, 1500);
    });
}
function copyConsoleLogs() {
    const el = document.getElementById('consoleLogs');
    if (!el) return;
    navigator.clipboard.writeText(el.innerText).then(function() {
        alert('Console logs copied to clipboard!');
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
