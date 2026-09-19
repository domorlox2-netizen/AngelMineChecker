using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

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

        private static string DecodeSig(string b64)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        }

        public static bool CheckInFile(FileInfo file, out string foundSig)
        {
            foundSig = "";
            if (file == null || !file.Exists) return false;
            if (QuickScanner.IsCheckerOrSelf(file.FullName)) return false;

            string nameLower = file.Name.ToLower();
            string ext = file.Extension.ToLower();
            if (nameLower.StartsWith("+~jf") || ext == ".ttf" || ext == ".otf" || ext == ".woff" || ext == ".woff2")
                return false;

            try
            {
                long len = file.Length;
                if (len == 0 || len > 35 * 1024 * 1024) return false;

                using (var fs = file.OpenRead())
                {
                    byte[] buf = new byte[Math.Min((int)len, 4 * 1024 * 1024)];
                    int read = fs.Read(buf, 0, buf.Length);
                    if (read >= 4)
                    {
                        if ((buf[0] == 0 && buf[1] == 1 && buf[2] == 0 && buf[3] == 0) ||
                            (buf[0] == 'O' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'O') ||
                            (buf[0] == 'w' && buf[1] == 'O' && buf[2] == 'F' && buf[3] == 'F'))
                            return false;
                    }

                    string ascii = Encoding.ASCII.GetString(buf, 0, read);
                    string utf8 = Encoding.UTF8.GetString(buf, 0, read);
                    string unicode = Encoding.Unicode.GetString(buf, 0, read - (read % 2));

                    foreach (var sig in Signatures)
                    {
                        if (ascii.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0 ||
                            utf8.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0 ||
                            unicode.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0)
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

        public static void Scan(Action<string> log, List<string> banReasons)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string[] probeDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            };

            foreach (var dir in probeDirs)
            {
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var sub in Directory.GetDirectories(dir))
                    {
                        if (QuickScanner.IsCheckerOrSelf(sub)) continue;
                        string subName = Path.GetFileName(sub).ToLower();
                        if (subName.Contains("jlivef") || subName.Contains("systemdlc"))
                        {
                            if (!seen.Contains(sub))
                            {
                                seen.Add(sub);
                                log($"Найден: Папка {Path.GetFileName(sub)} ({sub})");
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
                        string fName = Path.GetFileName(f).ToLower();

                        if (fName.Contains("jlivef") || fName.Contains("systemdlc") || fName.Contains("psexec"))
                        {
                            if (!seen.Contains(f))
                            {
                                seen.Add(f);
                                log($"Найден: Файл {Path.GetFileName(f)} ({f})");
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
                                    if (!seen.Contains(f))
                                    {
                                        seen.Add(f);
                                        log($"Найден след SystemDLC в файле: {Path.GetFileName(f)} (сигнатура {foundSig})");
                                        banReasons.Add($"Найден SystemDLC - {f} (сигнатура: {foundSig})");
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            try
            {
                string prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                if (Directory.Exists(prefetchDir))
                {
                    foreach (var pf in Directory.GetFiles(prefetchDir, "*.pf"))
                    {
                        string pfName = Path.GetFileName(pf).ToLower();
                        if (pfName.Contains("jlivef") || pfName.Contains("systemdlc") || pfName.Contains("psexec"))
                        {
                            var fi = new FileInfo(pf);
                            if (!seen.Contains(fi.Name))
                            {
                                seen.Add(fi.Name);
                                log($"Найден запуск в Prefetch: {fi.Name} (время: {fi.LastWriteTime:dd.MM.yyyy HH:mm:ss})");
                                banReasons.Add($"Найден запуск чита в Prefetch - {fi.Name}");
                            }
                        }
                    }
                }
            }
            catch { }
        }
    }
}
