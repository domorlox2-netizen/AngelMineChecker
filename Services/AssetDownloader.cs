using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace AngelMineChecker
{
    public static class AssetDownloader
    {
        public const string ArchiveUrl = "https://raw.githubusercontent.com/domorlox2-netizen/AngelMineChecker/main/ico-tool.rar";

        public static bool IsDownloading { get; private set; }

        public static bool AreAssetsInstalled()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string toolsDir = Path.Combine(baseDir, "tools");
                if (!Directory.Exists(toolsDir)) return false;

                string jt = Path.Combine(toolsDir, "JournalTrace.exe");
                string ev = Path.Combine(toolsDir, "everything.exe");
                string ev2 = Path.Combine(toolsDir, "Everything.exe");
                string ep = Path.Combine(toolsDir, "ExecutedProgramsList.exe");
                
                return File.Exists(jt) || File.Exists(ev) || File.Exists(ev2) || File.Exists(ep);
            }
            catch
            {
                return false;
            }
        }

        public static async Task<bool> DownloadAndExtractAsync(Action<int> progressCallback, Action<string> statusCallback)
        {
            if (IsDownloading) return false;
            IsDownloading = true;

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string tempRar = Path.Combine(Path.GetTempPath(), "ico-tool-" + Guid.NewGuid().ToString("N") + ".rar");

            try
            {
                statusCallback?.Invoke("Подключение к GitHub...");
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

                using (var client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromMinutes(5);
                    using (var response = await client.GetAsync(ArchiveUrl, HttpCompletionOption.ResponseHeadersRead))
                    {
                        response.EnsureSuccessStatusCode();

                        long totalBytes = response.Content.Headers.ContentLength ?? -1;
                        using (var stream = await response.Content.ReadAsStreamAsync())
                        using (var fs = new FileStream(tempRar, FileMode.Create, FileAccess.Write, FileShare.None, 16384, true))
                        {
                            byte[] buffer = new byte[32768];
                            long totalRead = 0;
                            int bytesRead;

                            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                            {
                                await fs.WriteAsync(buffer, 0, bytesRead);
                                totalRead += bytesRead;

                                if (totalBytes > 0)
                                {
                                    int pct = (int)((totalRead * 100) / totalBytes);
                                    progressCallback?.Invoke(pct);
                                }
                            }
                        }
                    }
                }

                statusCallback?.Invoke("Распаковка архива...");
                bool extracted = ExtractRar(tempRar, baseDir);

                if (extracted)
                {
                    statusCallback?.Invoke("Компоненты готовы");
                    return true;
                }
                else
                {
                    statusCallback?.Invoke("Ошибка распаковки");
                    return false;
                }
            }
            catch (Exception ex)
            {
                statusCallback?.Invoke("Ошибка загрузки");
                try
                {
                    File.AppendAllText(Path.Combine(baseDir, "download_error.log"), $"[{DateTime.Now}] {ex}\r\n");
                }
                catch { }
                return false;
            }
            finally
            {
                try
                {
                    if (File.Exists(tempRar))
                        File.Delete(tempRar);
                }
                catch { }

                IsDownloading = false;
            }
        }

        private static bool ExtractRar(string rarPath, string destinationDir)
        {
            string tarPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "tar.exe");
            if (!File.Exists(tarPath))
                tarPath = "tar.exe";

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = tarPath,
                    Arguments = $"-xf \"{rarPath}\" -C \"{destinationDir}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                using (var proc = Process.Start(psi))
                {
                    if (proc != null)
                    {
                        proc.WaitForExit(90000);
                        if (proc.ExitCode == 0)
                            return true;
                    }
                }
            }
            catch { }

            string[] winRarCandidates = new[]
            {
                @"C:\Program Files\WinRAR\UnRAR.exe",
                @"C:\Program Files\WinRAR\WinRAR.exe",
                @"C:\Program Files (x86)\WinRAR\UnRAR.exe",
                @"C:\Program Files (x86)\WinRAR\WinRAR.exe"
            };

            foreach (var wr in winRarCandidates)
            {
                if (File.Exists(wr))
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = wr,
                            Arguments = $"x -y \"{rarPath}\" \"{destinationDir}\\\"",
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            WindowStyle = ProcessWindowStyle.Hidden
                        };
                        using (var p = Process.Start(psi))
                        {
                            p?.WaitForExit(90000);
                            if (p != null && p.ExitCode == 0) return true;
                        }
                    }
                    catch { }
                }
            }

            string[] sevenZipCandidates = new[]
            {
                @"C:\Program Files\7-Zip\7z.exe",
                @"C:\Program Files (x86)\7-Zip\7z.exe"
            };

            foreach (var sz in sevenZipCandidates)
            {
                if (File.Exists(sz))
                {
                    try
                    {
                        var psi = new ProcessStartInfo
                        {
                            FileName = sz,
                            Arguments = $"x -y \"-o{destinationDir}\" \"{rarPath}\"",
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            WindowStyle = ProcessWindowStyle.Hidden
                        };
                        using (var p = Process.Start(psi))
                        {
                            p?.WaitForExit(90000);
                            if (p != null && p.ExitCode == 0) return true;
                        }
                    }
                    catch { }
                }
            }

            return AreAssetsInstalled();
        }
    }
}
