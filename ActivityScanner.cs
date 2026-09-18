using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace AngelMineChecker
{
    public static class ActivityScanner
    {
        public static (bool isRunning, bool isRecording, string status, string color) CheckObs()
        {
            try
            {
                var obsNames = new[] { "obs64", "obs32", "obs", "Streamlabs OBS" };
                bool isRunning = false;
                foreach (var name in obsNames)
                {
                    if (Process.GetProcessesByName(name).Length > 0)
                    {
                        isRunning = true;
                        break;
                    }
                }

                if (!isRunning)
                {
                    return (false, false, "Не идет запись", "#94A3B8");
                }

                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string obsLogsDir = Path.Combine(appData, "obs-studio", "basic", "logs");
                if (Directory.Exists(obsLogsDir))
                {
                    var dir = new DirectoryInfo(obsLogsDir);
                    var latestLog = dir.GetFiles("*.txt")
                        .OrderByDescending(f => f.LastWriteTime)
                        .FirstOrDefault();

                    if (latestLog != null && (DateTime.Now - latestLog.LastWriteTime).TotalHours < 12)
                    {
                        try
                        {
                            using (var fs = new FileStream(latestLog.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                            using (var reader = new StreamReader(fs))
                            {
                                string content = reader.ReadToEnd();
                                int startIdx = content.LastIndexOf("==== Recording Start", StringComparison.OrdinalIgnoreCase);
                                int stopIdx = content.LastIndexOf("==== Recording Stop", StringComparison.OrdinalIgnoreCase);
                                if (startIdx > stopIdx)
                                {
                                    return (true, true, "Идет запись", "#94A3B8");
                                }
                            }
                        }
                        catch { }
                    }
                }

                string videosDir = Environment.GetFolderPath(Environment.SpecialFolder.MyVideos);
                if (Directory.Exists(videosDir))
                {
                    var dir = new DirectoryInfo(videosDir);
                    var videoFiles = dir.GetFiles()
                        .Where(f => f.Extension.Equals(".mp4", StringComparison.OrdinalIgnoreCase) ||
                                    f.Extension.Equals(".mkv", StringComparison.OrdinalIgnoreCase) ||
                                    f.Extension.Equals(".flv", StringComparison.OrdinalIgnoreCase))
                        .Where(f => (DateTime.Now - f.LastWriteTime).TotalMinutes < 30);

                    foreach (var file in videoFiles)
                    {
                        if (IsFileInUse(file.FullName))
                        {
                            return (true, true, "Идет запись", "#94A3B8");
                        }
                    }
                }

                return (true, false, "Не идет запись", "#94A3B8");
            }
            catch
            {
                return (false, false, "Не идет запись", "#94A3B8");
            }
        }

        private static bool IsFileInUse(string path)
        {
            try
            {
                using (var stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                {
                    return false;
                }
            }
            catch (IOException)
            {
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static (bool isRunning, bool isVoice, bool isStreaming, string status, string color) CheckDiscord()
        {
            try
            {
                var discordProcs = Process.GetProcessesByName("Discord")
                    .Concat(Process.GetProcessesByName("DiscordCanary"))
                    .Concat(Process.GetProcessesByName("DiscordPTB"))
                    .ToList();

                if (discordProcs.Count == 0)
                {
                    return (false, false, false, "Выкл", "#94A3B8");
                }

                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                string[] logCandidates = new[]
                {
                    Path.Combine(appData, "discord", "logs", "renderer_js.log"),
                    Path.Combine(appData, "discordcanary", "logs", "renderer_js.log"),
                    Path.Combine(appData, "discordptb", "logs", "renderer_js.log")
                };

                foreach (var logFile in logCandidates)
                {
                    if (!File.Exists(logFile)) continue;

                    try
                    {
                        using (var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            if (fs.Length == 0) continue;

                            long readLength = Math.Min(fs.Length, 65536);
                            fs.Seek(-readLength, SeekOrigin.End);

                            using (var reader = new StreamReader(fs))
                            {
                                string text = reader.ReadToEnd();
                                string[] lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                                bool voice = false;
                                bool stream = false;

                                foreach (var line in lines)
                                {
                                    if (line.IndexOf("[RTCConnection", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        if (line.IndexOf("default", StringComparison.OrdinalIgnoreCase) >= 0)
                                        {
                                            if (line.IndexOf("=> RTC_CONNECTED", StringComparison.OrdinalIgnoreCase) >= 0)
                                                voice = true;
                                            else if (line.IndexOf("DISCONNECTED", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     line.IndexOf("Destroy RTCConnection", StringComparison.OrdinalIgnoreCase) >= 0)
                                                voice = false;
                                        }

                                        if (line.IndexOf("stream", StringComparison.OrdinalIgnoreCase) >= 0)
                                        {
                                            if (line.IndexOf("=> RTC_CONNECTED", StringComparison.OrdinalIgnoreCase) >= 0)
                                                stream = true;
                                            else if (line.IndexOf("DISCONNECTED", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                     line.IndexOf("Destroy RTCConnection", StringComparison.OrdinalIgnoreCase) >= 0)
                                                stream = false;
                                        }
                                    }
                                }

                                if (stream)
                                {
                                    return (true, voice, true, "Вкл", "#94A3B8");
                                }
                            }
                        }
                    }
                    catch { }
                }

                return (true, false, false, "Выкл", "#94A3B8");
            }
            catch
            {
                return (false, false, false, "Выкл", "#94A3B8");
            }
        }
    }
}
