using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AngelMineChecker
{
    public class AccountRecord
    {
        public string Nickname { get; set; }
        public List<string> Sources { get; set; } = new List<string>();

        public string SourceDisplay => string.Join(", ", Sources.Distinct());
    }

    public static class AccountScanner
    {
        private static readonly HashSet<string> BlacklistedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "release", "snapshot", "fabric", "forge", "optifine", "quilt", "neoforge", "latest",
            "default", "game", "client", "server", "profile", "plain", "ely", "mojang", "microsoft",
            "latest-release", "latest-snapshot", "vanilla", "unknown", "accounts", "profiles",
            "_v1", "_v2", "_v3", "offline", "offline_v1", "offline_v2", "online"
        };

        private static bool IsValidMinecraftNick(string nick)
        {
            if (string.IsNullOrWhiteSpace(nick)) return false;
            nick = nick.Trim();
            if (nick.Length < 3 || nick.Length > 16) return false;
            if (BlacklistedNames.Contains(nick)) return false;
            return Regex.IsMatch(nick, @"^[a-zA-Z0-9_]{3,16}$");
        }

        public static List<AccountRecord> FindAllAccounts()
        {
            var nickToSources = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

            void AddNick(string nick, string source)
            {
                if (!IsValidMinecraftNick(nick)) return;
                nick = nick.Trim();
                if (!nickToSources.TryGetValue(nick, out var set))
                {
                    set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    nickToSources[nick] = set;
                }
                set.Add(source);
            }

            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            string[] legacyPaths = new[]
            {
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game", "tlauncher_profiles.json"),
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "tlauncher_profiles.json"),
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game", "launcher_profiles.json"),
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "launcher_profiles.json"),
                Path.Combine(appData, ".tlegacy", "tlauncher_profiles.json"),
                Path.Combine(appData, ".tlauncher", "legacy.properties")
            };

            foreach (var path in legacyPaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "Legacy Launcher", AddNick);
            }

            string[] tlPaths = new[]
            {
                Path.Combine(appData, ".minecraft", "tlauncher_profiles.json"),
                Path.Combine(appData, ".tlauncher", "tlauncher-2.0.properties"),
                Path.Combine(appData, ".tlauncher", "users.json")
            };

            foreach (var path in tlPaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "TLauncher", AddNick);
            }

            var iasDirs = new[]
            {
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game", "_IAS_ACCOUNTS_DO_NOT_SEND_TO_ANYONE", ".hidden"),
                Path.Combine(appData, ".minecraft", "_IAS_ACCOUNTS_DO_NOT_SEND_TO_ANYONE", ".hidden"),
                Path.Combine(appData, ".pulse", "_IAS_ACCOUNTS_DO_NOT_SEND_TO_ANYONE", ".hidden"),
                Path.Combine(appData, ".visual", "_IAS_ACCOUNTS_DO_NOT_SEND_TO_ANYONE", ".hidden")
            };

            foreach (var dir in iasDirs)
            {
                string datFile = Path.Combine(dir, "accounts_v1.do_not_send_to_anyone");
                if (File.Exists(datFile))
                    ParseIasBinary(datFile, "InGameAccountSwitcher", AddNick);
            }

            string[] iasJsonPaths = new[]
            {
                Path.Combine(appData, ".minecraft", "config", "ias", "accounts.json"),
                Path.Combine(appData, ".minecraft", "config", "InGameAccountSwitcher", "accounts.json"),
                Path.Combine(appData, ".minecraft", "ias.json"),
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game", "config", "ias", "accounts.json")
            };

            foreach (var path in iasJsonPaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "InGameAccountSwitcher", AddNick);
            }

            string lunarPath = Path.Combine(userProfile, ".lunarclient", "settings", "game", "accounts.json");
            if (File.Exists(lunarPath))
                ParseJsonOrProps(lunarPath, "Lunar Client", AddNick);

            string[] badlionPaths = new[]
            {
                Path.Combine(appData, "Badlion Client", "accounts.json"),
                Path.Combine(appData, ".minecraft", "badlion", "accounts.json")
            };
            foreach (var path in badlionPaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "Badlion Client", AddNick);
            }

            string[] pulsePaths = new[]
            {
                Path.Combine(appData, ".pulse", "accounts.json"),
                Path.Combine(appData, "pulse", "accounts.json"),
                Path.Combine(appData, "PulseClient", "accounts.json"),
                Path.Combine(userProfile, ".pulse", "accounts.json"),
                Path.Combine(appData, ".pulse", "launcher_profiles.json")
            };
            foreach (var path in pulsePaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "Pulse Client", AddNick);
            }

            string[] visualPaths = new[]
            {
                Path.Combine(appData, ".visual", "accounts.json"),
                Path.Combine(appData, "VisualClient", "accounts.json"),
                Path.Combine(appData, ".visual", "launcher_profiles.json")
            };
            foreach (var path in visualPaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "Visual Launcher", AddNick);
            }

            string[] vanillaPaths = new[]
            {
                Path.Combine(appData, ".minecraft", "launcher_profiles.json"),
                Path.Combine(appData, ".minecraft", "launcher_accounts.json")
            };
            foreach (var path in vanillaPaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "Vanilla Launcher", AddNick);
            }

            string[] usercachePaths = new[]
            {
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game", "usercache.json"),
                Path.Combine(appData, ".minecraft", "usercache.json")
            };
            foreach (var path in usercachePaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "UserCache", AddNick);
            }

            string[] labyPaths = new[]
            {
                Path.Combine(appData, ".minecraft", "config", "LabyMod", "accounts.json"),
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game", "config", "LabyMod", "accounts.json"),
                Path.Combine(appData, "LabyMod", "accounts.json"),
                Path.Combine(appData, ".labymod", "accounts.json")
            };
            foreach (var path in labyPaths)
            {
                if (File.Exists(path))
                    ParseJsonOrProps(path, "LabyMod", AddNick);
            }

            string featherPath = Path.Combine(appData, ".feather", "user.json");
            if (File.Exists(featherPath)) ParseJsonOrProps(featherPath, "Feather Client", AddNick);

            string prismPath = Path.Combine(appData, "PrismLauncher", "accounts.json");
            if (File.Exists(prismPath)) ParseJsonOrProps(prismPath, "Prism Launcher", AddNick);

            var result = new List<AccountRecord>();
            foreach (var kvp in nickToSources.OrderBy(x => x.Key))
            {
                result.Add(new AccountRecord
                {
                    Nickname = kvp.Key,
                    Sources = kvp.Value.ToList()
                });
            }

            return result;
        }

        private static void ParseJsonOrProps(string filePath, string sourceName, Action<string, string> onNickFound)
        {
            try
            {
                string text = File.ReadAllText(filePath, Encoding.UTF8);

                var jsonMatches = Regex.Matches(text, @"""(?:username|displayName|alias|name|selectedUser)""\s*:\s*""([a-zA-Z0-9_]{3,16})""", RegexOptions.IgnoreCase);
                foreach (Match m in jsonMatches)
                {
                    if (m.Groups[1].Success)
                        onNickFound(m.Groups[1].Value, sourceName);
                }

                var propMatches = Regex.Matches(text, @"(?:login|username|selectedUser)\s*=\s*([a-zA-Z0-9_]{3,16})", RegexOptions.IgnoreCase);
                foreach (Match m in propMatches)
                {
                    if (m.Groups[1].Success)
                        onNickFound(m.Groups[1].Value, sourceName);
                }
            }
            catch { }
        }

        private static void ParseIasBinary(string filePath, string sourceName, Action<string, string> onNickFound)
        {
            try
            {
                byte[] bytes = File.ReadAllBytes(filePath);
                if (bytes.Length < 10) return;

                byte[] decompressed = null;
                if (bytes[0] == 0x78 && (bytes[1] == 0x9C || bytes[1] == 0xDA || bytes[1] == 0x01 || bytes[1] == 0x5E))
                {
                    try
                    {
                        using (var ms = new MemoryStream(bytes, 2, bytes.Length - 6))
                        using (var deflate = new DeflateStream(ms, CompressionMode.Decompress))
                        using (var outMs = new MemoryStream())
                        {
                            deflate.CopyTo(outMs);
                            decompressed = outMs.ToArray();
                        }
                    }
                    catch { }
                }

                string text = decompressed != null 
                    ? Encoding.UTF8.GetString(decompressed) 
                    : Encoding.UTF8.GetString(bytes);

                var matches = Regex.Matches(text, @"(?:ias:offline(?:_v\d+)?[\s\x00-\x1F]+|alias[\s\x00-\x1F]+)([a-zA-Z0-9_]{3,16})", RegexOptions.IgnoreCase);
                foreach (Match m in matches)
                {
                    if (m.Groups[1].Success)
                    {
                        onNickFound(m.Groups[1].Value, sourceName);
                    }
                }
            }
            catch { }
        }

        public static (string formattedDate, string relativeTime) GetWindowsInstallDate()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        object installTimeObj = key.GetValue("InstallTime");
                        if (installTimeObj != null)
                        {
                            long ft = Convert.ToInt64(installTimeObj);
                            if (ft > 0)
                            {
                                DateTime dt = DateTime.FromFileTime(ft);
                                TimeSpan span = DateTime.Now - dt;
                                string rel = span.TotalDays >= 1 
                                    ? $"{(int)span.TotalDays} дн. назад" 
                                    : $"{(int)span.TotalHours} ч. назад";
                                return (dt.ToString("dd.MM.yyyy HH:mm:ss"), rel);
                            }
                        }

                        object installDateObj = key.GetValue("InstallDate");
                        if (installDateObj != null)
                        {
                            long sec = Convert.ToInt64(installDateObj);
                            if (sec > 0)
                            {
                                DateTime dt = DateTimeOffset.FromUnixTimeSeconds(sec).LocalDateTime;
                                TimeSpan span = DateTime.Now - dt;
                                string rel = span.TotalDays >= 1 
                                    ? $"{(int)span.TotalDays} дн. назад" 
                                    : $"{(int)span.TotalHours} ч. назад";
                                return (dt.ToString("dd.MM.yyyy HH:mm:ss"), rel);
                            }
                        }
                    }
                }
            }
            catch { }

            return ("Не удалось определить", "");
        }
    }
}
