using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace AngelMineChecker
{
    public static class QuickScanner
    {
        internal static readonly string[] CheatKeywords = new[]
        {
            "celestial", "nursultan", "sk3dguard", "sk3d", "baritone",
            "deadcode", "rich", "system dlc", "system-dlc", "systemdlc", "sadnes", "sadness",
            "catlavan", "wildclient", "expensive", "akrien", "wurst",
            "meteor", "bleachhack", "liquidbounce", "matrix",
            "fluegel", "flügel", "zamorozka", "neverlose", "exhi",
            "impact", "aristois", "sigma", "xros", "minced", "excellent", "vape",
            "doomsday", "doomday", "jlivef"
        };

        private static readonly Dictionary<string, HashSet<string>> DetectedCheatFolders = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        private class ForbiddenModRule
        {
            public string Category { get; set; }
            public string LogDescription { get; set; }
            public string SummaryTag { get; set; }
            public string[] Keywords { get; set; }

            public ForbiddenModRule(string category, string logDescription, string summaryTag, params string[] keywords)
            {
                Category = category;
                LogDescription = logDescription;
                SummaryTag = summaryTag;
                Keywords = keywords;
            }
        }

        private static readonly ForbiddenModRule[] ForbiddenModRules = new[]
        {
            new ForbiddenModRule("hitbox", "расширение хитбоксов", "хитбоксы",
                "ezhitbox", "ezhitboxes", "goprone", "mob_hitbox", "mobhitbox", "bushroot"),

            new ForbiddenModRule("autototem", "автототем", "автототем",
                "autototem", "auto_totem", "smarttotem", "totem_swap", "totemswap", "offhandtotem"),

            new ForbiddenModRule("autobuy", "автоскупка аукциона", "автоскупка аукциона",
                "topkaautobuy", "topkautobuy", "autobuy", "auto_buy", "ahbuyer", "auctionbuyer", "auction_buyer"),

            new ForbiddenModRule("autosell", "автопродажа аукциона", "автопродажа аукциона",
                "topkaautosell", "topkaaautosell", "autosell", "auto_sell", "ahseller", "auctionseller"),

            new ForbiddenModRule("automyst", "автолутание мистиков", "автолутание мистиков",
                "automyst", "auto_myst", "mystloot", "myst_loot", "chestevent", "chest_event",
                "cheststealer", "chest_stealer", "chest-stealer", "chest stealer",
                "cheststealler", "chest_stealler", "chest-stealler", "chest stealler",
                "autochestloot", "chestloot", "chest_loot"),

            new ForbiddenModRule("invis", "показ невидимок", "показ невидимок",
                "torohealth", "player_highlighter", "playerhighlighter", "truesight", "true_sight", "tracers", "entity_outliner", "entityoutliner", "showinvis", "invisibleshow"),

            new ForbiddenModRule("crystal", "оптимизатор кристаллов", "оптимизатор кристаллов",
                "haramclientsidecrystalremover", "crystaloptimizer", "crystal_optimizer", "fastcrystal", "fast_crystal", "crystalassist", "crystal_assist", "marlowcrystal"),

            new ForbiddenModRule("seed", "поиск сида мира", "поиск сида мира",
                "bedrockfinder", "bedrock_finder", "bedrock_breaker_mode", "seedcracker", "seed_cracker", "seedminer", "seed_miner"),

            new ForbiddenModRule("invwalk", "движение с открытым инвентарем", "инвентарь вок",
                "inventorywalk", "inventory_walk", "invmove", "inv_move"),

            new ForbiddenModRule("blindness", "скрытие эффекта слепоты", "скрытие слепоты",
                "removeblindness", "remove_blindness", "removeblind", "remove_blind", "noblindness", "no_blindness", "anti_blind", "antiblind"),

            new ForbiddenModRule("bot", "чит-бот", "баритон",
                "baritone", "fabaritone", "spambot", "spam_bot"),

            new ForbiddenModRule("grass", "атака сквозь траву", "атака сквозь траву",
                "grassbypass", "grass_bypass", "cleancut", "clean_cut", "swingthroughgrass", "swing_through_grass", "cutthrough"),

            new ForbiddenModRule("online", "чекер онлайна персонала", "чекер онлайна",
                "stafftracker", "staff_tracker", "vanishchecker", "vanish_checker", "adminchecker", "admin_checker", "spectatordetect"),

            new ForbiddenModRule("freecam", "FreeCam", "FreeCam",
                "freecam", "free_cam", "camerahack"),

            new ForbiddenModRule("minimap", "запрещенная миникарта", "запрещенная миникарта",
                "xaerosminimap", "xaeros_minimap", "xerosminimap", "xeros_minimap", "xaerominimap", "xaero.minimap", "xaeromap"),

            new ForbiddenModRule("tweakeroo", "Tweakeroo", "Tweakeroo",
                "tweakeroo"),

            new ForbiddenModRule("swap", "свап брони/элитр", "свап брони/элитр",
                "elytrahack", "elytra_swap", "elytraswap", "armor_hotswap", "armorhotswap", "elytraswapper"),

            new ForbiddenModRule("trade", "поиск торгов / хоруса", "поиск торгов/хоруса",
                "librarian_trade_finder", "librariantradefinder", "sacurachorusfind", "chorusfind")
        };

        public static async Task RunAsync(Action<string> log)
        {
            var banReasons = new List<string>();

            lock (DetectedCheatFolders)
            {
                DetectedCheatFolders.Clear();
            }

            log("Запуск проверки");
            await Task.Delay(300);

            log("Поиск папок");
            await Task.Delay(400);
            ScanDirectoriesForCheats(log, banReasons);
            await Task.Delay(300);

            log("Поиск логов инжекта");
            await Task.Delay(350);
            ScanUserFolderForInjectors(log, banReasons);
            await Task.Delay(300);

            var (modsDirs, logsDirs) = DiscoverLauncherDirectories();

            log("Проверка папки модов");
            await Task.Delay(400);
            await ScanModsFoldersAsync(modsDirs, log, banReasons);
            CheckModsDeletedAfterMinecraftLaunch(modsDirs, logsDirs, log, banReasons);
            await Task.Delay(350);

            log("Поиск запуска loader");
            await Task.Delay(350);
            ScanRegistry(log, banReasons);
            await Task.Delay(300);

            log("Проверка логов");
            await Task.Delay(350);
            ScanLatestLogs(logsDirs, log, banReasons);
            await Task.Delay(300);

            log("Проверяем следы отчистки");
            await Task.Delay(350);
            CheckCleanupActivity(log);
            await Task.Delay(300);

            CheckRecentDownloads(log, banReasons);
            CheckSuspiciousProcesses(log, banReasons);

            log("");
            log("");
            log("");
            log("");
            log("");
            log("Итоги:");
            if (banReasons.Count > 0)
            {
                foreach (var reason in banReasons.Distinct())
                {
                    log(reason);
                }
            }
            else
            {
                log("Нарушений не обнаружено.");
            }
        }

        internal static (List<string> modsDirs, List<string> logsDirs) DiscoverLauncherDirectories()
        {
            var modsDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var logsDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            var legacyCandidates = new[]
            {
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game"),
                Path.Combine(appData, ".tlauncher", "legacy", "Minecraft"),
                Path.Combine(appData, ".tlauncher")
            };

            foreach (var baseDir in legacyCandidates)
            {
                if (Directory.Exists(baseDir))
                {
                    string m = Path.Combine(baseDir, "mods");
                    if (Directory.Exists(m)) modsDirs.Add(m);
                    string l = Path.Combine(baseDir, "logs");
                    if (Directory.Exists(l)) logsDirs.Add(l);

                    string versionsDir = Path.Combine(baseDir, "versions");
                    if (Directory.Exists(versionsDir))
                    {
                        try
                        {
                            foreach (var vSub in Directory.GetDirectories(versionsDir))
                            {
                                string vm = Path.Combine(vSub, "mods");
                                if (Directory.Exists(vm)) modsDirs.Add(vm);
                            }
                        }
                        catch { }
                    }
                }
            }

            var standardCandidates = new[]
            {
                Path.Combine(appData, ".minecraft"),
                Path.Combine(appData, ".minecraft-launchers")
            };

            foreach (var baseDir in standardCandidates)
            {
                if (Directory.Exists(baseDir))
                {
                    string m = Path.Combine(baseDir, "mods");
                    if (Directory.Exists(m)) modsDirs.Add(m);
                    string l = Path.Combine(baseDir, "logs");
                    if (Directory.Exists(l)) logsDirs.Add(l);

                    string versionsDir = Path.Combine(baseDir, "versions");
                    if (Directory.Exists(versionsDir))
                    {
                        try
                        {
                            foreach (var vSub in Directory.GetDirectories(versionsDir))
                            {
                                string vm = Path.Combine(vSub, "mods");
                                if (Directory.Exists(vm)) modsDirs.Add(vm);
                            }
                        }
                        catch { }
                    }
                }
            }

            var clientCandidates = new[]
            {
                Path.Combine(appData, ".pulse"),
                Path.Combine(appData, ".pulse", "game"),
                Path.Combine(appData, "pulse"),
                Path.Combine(appData, "PulseClient"),
                Path.Combine(userProfile, ".pulse"),
                Path.Combine(userProfile, ".pulse", "game"),
                Path.Combine(appData, ".visual"),
                Path.Combine(appData, ".visual", "game"),
                Path.Combine(appData, "VisualClient"),
                Path.Combine(appData, ".feather", "user-mods"),
                Path.Combine(appData, "Badlion Client"),
                Path.Combine(userProfile, ".lunarclient", "offline", "multiver")
            };

            foreach (var baseDir in clientCandidates)
            {
                if (Directory.Exists(baseDir))
                {
                    string m = Path.Combine(baseDir, "mods");
                    if (Directory.Exists(m)) modsDirs.Add(m);
                    string l = Path.Combine(baseDir, "logs");
                    if (Directory.Exists(l)) logsDirs.Add(l);

                    string instancesDir = Path.Combine(baseDir, "instances");
                    if (Directory.Exists(instancesDir))
                    {
                        try
                        {
                            foreach (var inst in Directory.GetDirectories(instancesDir))
                            {
                                string im = Path.Combine(inst, "mods");
                                if (Directory.Exists(im)) modsDirs.Add(im);
                                string il = Path.Combine(inst, "logs");
                                if (Directory.Exists(il)) logsDirs.Add(il);
                            }
                        }
                        catch { }
                    }
                }
            }

            if (modsDirs.Count == 0 && (Process.GetProcessesByName("javaw").Length > 0 || Process.GetProcessesByName("java").Length > 0))
            {
                try
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT CommandLine, ExecutablePath FROM Win32_Process WHERE Name = 'javaw.exe' OR Name = 'java.exe'"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            string cmd = obj["CommandLine"]?.ToString();
                            if (!string.IsNullOrEmpty(cmd))
                            {
                                var match = Regex.Match(cmd, @"--gameDir\s+(?:""([^""]+)""|'([^']+)'|([^\s]+))", RegexOptions.IgnoreCase);
                                if (match.Success)
                                {
                                    string gDir = match.Groups[1].Success ? match.Groups[1].Value :
                                                  match.Groups[2].Success ? match.Groups[2].Value :
                                                  match.Groups[3].Value;

                                    if (!string.IsNullOrEmpty(gDir) && Directory.Exists(gDir))
                                    {
                                        string m = Path.Combine(gDir, "mods");
                                        if (Directory.Exists(m)) modsDirs.Add(m);
                                        string l = Path.Combine(gDir, "logs");
                                        if (Directory.Exists(l)) logsDirs.Add(l);
                                    }
                                }
                            }

                            string exePath = obj["ExecutablePath"]?.ToString();
                            if (!string.IsNullOrEmpty(exePath))
                            {
                                string dir = Path.GetDirectoryName(exePath);
                                for (int i = 0; i < 6 && dir != null; i++)
                                {
                                    string candidateGame = Path.Combine(dir, "game");
                                    if (Directory.Exists(candidateGame))
                                    {
                                        string m = Path.Combine(candidateGame, "mods");
                                        if (Directory.Exists(m)) modsDirs.Add(m);
                                        string l = Path.Combine(candidateGame, "logs");
                                        if (Directory.Exists(l)) logsDirs.Add(l);
                                    }
                                    dir = Path.GetDirectoryName(dir);
                                }
                            }
                        }
                    }
                }
                catch { }
            }

            try
            {
                string prism = Path.Combine(appData, "PrismLauncher", "instances");
                if (Directory.Exists(prism))
                {
                    foreach (var inst in Directory.GetDirectories(prism))
                    {
                        string m = Path.Combine(inst, ".minecraft", "mods");
                        if (Directory.Exists(m)) modsDirs.Add(m);
                        string l = Path.Combine(inst, ".minecraft", "logs");
                        if (Directory.Exists(l)) logsDirs.Add(l);
                    }
                }
            }
            catch { }

            try
            {
                string curse = Path.Combine(userProfile, "curseforge", "minecraft", "Instances");
                if (Directory.Exists(curse))
                {
                    foreach (var inst in Directory.GetDirectories(curse))
                    {
                        string m = Path.Combine(inst, "mods");
                        if (Directory.Exists(m)) modsDirs.Add(m);
                        string l = Path.Combine(inst, "logs");
                        if (Directory.Exists(l)) logsDirs.Add(l);
                    }
                }
            }
            catch { }

            try
            {
                string tlRoot = Path.Combine(appData, ".tlauncher");
                if (Directory.Exists(tlRoot))
                {
                    SearchForModsAndLogs(tlRoot, 0, 5, modsDirs, logsDirs);
                }
            }
            catch { }

            return (modsDirs.ToList(), logsDirs.ToList());
        }

        private static void SearchForModsAndLogs(string currentDir, int depth, int maxDepth, HashSet<string> mods, HashSet<string> logs)
        {
            if (depth > maxDepth) return;
            try
            {
                foreach (var d in Directory.GetDirectories(currentDir))
                {
                    string name = Path.GetFileName(d).ToLower();
                    if (name == "mods") mods.Add(d);
                    else if (name == "logs") logs.Add(d);
                    else if (name != "resourcepacks" && name != "saves" && name != "shaderpacks" && name != "assets")
                    {
                        SearchForModsAndLogs(d, depth + 1, maxDepth, mods, logs);
                    }
                }
            }
            catch { }
        }

        internal static int ScanDirectoriesForCheats(Action<string> log, List<string> banReasons)
        {
            int found = 0;
            var searchRoots = new List<string>();

            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable))
                    {
                        searchRoots.Add(drive.RootDirectory.FullName);
                    }
                }
            }
            catch
            {
                searchRoots.Add(@"C:\");
            }

            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string tempDir = Path.GetTempPath();

            if (Directory.Exists(appData)) searchRoots.Add(appData);
            if (Directory.Exists(localAppData)) searchRoots.Add(localAppData);
            if (Directory.Exists(userProfile)) searchRoots.Add(userProfile);
            if (Directory.Exists(programData)) searchRoots.Add(programData);
            if (Directory.Exists(tempDir)) searchRoots.Add(tempDir);

            string mcRoot = Path.Combine(appData, ".minecraft");
            if (Directory.Exists(mcRoot)) searchRoots.Add(mcRoot);
            string mcVersions = Path.Combine(appData, ".minecraft", "versions");
            if (Directory.Exists(mcVersions)) searchRoots.Add(mcVersions);

            string tlRoot = Path.Combine(appData, ".tlauncher");
            if (Directory.Exists(tlRoot)) searchRoots.Add(tlRoot);
            string tlLegacy = Path.Combine(appData, ".tlauncher", "legacy", "Minecraft");
            if (Directory.Exists(tlLegacy)) searchRoots.Add(tlLegacy);
            string tlGame = Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game");
            if (Directory.Exists(tlGame)) searchRoots.Add(tlGame);
            string tlVersions = Path.Combine(appData, ".tlauncher", "legacy", "Minecraft", "game", "versions");
            if (Directory.Exists(tlVersions)) searchRoots.Add(tlVersions);

            foreach (var root in searchRoots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var dirInfo = new DirectoryInfo(root);
                    foreach (var sub in dirInfo.EnumerateDirectories())
                    {
                        if (IsCheckerOrSelf(sub.FullName)) continue;
                        try
                        {
                            string name = sub.Name.ToLower();
                            bool isHidden = (sub.Attributes & FileAttributes.Hidden) != 0;
                            bool isSystem = (sub.Attributes & FileAttributes.System) != 0;

                            foreach (var kw in CheatKeywords)
                            {
                                if (name.Contains(kw))
                                {
                                    if (kw == "impact" && (name.Contains("genshin") || name.Contains("hoyoverse") || name.Contains("mihoyo") || name.Contains("hoyoplay")))
                                        continue;

                                    log($"Найден: Папка {sub.Name} ({sub.FullName})");
                                    banReasons.Add($"Найдена папка чита - {sub.Name} ({sub.FullName})");
                                    lock (DetectedCheatFolders)
                                    {
                                        if (!DetectedCheatFolders.ContainsKey(kw)) DetectedCheatFolders[kw] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                        DetectedCheatFolders[kw].Add(sub.FullName);
                                    }
                                    found++;
                                    break;
                                }
                            }
                        }
                        catch { }
                    }

                    foreach (var file in dirInfo.EnumerateFiles())
                    {
                        if (IsCheckerOrSelf(file.FullName)) continue;
                        try
                        {
                            string fName = file.Name.ToLower();
                            if (fName == "desktop.ini" || fName == "thumbs.db" || fName == ".ds_store")
                                continue;

                            foreach (var kw in CheatKeywords)
                            {
                                if (fName.Contains(kw))
                                {
                                    if (kw == "impact" && (fName.Contains("genshin") || fName.Contains("hoyoverse") || fName.Contains("mihoyo") || fName.Contains("hoyoplay")))
                                        continue;

                                    log($"Найден: Файл {file.Name} ({file.FullName})");
                                    banReasons.Add($"Найден файл чита - {file.Name} ({file.FullName})");
                                    lock (DetectedCheatFolders)
                                    {
                                        if (!DetectedCheatFolders.ContainsKey(kw)) DetectedCheatFolders[kw] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                        DetectedCheatFolders[kw].Add(file.FullName);
                                    }
                                    found++;
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            return found;
        }

        internal static int ScanUserFolderForInjectors(Action<string> log, List<string> banReasons)
        {
            int found = 0;
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            var checkFolders = new[]
            {
                userProfile,
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Documents")
            };

            foreach (var folder in checkFolders)
            {
                if (!Directory.Exists(folder)) continue;

                try
                {
                    var files = Directory.GetFiles(folder, "*.*", SearchOption.TopDirectoryOnly);
                    foreach (var f in files)
                    {
                        if (IsCheckerOrSelf(f)) continue;
                        string fileName = Path.GetFileName(f).ToLower();
                        if (fileName.Contains("jar-to-dll") || fileName.Contains("jar2dll") ||
                            fileName.Contains("jar_to_dll") || fileName.Contains("jartodll"))
                        {
                            log($"Найден: Инжектор {Path.GetFileName(f)} ({f})");
                            banReasons.Add($"Инжектор {Path.GetFileName(f)}");
                            found++;
                            continue;
                        }

                        if (CheckDoomsdayJar(new FileInfo(f), out string dReason))
                        {
                            log($"Найден чит Doomsday: {Path.GetFileName(f)} ({f}) [{dReason}]");
                            banReasons.Add($"Найден Doomsday - {f} ({dReason})");
                            found++;
                        }
                    }
                }
                catch { }
            }

            return found;
        }

        public static bool CheckDoomsdayJar(FileInfo file, out string reason)
        {
            reason = "";
            if (file == null || !file.Exists) return false;
            if (IsCheckerOrSelf(file.FullName)) return false;

            try
            {
                long len = file.Length;
                if (len < 512 || len > 35 * 1024 * 1024) return false;

                string ext = file.Extension.ToLower();

                bool isZip = false;
                using (var fs = file.OpenRead())
                {
                    byte[] magic = new byte[4];
                    int read = fs.Read(magic, 0, 4);
                    if (read >= 2 && magic[0] == 0x50 && magic[1] == 0x4B)
                    {
                        isZip = true;
                    }
                }

                bool isDllDisguised = (ext == ".dll" && isZip);

                if (len >= 28000 && len <= 35000)
                {
                    byte[] raw = File.ReadAllBytes(file.FullName);
                    string rawUtf8 = Encoding.UTF8.GetString(raw);
                    if (rawUtf8.Contains("net/minecraft/client/entity/player/ClientPlayerEntity") ||
                        rawUtf8.Contains("net/minecraft/util/math/AxisAlignedBB"))
                    {
                        reason = isDllDisguised
                            ? "Doomsday, замаскированный под .dll (размер ~30KB и сигнатура Entity/AxisAlignedBB)"
                            : "размер ~30KB и сигнатура Entity/AxisAlignedBB";
                        return true;
                    }
                }

                if (isZip || ext == ".jar" || ext == ".zip" || ext == ".dll" || ext == ".disabled" || ext == ".bak")
                {
                    bool hasLPng = false;
                    bool hasMcmodInfo = false;
                    bool hasNetJavaS = false;
                    bool hasNetJavaF = false;
                    bool hasClassFiles = false;
                    bool hasManifest = false;
                    bool hasDoomsdayName = false;

                    try
                    {
                        using (var archive = ZipFile.OpenRead(file.FullName))
                        {
                            foreach (var entry in archive.Entries)
                            {
                                string eName = entry.FullName.ToLower().Replace('\\', '/');

                                if (eName.EndsWith(".class"))
                                    hasClassFiles = true;

                                if (eName.EndsWith("manifest.mf"))
                                    hasManifest = true;

                                if (eName.Contains("doomsday") || eName.Contains("doomday"))
                                    hasDoomsdayName = true;

                                if (eName.EndsWith("l.png") || eName == "l.png")
                                    hasLPng = true;

                                if (eName.EndsWith("mcmod.info") || eName == "mcmod.info")
                                    hasMcmodInfo = true;

                                if (eName.Contains("net/java/s.class") || (eName.Contains("net/java") && eName.EndsWith("/s.class")))
                                    hasNetJavaS = true;

                                if (eName.Contains("net/java/f.class") || (eName.Contains("net/java") && eName.EndsWith("/f.class")))
                                    hasNetJavaF = true;
                            }
                        }

                        if (hasLPng && hasMcmodInfo)
                        {
                            reason = isDllDisguised
                                ? "Doomsday, замаскированный под .dll (l.png + mcmod.info)"
                                : "сигнатура Doomsday (l.png + mcmod.info)";
                            return true;
                        }

                        if (hasNetJavaS && hasNetJavaF)
                        {
                            reason = isDllDisguised
                                ? "Doomsday, замаскированный под .dll (net/java/s.class + net/java/f.class)"
                                : "сигнатура Doomsday (net/java/s.class + net/java/f.class)";
                            return true;
                        }

                        if (hasDoomsdayName)
                        {
                            reason = isDllDisguised
                                ? "Doomsday, замаскированный под .dll (внутренние пути doomsday)"
                                : "сигнатура Doomsday (внутренние пути doomsday)";
                            return true;
                        }

                        if (isDllDisguised && (hasClassFiles || hasManifest))
                        {
                            reason = "JAR-чит, замаскированный под .dll (PK-архив с байткодом Java для запуска через java -jar)";
                            return true;
                        }
                    }
                    catch { }

                    byte[] zipHead = new byte[Math.Min((int)len, 1048576)];
                    using (var fs = file.OpenRead())
                    {
                        fs.Read(zipHead, 0, zipHead.Length);
                    }
                    string headUtf8 = Encoding.UTF8.GetString(zipHead);
                    if (headUtf8.Contains("net/java/s.class") && headUtf8.Contains("net/java/f.class"))
                    {
                        reason = isDllDisguised
                            ? "Doomsday, замаскированный под .dll (net/java/s.class, f.class в байткоде)"
                            : "сигнатура Doomsday (net/java/s.class, f.class в байткоде)";
                        return true;
                    }

                    if (isDllDisguised && (headUtf8.Contains("net/java/s.class") || headUtf8.Contains("net/java/f.class") || headUtf8.Contains("doomsday") || headUtf8.Contains("doomday")))
                    {
                        reason = "Doomsday, замаскированный под .dll (байткод Doomsday)";
                        return true;
                    }
                }
            }
            catch { }

            return false;
        }

        private static string DecodeSig(string b64)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        }

        public static bool IsCheckerOrSelf(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                string name = Path.GetFileName(path);
                if (name.IndexOf("angelminechecker", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    name.IndexOf("ico-tool", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }

                string currentExe = Process.GetCurrentProcess().MainModule?.FileName;
                if (!string.IsNullOrEmpty(currentExe))
                {
                    if (string.Equals(Path.GetFullPath(path), Path.GetFullPath(currentExe), StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (!string.IsNullOrEmpty(baseDir))
                {
                    string fullPath = Path.GetFullPath(path);
                    string fullBase = Path.GetFullPath(baseDir);
                    if (fullPath.StartsWith(fullBase, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        public static readonly string[] SystemDlcSignatures = new[]
        {
            DecodeSig("NjdjZnVlZ3UwcDhybQ=="),
            DecodeSig("QVJST1dfUklHSFRaT05UQUw="),
            DecodeSig("RFJPUERPV05fU1VDQ0VTUw=="),
            DecodeSig("Q0hFVlJPTl9SSUdIVA=="),
            DecodeSig("dG9vbHRpcF9hcnJvd191cA=="),
            DecodeSig("TjFZMEc2emZ6MEVTSm9DSQ=="),
            DecodeSig("YXJTQnFCUWZiVW5GUFRHZQ=="),
            DecodeSig("dX1weG10aG9iaV1kWF5SWExSRkxARjo/MzgsMSYq")
        };

        public static bool CheckSystemDlcInFile(FileInfo file, out string foundSig)
        {
            foundSig = "";
            if (file == null || !file.Exists) return false;
            if (IsCheckerOrSelf(file.FullName)) return false;
            try
            {
                long len = file.Length;
                if (len == 0 || len > 35 * 1024 * 1024) return false;

                using (var fs = file.OpenRead())
                {
                    byte[] buf = new byte[Math.Min((int)len, 4 * 1024 * 1024)];
                    int read = fs.Read(buf, 0, buf.Length);
                    string ascii = Encoding.ASCII.GetString(buf, 0, read);
                    string utf8 = Encoding.UTF8.GetString(buf, 0, read);
                    string unicode = Encoding.Unicode.GetString(buf, 0, read - (read % 2));

                    foreach (var sig in SystemDlcSignatures)
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

        internal static async Task<(int threats, int warnings)> ScanModsFoldersAsync(List<string> modsDirs, Action<string> log, List<string> banReasons)
        {
            if (modsDirs == null || modsDirs.Count == 0)
            {
                log("Папка mods не обнаружена (проверены javaw.exe, TLauncher, Legacy Launcher и стандартные пути).");
                return (0, 0);
            }

            var allFiles = new List<FileInfo>();
            var allDirs = new List<DirectoryInfo>();

            foreach (var dir in modsDirs)
            {
                if (Directory.Exists(dir))
                {
                    try
                    {
                        var di = new DirectoryInfo(dir);
                        EnumerateModDirectoriesAndFilesRecursive(di, allFiles, allDirs);
                    }
                    catch { }
                }
            }

            if (allFiles.Count == 0 && allDirs.Count == 0)
            {
                return (0, 0);
            }

            var issueLogs = new System.Collections.Concurrent.ConcurrentBag<string>();
            var modBanReasons = new System.Collections.Concurrent.ConcurrentBag<string>();
            int totalThreats = 0;
            int totalWarnings = 0;

            foreach (var sub in allDirs)
            {
                try
                {
                    bool isHidden = (sub.Attributes & FileAttributes.Hidden) != 0;
                    bool isSystem = (sub.Attributes & FileAttributes.System) != 0;
                    string attrStr = (isHidden && isSystem) ? "attrib +s +h" : isSystem ? "attrib +s" : isHidden ? "attrib +h" : "";
                    string dirName = sub.Name.ToLower();

                    bool hasCheatKw = false;
                    foreach (var kw in CheatKeywords)
                    {
                        if (dirName.Contains(kw))
                        {
                            hasCheatKw = true;
                            break;
                        }
                    }

                    if (!string.IsNullOrEmpty(attrStr) || hasCheatKw)
                    {
                        issueLogs.Add($"Найден: Папка в mods {sub.Name} ({sub.FullName})");
                        banReasons.Add($"Папка в mods {sub.Name} ({sub.FullName})");
                        System.Threading.Interlocked.Increment(ref totalThreats);
                    }
                }
                catch { }
            }

            foreach (var file in allFiles)
            {
                try
                {
                    string fileName = file.Name.ToLower();
                    if (fileName == "desktop.ini" || fileName == "thumbs.db" || fileName == ".ds_store")
                        continue;

                    bool isHidden = (file.Attributes & FileAttributes.Hidden) != 0;
                    bool isSystem = (file.Attributes & FileAttributes.System) != 0;
                    string attrStr = (isHidden && isSystem) ? "attrib +s +h" : isSystem ? "attrib +s" : isHidden ? "attrib +h" : "";

                    bool hasCheatKw = false;
                    foreach (var kw in CheatKeywords)
                    {
                        if (fileName.Contains(kw))
                        {
                            if (kw == "impact" && (fileName.Contains("genshin") || fileName.Contains("hoyoverse") || fileName.Contains("mihoyo") || fileName.Contains("hoyoplay")))
                                continue;

                            hasCheatKw = true;
                            break;
                        }
                    }

                    if (!string.IsNullOrEmpty(attrStr) || hasCheatKw)
                    {
                        issueLogs.Add($"Найден: Файл в mods {file.Name} ({file.FullName})");
                        banReasons.Add($"Файл в mods {file.Name} ({file.FullName})");
                        System.Threading.Interlocked.Increment(ref totalThreats);
                    }
                }
                catch { }
            }

            var targetArchives = new List<FileInfo>();
            foreach (var file in allFiles)
            {
                try
                {
                    string ext = file.Extension.ToLower();
                    if (ext == ".jar" || ext == ".zip" || ext == ".disabled" || ext == ".bak")
                    {
                        targetArchives.Add(file);
                    }
                    else if (file.Length > 200)
                    {
                        using (var fs = file.OpenRead())
                        {
                            byte[] magic = new byte[4];
                            if (fs.Read(magic, 0, 4) == 4 && magic[0] == 0x50 && magic[1] == 0x4B && magic[2] == 0x03 && magic[3] == 0x04)
                            {
                                targetArchives.Add(file);
                                issueLogs.Add($"Найден: Маскированный архив в mods ({file.Extension}) - {file.Name}");
                                banReasons.Add($"Маскированный архив {file.Name}");
                                System.Threading.Interlocked.Increment(ref totalThreats);
                            }
                        }
                    }
                }
                catch { }
            }

            await Task.Run(() =>
            {
                Parallel.ForEach(targetArchives, file =>
                {
                    string jarName = file.Name;
                    string jarNameLower = jarName.ToLower();
                    bool hasKillauraOrCheat = false;
                    bool hasHitboxExpand = false;
                    bool hasLoader = false;
                    bool hasObfuscation = false;
                    var detectedRules = new HashSet<ForbiddenModRule>();

                    foreach (var rule in ForbiddenModRules)
                    {
                        foreach (var kw in rule.Keywords)
                        {
                            if (jarNameLower.Contains(kw))
                            {
                                if (rule.Category == "hitbox")
                                {
                                    hasHitboxExpand = true;
                                }
                                else
                                {
                                    detectedRules.Add(rule);
                                }
                                break;
                            }
                        }
                    }

                    try
                    {
                        using (var archive = ZipFile.OpenRead(file.FullName))
                        {
                            int totalClasses = 0;
                            int obfuscatedClasses = 0;

                            foreach (var entry in archive.Entries)
                            {
                                string entryName = entry.FullName.ToLower();

                                if (entryName.EndsWith(".class"))
                                {
                                    totalClasses++;
                                    string simpleName = Path.GetFileNameWithoutExtension(entryName);
                                    if (simpleName.Length <= 2 || simpleName.All(c => c >= '0' && c <= '9') || simpleName.Any(c => c > 127 || c < 32))
                                    {
                                        obfuscatedClasses++;
                                    }

                                    bool isCompat = entryName.Contains("/compat/") || entryName.Contains("/compatibility/") ||
                                                    entryName.Contains("/integration/") || entryName.Contains("/integrations/") ||
                                                    entryName.Contains("/plugin/") || entryName.Contains("/plugins/") ||
                                                    entryName.Contains("/mixin/compat/") || entryName.Contains("/mixins/compat/") ||
                                                    simpleName.Contains("compat") || simpleName.Contains("integration");

                                    if (!isCompat)
                                    {
                                        foreach (var rule in ForbiddenModRules)
                                        {
                                            foreach (var kw in rule.Keywords)
                                            {
                                                if (entryName.Contains(kw))
                                                {
                                                    if (rule.Category == "hitbox")
                                                    {
                                                        hasHitboxExpand = true;
                                                    }
                                                    else
                                                    {
                                                        detectedRules.Add(rule);
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                                if (entryName == "fabric.mod.json" || entryName == "mcmod.info" || entryName == "meta-inf/mods.toml" || entryName == "quilt.mod.json")
                                {
                                    try
                                    {
                                        using (var stream = entry.Open())
                                        using (var reader = new StreamReader(stream))
                                        {
                                            string manifest = reader.ReadToEnd();
                                            var modIdentifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                                            var idMatches = Regex.Matches(manifest, @"(?:""(?:id|modid)""|modId)\s*[:=]\s*""([^""]+)""", RegexOptions.IgnoreCase);
                                            foreach (Match m in idMatches)
                                            {
                                                if (m.Groups.Count > 1) modIdentifiers.Add(m.Groups[1].Value.ToLower());
                                            }
                                            var nameMatches = Regex.Matches(manifest, @"(?:""(?:name|displayName)""|displayName)\s*[:=]\s*""([^""]+)""", RegexOptions.IgnoreCase);
                                            foreach (Match m in nameMatches)
                                            {
                                                if (m.Groups.Count > 1) modIdentifiers.Add(m.Groups[1].Value.ToLower());
                                            }

                                            foreach (var rule in ForbiddenModRules)
                                            {
                                                foreach (var kw in rule.Keywords)
                                                {
                                                    if (modIdentifiers.Any(id => id.Contains(kw)))
                                                    {
                                                        if (rule.Category == "hitbox")
                                                        {
                                                            hasHitboxExpand = true;
                                                        }
                                                        else
                                                        {
                                                            detectedRules.Add(rule);
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    catch { }
                                }

                                if (entryName.Contains("killaura") ||
                                    (entryName.Contains("aura") && (entryName.Contains("combat") || entryName.Contains("attack") || entryName.Contains("target"))) ||
                                    entryName.Contains("triggerbot") || entryName.Contains("targetstrafe") ||
                                    entryName.Contains("autoclicker") || entryName.Contains("antiknockback") ||
                                    (entryName.Contains("velocity") && entryName.Contains("combat")) ||
                                    entryName.Contains("fastbow") || entryName.Contains("bowaimbot"))
                                {
                                    hasKillauraOrCheat = true;
                                }

                                if (entryName.Contains("injectedagent") ||
                                    (entryName.EndsWith(".dll") && (
                                        entryName.Contains("loader") || entryName.Contains("cheat") || entryName.Contains("inject") ||
                                        entryName.Contains("hook") || entryName.Contains("agent") || entryName.Contains("celestial") ||
                                        entryName.Contains("nursultan") || entryName.Contains("sk3d") || entryName.Contains("rich") ||
                                        entryName.Contains("deadcode") || entryName.Contains("wildclient"))))
                                {
                                    hasLoader = true;
                                }

                                if (entryName.Contains("bushroot") || entryName.Contains("/hb/") || entryName.StartsWith("hb/"))
                                {
                                    hasHitboxExpand = true;
                                }

                                if (entryName.Contains("hitbox") || entryName.Contains("reach") || jarNameLower.Contains("hitbox"))
                                {
                                    if (entryName.EndsWith(".class"))
                                    {
                                        try
                                        {
                                            using (var stream = entry.Open())
                                            using (var ms = new MemoryStream())
                                            {
                                                stream.CopyTo(ms);
                                                string content = Encoding.ASCII.GetString(ms.ToArray()).ToLower();

                                                bool isExpand = content.Contains("expandhitbox") || content.Contains("hitboxexpand") ||
                                                                content.Contains("gettargetingmargin") ||
                                                                (content.Contains("reachdistance") && !entryName.Contains("gamewrap") && !entryName.Contains("brush")) ||
                                                                (content.Contains("hasextendedreach") && !entryName.Contains("gamewrap"));

                                                if ((content.Contains("expand") || content.Contains("grow") || content.Contains("setboundingbox")) &&
                                                    (entryName.Contains("entity") || entryName.Contains("player") || entryName.Contains("combat")))
                                                {
                                                    bool isPureRender = (content.Contains("render") || content.Contains("painter") || content.Contains("overlay") || content.Contains("color")) &&
                                                                        !content.Contains("gettargetingmargin") && !content.Contains("expandhitbox");

                                                    if (!isPureRender)
                                                    {
                                                        isExpand = true;
                                                    }
                                                }

                                                if (isExpand)
                                                {
                                                    hasHitboxExpand = true;
                                                }
                                            }
                                        }
                                        catch { }
                                    }
                                }
                            }

                            if (totalClasses > 8 && ((double)obfuscatedClasses / totalClasses > 0.40))
                            {
                                hasObfuscation = true;
                            }
                        }
                    }
                    catch { }

                    if (hasHitboxExpand)
                    {
                        issueLogs.Add($"Найден мод на расширения хитбокс - {jarName}");
                        modBanReasons.Add($"Найден мод на расширения хитбокс - {jarName}");
                        System.Threading.Interlocked.Increment(ref totalThreats);
                    }

                    if (CheckDoomsdayJar(file, out string doomsdayReason))
                    {
                        issueLogs.Add($"Найден чит Doomsday - {jarName} ({doomsdayReason})");
                        modBanReasons.Add($"Найден Doomsday - {file.FullName} ({doomsdayReason})");
                        System.Threading.Interlocked.Increment(ref totalThreats);
                    }

                    foreach (var rule in detectedRules)
                    {
                        issueLogs.Add($"Найден запрещенный мод - {jarName} ({rule.SummaryTag})");
                        modBanReasons.Add($"Найден запрещенный мод - {jarName} ({rule.SummaryTag})");
                        System.Threading.Interlocked.Increment(ref totalThreats);
                    }

                    if (hasKillauraOrCheat)
                    {
                        issueLogs.Add($"Найден чит в моде - {jarName}");
                        modBanReasons.Add($"{jarName} - чит в моде");
                        System.Threading.Interlocked.Increment(ref totalThreats);
                    }
                    if (hasLoader)
                    {
                        issueLogs.Add($"Найден лоадер в моде - {jarName}");
                        modBanReasons.Add($"{jarName} - лоадер в моде");
                        System.Threading.Interlocked.Increment(ref totalThreats);
                    }
                    if (hasObfuscation)
                    {
                        issueLogs.Add($"Подозрительная обфускация в моде: {jarName}");
                        System.Threading.Interlocked.Increment(ref totalWarnings);
                    }
                });
            });

            foreach (var r in modBanReasons)
            {
                banReasons.Add(r);
            }

            foreach (var issue in issueLogs)
            {
                log(issue);
            }

            return (totalThreats, totalWarnings);
        }

        private static void EnumerateModDirectoriesAndFilesRecursive(DirectoryInfo dir, List<FileInfo> files, List<DirectoryInfo> dirs)
        {
            try
            {
                foreach (var f in dir.EnumerateFiles())
                {
                    files.Add(f);
                }
                foreach (var sub in dir.EnumerateDirectories())
                {
                    dirs.Add(sub);
                    EnumerateModDirectoriesAndFilesRecursive(sub, files, dirs);
                }
            }
            catch { }
        }

        internal static int ScanRegistry(Action<string> log, List<string> banReasons)
        {
            int threats = 0;
            var regMatches = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

            Action<string> addRegMatch = (rawVal) =>
            {
                if (string.IsNullOrWhiteSpace(rawVal)) return;
                string clean = CleanRegistryValue(rawVal);
                if (string.IsNullOrWhiteSpace(clean)) return;
                string lower = clean.ToLower();
                foreach (var kw in CheatKeywords)
                {
                    if (lower.Contains(kw))
                    {
                        if (kw == "impact" && (lower.Contains("genshin") || lower.Contains("hoyoverse") || lower.Contains("mihoyo") || lower.Contains("hoyoplay")))
                        {
                            continue;
                        }

                        if (!regMatches.ContainsKey(kw))
                        {
                            regMatches[kw] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        }
                        regMatches[kw].Add(clean);
                        break;
                    }
                }
            };

            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"))
                {
                    if (key != null)
                    {
                        foreach (var val in key.GetValueNames())
                        {
                            addRegMatch(val);
                        }
                    }
                }
            }
            catch { }

            try
            {
                using (var uaRoot = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"))
                {
                    if (uaRoot != null)
                    {
                        foreach (var sub in uaRoot.GetSubKeyNames())
                        {
                            using (var countKey = uaRoot.OpenSubKey(sub + @"\Count"))
                            {
                                if (countKey == null) continue;
                                foreach (var name in countKey.GetValueNames())
                                {
                                    string decoded = DecodeRot13(name);
                                    addRegMatch(decoded);
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"))
                {
                    if (key != null)
                    {
                        foreach (var val in key.GetValueNames())
                        {
                            addRegMatch(val);
                        }
                    }
                }
            }
            catch { }

            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"))
                {
                    if (key != null)
                    {
                        foreach (var val in key.GetValueNames())
                        {
                            var data = key.GetValue(val)?.ToString() ?? "";
                            addRegMatch(data);
                        }
                    }
                }
            }
            catch { }

            foreach (var kvp in regMatches)
            {
                string kw = kvp.Key;
                var paths = kvp.Value.ToList();
                string regStr = string.Join(", ", paths);

                string folderPart = "";
                lock (DetectedCheatFolders)
                {
                    if (DetectedCheatFolders.TryGetValue(kw, out var fSet) && fSet.Count > 0)
                    {
                        folderPart = " (папки = " + string.Join(", ", fSet) + ")";
                    }
                }

                string outputLine = $"{kw} (RegEdit = {regStr}){folderPart}";
                log(outputLine);
                banReasons.Add(outputLine);
                threats++;
            }

            return threats;
        }

        private static string CleanRegistryValue(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return "";
            string s = raw.Trim();

            int idx = s.IndexOf(".FriendlyAppName", StringComparison.OrdinalIgnoreCase);
            if (idx > 0) s = s.Substring(0, idx);

            idx = s.IndexOf(".ApplicationCompany", StringComparison.OrdinalIgnoreCase);
            if (idx > 0) s = s.Substring(0, idx);

            s = Regex.Replace(s, @"\\[0-9a-zA-Z]$", "");

            return s.Trim();
        }

        private static string DecodeRot13(string input)
        {
            if (string.IsNullOrEmpty(input)) return "";
            char[] array = input.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                int number = array[i];
                if (number >= 'a' && number <= 'z')
                {
                    if (number > 'm') number -= 13;
                    else number += 13;
                }
                else if (number >= 'A' && number <= 'Z')
                {
                    if (number > 'M') number -= 13;
                    else number += 13;
                }
                array[i] = (char)number;
            }
            return new string(array);
        }

        internal static (int threats, int warnings) ScanLatestLogs(List<string> logsDirs, Action<string> log, List<string> banReasons)
        {
            int threats = 0;
            int warnings = 0;

            if (logsDirs == null || logsDirs.Count == 0)
            {
                return (0, 0);
            }

            var logFiles = new List<string>();
            foreach (var lDir in logsDirs)
            {
                try
                {
                    if (Directory.Exists(lDir))
                    {
                        string p1 = Path.Combine(lDir, "latest.log");
                        if (File.Exists(p1) && !logFiles.Contains(p1, StringComparer.OrdinalIgnoreCase)) logFiles.Add(p1);
                        string p2 = Path.Combine(lDir, "latest.txt");
                        if (File.Exists(p2) && !logFiles.Contains(p2, StringComparer.OrdinalIgnoreCase)) logFiles.Add(p2);
                    }
                }
                catch { }
            }

            if (logFiles.Count == 0)
            {
                return (0, 0);
            }

            var detectedLogCheats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var logFile in logFiles)
            {
                try
                {
                    using (var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (var reader = new StreamReader(fs, Encoding.UTF8))
                    {
                        string line;
                        while ((line = reader.ReadLine()) != null)
                        {
                            string lower = line.ToLower();

                            if (lower.Contains("[chat]") || lower.Contains("[system] [chat]") || lower.Contains("async chat thread") || lower.Contains(" /near"))
                            {
                                continue;
                            }

                            if (lower.Contains("hitboxusers") || lower.Contains("hitbox_users"))
                            {
                                continue;
                            }

                            if (lower.Contains("connecting to localhost") || lower.Contains("connecting to 127.0.0.1") ||
                                lower.Contains("connecting to 0.0.0.0") || lower.Contains("connected to localhost"))
                            {
                                var timeMatch = Regex.Match(line, @"\[(\d{2}:\d{2}:\d{2})\]");
                                string timeStr = timeMatch.Success ? timeMatch.Groups[1].Value : "";
                                string timeInfo = string.IsNullOrEmpty(timeStr) ? "" : $" ({timeStr})";
                                string report = $"Подключение к localhost{timeInfo}: {line.Trim()}";
                                if (detectedLogCheats.Add(report))
                                {
                                    log(report);
                                    banReasons.Add($"Подключение к localhost{timeInfo}");
                                    warnings++;
                                }
                                continue;
                            }

                            string modCandidate = null;

                            var fabricMatch = Regex.Match(line, @"^\s*(?:-|\|--)\s+([a-zA-Z0-9_\-\.]+)(?:\s+(.*))?$");
                            if (fabricMatch.Success)
                            {
                                modCandidate = fabricMatch.Groups[1].Value.ToLower();
                            }
                            else if (lower.Contains("loading mod id") || lower.Contains("loading mod ") || lower.Contains("found mod file") || lower.Contains("mod file:"))
                            {
                                var forgeMatch = Regex.Match(line, @"(?:loading mod id '([a-zA-Z0-9_\-\.]+)'|loading mod ([a-zA-Z0-9_\-\.]+)|mod file:?\s*([a-zA-Z0-9_\-\.]+))", RegexOptions.IgnoreCase);
                                if (forgeMatch.Success)
                                {
                                    modCandidate = (forgeMatch.Groups[1].Success ? forgeMatch.Groups[1].Value :
                                                    forgeMatch.Groups[2].Success ? forgeMatch.Groups[2].Value :
                                                    forgeMatch.Groups[3].Value).ToLower();
                                }
                            }

                            if (!string.IsNullOrEmpty(modCandidate))
                            {
                                if (modCandidate.Contains("hitboxusers") || modCandidate == "minecraft")
                                {
                                    continue;
                                }

                                bool modMatched = false;
                                foreach (var rule in ForbiddenModRules)
                                {
                                    if (rule.Keywords.Any(kw => modCandidate.Contains(kw)))
                                    {
                                        string tag = rule.Category == "hitbox" ? "хитбоксы" : rule.SummaryTag;
                                        string report = $"Найден запрещенный мод в логах: {modCandidate} ({tag})";
                                        if (detectedLogCheats.Add(report))
                                        {
                                            log(report);
                                            banReasons.Add($"Логи: {modCandidate} - {tag}");
                                            threats++;
                                        }
                                        modMatched = true;
                                        break;
                                    }
                                }

                                if (!modMatched)
                                {
                                    foreach (var kw in CheatKeywords)
                                    {
                                        if (modCandidate.Contains(kw))
                                        {
                                            if (kw == "impact" && (modCandidate.Contains("genshin") || modCandidate.Contains("hoyoverse") || modCandidate.Contains("mihoyo") || modCandidate.Contains("hoyoplay")))
                                                continue;

                                            string report = $"Найден чит в логах: {modCandidate}";
                                            if (detectedLogCheats.Add(report))
                                            {
                                                log(report);
                                                banReasons.Add($"Логи: {modCandidate}");
                                                threats++;
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch { }
            }

            return (threats, warnings);
        }

        internal static int CheckCleanupActivity(Action<string> log)
        {
            int warnings = 0;

            try
            {
                string recyclePath = @"C:\$RECYCLE.BIN";
                if (Directory.Exists(recyclePath))
                {
                    DateTime latestRecycle = Directory.GetLastWriteTime(recyclePath);
                    try
                    {
                        foreach (var sub in Directory.GetDirectories(recyclePath))
                        {
                            DateTime dt = Directory.GetLastWriteTime(sub);
                            if (dt > latestRecycle) latestRecycle = dt;
                        }
                    }
                    catch { }

                    TimeSpan age = DateTime.Now - latestRecycle;
                    if (age.TotalMinutes <= 30 && age.TotalMinutes >= 0)
                    {
                        log($"Корзина была очищена {(int)age.TotalMinutes} минут назад");
                        warnings++;
                    }
                    else
                    {
                        log($"Корзина: последнее изменение {latestRecycle:dd.MM.yyyy HH:mm} (> 30 мин. назад).");
                    }
                }
            }
            catch { }

            try
            {
                string prefetchPath = @"C:\Windows\Prefetch";
                if (Directory.Exists(prefetchPath))
                {
                    var pfFiles = Directory.GetFiles(prefetchPath, "*.pf");
                    if (pfFiles.Length == 0)
                    {
                        log("Папка Prefetch пустая");
                        warnings++;
                    }
                    else
                    {
                        DateTime latestPf = pfFiles.Select(f => new FileInfo(f).LastWriteTime).Max();
                        TimeSpan pfAge = DateTime.Now - latestPf;
                        if (pfAge.TotalMinutes <= 30 && pfAge.TotalMinutes >= 0)
                        {
                            log($"Prefetch: недавняя активность (< 30 мин. назад, {latestPf:dd.MM.yyyy HH:mm}, {(int)pfAge.TotalMinutes} мин. назад).");
                        }
                        else
                        {
                            log($"Prefetch: последнее изменение {latestPf:dd.MM.yyyy HH:mm} (> 30 мин. назад).");
                        }
                    }
                }
            }
            catch { }

            try
            {
                string tempPath = Path.GetTempPath();
                if (Directory.Exists(tempPath))
                {
                    DateTime tempTime = Directory.GetLastWriteTime(tempPath);
                    TimeSpan tempAge = DateTime.Now - tempTime;
                    if (tempAge.TotalMinutes <= 30 && tempAge.TotalMinutes >= 0)
                    {
                        log($"Temp: недавнее изменение (< 30 мин. назад, {tempTime:dd.MM.yyyy HH:mm}, {(int)tempAge.TotalMinutes} мин. назад).");
                    }
                    else
                    {
                        log($"Temp: последнее изменение {tempTime:dd.MM.yyyy HH:mm} (> 30 мин. назад).");
                    }
                }
            }
            catch { }

            try
            {
                string recentPath = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
                if (Directory.Exists(recentPath))
                {
                    DateTime recentTime = Directory.GetLastWriteTime(recentPath);
                    TimeSpan recentAge = DateTime.Now - recentTime;
                    if (recentAge.TotalMinutes <= 30 && recentAge.TotalMinutes >= 0)
                    {
                        log($"Recent: недавнее изменение (< 30 мин. назад, {recentTime:dd.MM.yyyy HH:mm}, {(int)recentAge.TotalMinutes} мин. назад).");
                    }
                    else
                    {
                        log($"Recent: последнее изменение {recentTime:dd.MM.yyyy HH:mm} (> 30 мин. назад).");
                    }
                }
            }
            catch { }

            return warnings;
        }

        internal static void CheckModsDeletedAfterMinecraftLaunch(List<string> modsDirs, List<string> logsDirs, Action<string> log, List<string> banReasons)
        {
            if (modsDirs == null || modsDirs.Count == 0) return;

            DateTime? mcLaunchTime = null;
            bool isGameCurrentlyRunning = false;

            try
            {
                var procs = Process.GetProcessesByName("javaw").Concat(Process.GetProcessesByName("java")).ToList();
                if (procs.Count > 0)
                {
                    var mainProc = procs.OrderByDescending(p =>
                    {
                        try { return p.StartTime; } catch { return DateTime.MinValue; }
                    }).First();

                    try
                    {
                        mcLaunchTime = mainProc.StartTime;
                        isGameCurrentlyRunning = true;
                    }
                    catch { }
                }
            }
            catch { }

            if (!mcLaunchTime.HasValue && logsDirs != null)
            {
                foreach (var lDir in logsDirs)
                {
                    try
                    {
                        string latestLog = Path.Combine(lDir, "latest.log");
                        if (File.Exists(latestLog))
                        {
                            var fi = new FileInfo(latestLog);
                            if ((DateTime.Now - fi.LastWriteTime).TotalHours > 12)
                            {
                                continue;
                            }

                            DateTime logTime = fi.CreationTime < fi.LastWriteTime ? fi.CreationTime : fi.LastWriteTime;
                            try
                            {
                                using (var fs = new FileStream(latestLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                                using (var reader = new StreamReader(fs, Encoding.UTF8))
                                {
                                    string firstLine = reader.ReadLine();
                                    if (!string.IsNullOrEmpty(firstLine))
                                    {
                                        var m = Regex.Match(firstLine, @"\[(\d{2}):(\d{2}):(\d{2})\]");
                                        if (m.Success)
                                        {
                                            int hh = int.Parse(m.Groups[1].Value);
                                            int mm = int.Parse(m.Groups[2].Value);
                                            int ss = int.Parse(m.Groups[3].Value);
                                            logTime = new DateTime(fi.LastWriteTime.Year, fi.LastWriteTime.Month, fi.LastWriteTime.Day, hh, mm, ss);
                                        }
                                    }
                                }
                            }
                            catch { }

                            mcLaunchTime = logTime;
                            break;
                        }
                    }
                    catch { }
                }
            }

            if (!mcLaunchTime.HasValue)
            {
                return;
            }

            DateTime launch = mcLaunchTime.Value;
            var deletedModNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (logsDirs != null)
            {
                foreach (var lDir in logsDirs)
                {
                    string latestLog = Path.Combine(lDir, "latest.log");
                    if (!File.Exists(latestLog)) continue;

                    try
                    {
                        using (var fs = new FileStream(latestLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (var reader = new StreamReader(fs, Encoding.UTF8))
                        {
                            string line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                if (line.IndexOf("libraries", StringComparison.OrdinalIgnoreCase) >= 0)
                                    continue;

                                var matches = Regex.Matches(line, @"(?:[/\\]mods[/\\]|^mods[/\\])([a-zA-Z0-9_\.\-\+ ]+\.jar)", RegexOptions.IgnoreCase);
                                foreach (Match match in matches)
                                {
                                    string jarName = match.Groups[1].Value.Trim();
                                    string jarLower = jarName.ToLower();

                                    if (jarLower == "minecraft.jar" || jarLower == "client.jar" || jarLower == "server.jar" ||
                                        jarLower.Contains("mixin") || jarLower.Contains("authlib") || jarLower.Contains("intermediary") ||
                                        jarLower.Contains("sponge") || jarLower.Contains("lwjgl") || jarLower.Contains("fabric-loader") ||
                                        jarLower.Contains("forge") || jarLower.Contains("neoforge") || jarLower.Contains("log4j") ||
                                        jarLower.Contains("asm") || jarLower.Contains("guava") || jarLower.Contains("commons-") ||
                                        jarLower.Contains("netty") || jarLower.Contains("slf4j"))
                                    {
                                        continue;
                                    }

                                    bool existsInMods = false;
                                    foreach (var mDir in modsDirs)
                                    {
                                        if (File.Exists(Path.Combine(mDir, jarName)))
                                        {
                                            existsInMods = true;
                                            break;
                                        }
                                    }

                                    if (!existsInMods)
                                    {
                                        deletedModNames.Add(jarName);
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            }

            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (!drive.IsReady || drive.DriveType != DriveType.Fixed) continue;
                    string rbPath = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
                    if (!Directory.Exists(rbPath)) continue;

                    foreach (var userRb in Directory.GetDirectories(rbPath))
                    {
                        try
                        {
                            foreach (var iFile in Directory.GetFiles(userRb, "$I*.*"))
                            {
                                try
                                {
                                    var fi = new FileInfo(iFile);
                                    if (fi.Length < 28) continue;

                                    byte[] data = File.ReadAllBytes(iFile);
                                    long fileTime = BitConverter.ToInt64(data, 16);
                                    DateTime deletionUtc = DateTime.FromFileTimeUtc(fileTime);
                                    DateTime deletionLocal = deletionUtc.ToLocalTime();

                                    if (deletionLocal >= launch.AddSeconds(-5))
                                    {
                                        int version = BitConverter.ToInt32(data, 0);
                                        string originalPath = "";
                                        if (version == 2 && data.Length >= 28)
                                        {
                                            originalPath = Encoding.Unicode.GetString(data, 28, data.Length - 28).TrimEnd('\0');
                                        }
                                        else if (version == 1 && data.Length >= 24)
                                        {
                                            originalPath = Encoding.Unicode.GetString(data, 24, Math.Min(520, data.Length - 24)).TrimEnd('\0');
                                        }

                                        if (!string.IsNullOrEmpty(originalPath) &&
                                            (originalPath.IndexOf(@"\mods\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                             originalPath.IndexOf("/mods/", StringComparison.OrdinalIgnoreCase) >= 0) &&
                                            originalPath.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                                        {
                                            string modName = Path.GetFileName(originalPath);
                                            string modLower = modName.ToLower();
                                            if (!modLower.Contains("mixin") && !modLower.Contains("authlib") && !modLower.Contains("intermediary") &&
                                                !modLower.Contains("sponge") && !modLower.Contains("lwjgl") && !modLower.Contains("fabric-loader"))
                                            {
                                                deletedModNames.Add(modName);
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            if (isGameCurrentlyRunning && deletedModNames.Count == 0)
            {
                foreach (var mDir in modsDirs)
                {
                    try
                    {
                        var di = new DirectoryInfo(mDir);
                        if (di.LastWriteTime > launch.AddSeconds(15))
                        {
                            var currentFiles = di.GetFiles("*.jar");
                            bool hasNewFile = currentFiles.Any(f => f.CreationTime > launch.AddSeconds(10));
                            if (!hasNewFile)
                            {
                                deletedModNames.Add("(файл из папки mods)");
                            }
                        }
                    }
                    catch { }
                }
            }

            foreach (var mod in deletedModNames)
            {
                log($"После запуска майкрафта , был удален мод {mod}");
                banReasons.Add($"После запуска майкрафта , был удален мод {mod}");
            }
        }

        internal static int CheckRecentDownloads(Action<string> log, List<string> banReasons)
        {
            int warnings = 0;
            string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!Directory.Exists(downloads)) return 0;

            try
            {
                var files = Directory.GetFiles(downloads);
                foreach (var f in files)
                {
                    if (IsCheckerOrSelf(f)) continue;
                    string name = Path.GetFileName(f).ToLower();

                    bool matched = false;
                    foreach (var kw in CheatKeywords)
                    {
                        if (name.Contains(kw))
                        {
                            if (kw == "impact" && (name.Contains("genshin") || name.Contains("hoyoverse") || name.Contains("mihoyo") || name.Contains("hoyoplay")))
                                continue;

                            log($"Найден в загрузках: {Path.GetFileName(f)}");
                            banReasons.Add($"Найден в загрузках чит - {Path.GetFileName(f)} ({f})");
                            warnings++;
                            matched = true;
                            break;
                        }
                    }

                    if (!matched)
                    {
                        foreach (var rule in ForbiddenModRules)
                        {
                            if (rule.Keywords.Any(kw => name.Contains(kw)))
                            {
                                log($"Найден в загрузках: {Path.GetFileName(f)} ({rule.SummaryTag})");
                                banReasons.Add($"Найден в загрузках запрещенный софт - {Path.GetFileName(f)} ({rule.SummaryTag})");
                                warnings++;
                                matched = true;
                                break;
                            }
                        }
                    }

                    if (!matched && (name.EndsWith(".jar") || name.EndsWith(".zip") || name.EndsWith(".dll") || name.EndsWith(".disabled") || name.EndsWith(".bak")))
                    {
                        try
                        {
                            if (CheckDoomsdayJar(new FileInfo(f), out string dReason))
                            {
                                log($"Найден в загрузках чит Doomsday: {Path.GetFileName(f)} ({dReason})");
                                banReasons.Add($"Найден Doomsday - {f} ({dReason})");
                                warnings++;
                                matched = true;
                            }
                        }
                        catch { }
                    }

                    if (!matched)
                    {
                        try
                        {
                            var fi = new FileInfo(f);
                            if (fi.Length > 0 && fi.Length <= 35 * 1024 * 1024)
                            {
                                if (CheckSystemDlcInFile(fi, out string sSig))
                                {
                                    log($"Найден в загрузках чит SystemDLC: {Path.GetFileName(f)} (сигнатура {sSig})");
                                    banReasons.Add($"Найден SystemDLC - {f} ({sSig})");
                                    warnings++;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return warnings;
        }

        public static int CheckActiveJavaAndCheatProcesses(Action<string> log, List<string> banReasons)
        {
            int threats = 0;
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT ProcessId, Name, CommandLine FROM Win32_Process"))
                using (var objects = searcher.Get())
                {
                    foreach (ManagementObject obj in objects)
                    {
                        try
                        {
                            string pName = (obj["Name"] as string ?? "").ToLower();
                            string cmd = obj["CommandLine"] as string ?? "";
                            int pid = Convert.ToInt32(obj["ProcessId"]);
                            if (string.IsNullOrEmpty(cmd)) continue;

                            string cmdLower = cmd.ToLower();

                            if (cmdLower.Contains("-jar") && cmdLower.Contains(".dll"))
                            {
                                log($"Найден активный процесс запуска JAR под видом DLL: {pName} (PID {pid}) -> {cmd}");
                                banReasons.Add($"Запуск JAR под видом DLL (Doomsday) - {cmd}");
                                threats++;
                                continue;
                            }

                            if (cmdLower.Contains("doomsday") || cmdLower.Contains("doomday"))
                            {
                                log($"Найден активный процесс чита Doomsday: {pName} (PID {pid}) -> {cmd}");
                                banReasons.Add($"Активный процесс Doomsday (PID {pid}) - {cmd}");
                                threats++;
                                continue;
                            }

                            if (pName == "java.exe")
                            {
                                foreach (var kw in CheatKeywords)
                                {
                                    if (cmdLower.Contains(kw))
                                    {
                                        if (kw == "impact" && (cmdLower.Contains("genshin") || cmdLower.Contains("hoyoverse"))) continue;
                                        log($"Найден активный чит, запущенный через Java: {pName} (PID {pid}) -> {cmd}");
                                        banReasons.Add($"Активный чит в Java - {cmd}");
                                        threats++;
                                        break;
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return threats;
        }

        internal static int CheckSuspiciousProcesses(Action<string> log, List<string> banReasons)
        {
            int threats = 0;
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        string pName = proc.ProcessName.ToLower();
                        foreach (var kw in CheatKeywords)
                        {
                            if (pName.Contains(kw) && pName != "angelminechecker")
                            {
                                if (kw == "impact" && (pName.Contains("genshin") || pName.Contains("hoyoverse") || pName.Contains("mihoyo") || pName.Contains("hoyoplay")))
                                    continue;

                                log($"Найден активный процесс: {proc.ProcessName}.exe (PID: {proc.Id})");
                                banReasons.Add($"Активный процесс: {proc.ProcessName}.exe (PID: {proc.Id})");
                                threats++;
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            threats += CheckActiveJavaAndCheatProcesses(log, banReasons);

            return threats;
        }

    }
}
