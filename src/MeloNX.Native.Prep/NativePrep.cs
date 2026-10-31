using LibHac.Common.Keys;
using MeloNX.Native.Prep.Extract;
using MeloNX.Native.Prep.Rewriter;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace MeloNX.Native.Prep
{
    public sealed record NativeProfile(string Id, string Name, string[] Modules);

    // The game profiles the app carries (native_profiles.json, written by tools/native/gen_profiles.py at app build time)
    public static class NativeProfiles
    {
        public static List<NativeProfile> Load(string path)
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.EnumerateArray()
                      .Select(e => new NativeProfile(e.GetProperty("id").GetString(), e.GetProperty("name").GetString(),
                                                     e.GetProperty("modules").EnumerateArray().Select(m => m.GetString()).ToArray()))
                      .ToList();
        }

        public static NativeProfile Find(IEnumerable<NativeProfile> profiles, string titleId) =>
            profiles.FirstOrDefault(p => string.Equals(p.Id, titleId, StringComparison.OrdinalIgnoreCase));
    }

    // One game's preparation for native mode, on the device: what nxnative's scripts/build_ipa_from_nsp.py does on a Mac up to the rewrite (its extract and rewrite stages),
    // into <root>/<title ID>/:
    //   ExeFS/                      the code modules as extracted (kept, so a newer rewriter can run again without the game file)
    //   romfs.img                   the merged RomFS (DM_ROMFS)
    //   patched/<module>.*          the rewriter's outputs, the host's module directory (dmhost <dir>)
    //   control.nacp, icon.jpg
    //   native.json                 what was prepared, from what, by which rewriter (written last: its presence means the preparation finished)
    //   prep.log                    the last preparation's log, written as it goes: what is left of it when the app was stopped (out of memory, say)
    // Not yet: the NROs a game loads from its RomFS (nro.tsv), add-on content, and the shader steps.
    public static class NativePrep
    {
        public const int Version = 1;   // bump when the outputs change, so the app prepares again

        public sealed class Request
        {
            public KeySet Keys;
            public string BasePath, UpdatePath;   // UpdatePath may be null
            public string Root;                   // Documents/NativeGames
            public string TablesPath, ProfilesPath;
            public Action<string> Log;
            public Action<string, double> Stage;  // stage name, fraction done (0..1) within it
            public Func<long> FreeMemory;         // bytes the app may still allocate (iOS: os_proc_available_memory), logged before each module's rewrite; may be null
        }

        public static string Run(Request q)
        {
            var sink = q.Log ?? (_ => { });
            var stage = q.Stage ?? ((_, _) => { });
            var profiles = NativeProfiles.Load(q.ProfilesPath);
            var early = new List<string>();
            StreamWriter file = null;
            void log(string line)
            {
                sink(line);
                if (file == null) { early.Add(line); return; }
                file.WriteLine(line);
            }
            try
            {
                return Run(q, profiles, log, stage, early, f => file = f);
            }
            catch (Exception e)
            {
                file?.WriteLine("[RED] " + e);   // into prep.log only: the caller reports the error itself
                throw;
            }
            finally { file?.Dispose(); }
        }

        static string Run(Request q, List<NativeProfile> profiles, Action<string> log, Action<string, double> stage, List<string> early, Action<StreamWriter> openLog)
        {

            stage("identify", 0);
            string title = GameExtractor.TitleOf(q.Keys, q.BasePath) ?? throw new ExtractError("the game file has no content meta: is it a game NSP or XCI?");
            var profile = NativeProfiles.Find(profiles, title) ?? throw new ExtractError($"{title} has no native mode profile");
            log($"profile {profile.Id} ({profile.Name}), modules {string.Join(' ', profile.Modules)}");

            string dir = Path.Combine(q.Root, profile.Id.ToUpperInvariant());
            Directory.CreateDirectory(dir);
            File.Delete(Path.Combine(dir, "native.json"));
            var file = new StreamWriter(Path.Combine(dir, "prep.log"), append: false) { AutoFlush = true };
            foreach (var line in early) file.WriteLine(line);
            openLog(file);
            var watch = Stopwatch.StartNew();

            stage("extract", 0);
            var ex = GameExtractor.Run(q.Keys, q.BasePath, q.UpdatePath, dir, log, (done, total) => stage("extract", total > 0 ? (double)done / total : 1));
            log($"extracted in {watch.Elapsed.TotalSeconds:F1} s");

            string version = RewriteModules(dir, profile, PatchTables.Load(q.TablesPath), ex.BuildIds, log, f => stage("rewrite", f), q.FreeMemory);

            var info = new Dictionary<string, object>
            {
                ["prep_version"] = Version,
                ["title_id"] = profile.Id,
                ["name"] = ex.Name.Length > 0 ? ex.Name : profile.Name,
                ["display_version"] = ex.DisplayVersion,
                ["registered_version"] = version,
                ["modules"] = profile.Modules,
                ["build_ids"] = ex.BuildIds,
                ["romfs_files"] = ex.RomFsFiles,
                ["romfs_bytes"] = ex.RomFsBytes,
                ["base"] = Path.GetFileName(q.BasePath),
                ["update"] = q.UpdatePath == null ? null : Path.GetFileName(q.UpdatePath),
                ["seconds"] = Math.Round(watch.Elapsed.TotalSeconds, 1),
            };
            File.WriteAllText(Path.Combine(dir, "native.json"), JsonSerializer.Serialize(info, PrepJson.Default.DictionaryStringObject));
            log($"prepared in {watch.Elapsed.TotalSeconds:F1} s: {dir}");
            return dir;
        }

        // The rewriter on every module the profile lists, from <dir>/ExeFS into <dir>/patched (replaced whole, only once every module is rewritten).
        // Returns the registered display version of these modules' build, or null for a build the profile does not register
        public static string RewriteModules(string dir, NativeProfile profile, PatchTables tables, Dictionary<string, string> buildIds, Action<string> log, Action<double> progress = null,
                                            Func<long> freeMemory = null)
        {
            string version = RegisteredVersion(tables, profile.Id, buildIds);
            log(version != null ? $"registered build: version {version}" : "[RED] this build is not registered in the profile: the rewriter falls back on function matching, and the game may not boot");
            string patched = Path.Combine(dir, "patched"), tmp = patched + ".partial";
            if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
            Directory.CreateDirectory(tmp);
            int count = profile.Modules.Length;
            for (int i = 0; i < count; i++)
            {
                string m = profile.Modules[i], src = Path.Combine(dir, "ExeFS", m);
                progress?.Invoke((double)i / count);
                if (!File.Exists(src)) throw new ExtractError($"the game has no {m} module, which the profile lists");
                var watch = Stopwatch.StartNew();
                var mod = Nso.Read(src);
                string free = freeMemory == null ? "" : $", {freeMemory() / 1048576} MB free";
                log($"{m}: rewriting {mod.TextEnd / 1048576.0:F1} MB of code{free}");
                int at = i;
                var options = new RewriteOptions { Profile = profile.Id, Progress = progress == null ? null : f => progress((at + f) / count) };
                var result = PatchNso.Rewrite(mod, m, tables, options);
                File.WriteAllBytes(Path.Combine(tmp, m + ".patched.bin"), result.PatchedBin);
                foreach (var (file, text) in result.Files) File.WriteAllText(Path.Combine(tmp, file), text);
                File.WriteAllLines(Path.Combine(tmp, $"rewrite_{m}.log"), result.Log);
                log($"{m}: rewritten in {watch.Elapsed.TotalSeconds:F1} s");
            }
            if (Directory.Exists(patched)) Directory.Delete(patched, true);
            Directory.Move(tmp, patched);
            progress?.Invoke(1);
            return version;
        }

        // The display version of the profile's build row whose module build IDs all match the extracted modules, or null
        static string RegisteredVersion(PatchTables tables, string profile, Dictionary<string, string> buildIds)
        {
            foreach (var row in tables.BuildRows.GetValueOrDefault(profile) ?? new List<string[]>())
            {
                if (row.Length < 4 || row[0] != "build") continue;
                bool all = true, any = false;
                foreach (var cell in row.Skip(3))
                {
                    int eq = cell.IndexOf('='); if (eq < 0) continue;
                    any = true;
                    if (!buildIds.TryGetValue(cell[..eq], out var bid) || !string.Equals(bid, cell[(eq + 1)..], StringComparison.OrdinalIgnoreCase)) all = false;
                }
                if (any && all) return row[2];
            }
            return null;
        }
    }

    [System.Text.Json.Serialization.JsonSerializable(typeof(Dictionary<string, object>))]
    [System.Text.Json.Serialization.JsonSerializable(typeof(string))]
    [System.Text.Json.Serialization.JsonSerializable(typeof(string[]))]
    [System.Text.Json.Serialization.JsonSerializable(typeof(Dictionary<string, string>))]
    [System.Text.Json.Serialization.JsonSerializable(typeof(long))]
    [System.Text.Json.Serialization.JsonSerializable(typeof(int))]
    [System.Text.Json.Serialization.JsonSerializable(typeof(double))]
    [System.Text.Json.Serialization.JsonSourceGenerationOptions(WriteIndented = true)]
    internal partial class PrepJson : System.Text.Json.Serialization.JsonSerializerContext { }
}
