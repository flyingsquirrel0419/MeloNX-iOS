using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace MeloNX.Native.Prep.Rewriter
{
    public sealed record ObsEntry(long Offset, int Id, string Word, string Reason);

    // The registered patches of dm/tools/sdk_patches.py and dm/games/*/patches.py, as tools/native/convert_patches.py writes them at app build time (patch_tables.json),
    // with each profile's game.tsv build rows. FRAME_STEP stubs are C# code (FrameSteps.cs), named here by build ID
    public sealed class PatchTables
    {
        public Dictionary<string, List<Cut>> Cuts = new();
        public Dictionary<string, List<ObsEntry>> Obs = new();
        public HashSet<string> FrameStep = new();
        public Dictionary<string, Dictionary<string, List<MatchRule>>> MatchCuts = new();   // profile → module → rules
        public Dictionary<string, List<MatchRule>> SdkMatchCuts = new();                     // module → rules
        public Dictionary<string, List<string>> Capabilities = new();
        public Dictionary<string, List<string[]>> BuildRows = new();                         // profile → game.tsv "build" rows, cells stripped
        public Dictionary<string, string> FrameStepSources = new();                          // build ID → SHA-256 of the Python stub function's source

        public static PatchTables Load(string path) => Parse(File.ReadAllText(path));

        public static PatchTables Parse(string json)
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            var t = new PatchTables();
            foreach (var p in r.GetProperty("cuts").EnumerateObject()) t.Cuts[p.Name] = p.Value.EnumerateArray().Select(ParseCut).ToList();
            foreach (var p in r.GetProperty("obs").EnumerateObject())
                t.Obs[p.Name] = p.Value.EnumerateArray().Select(e => new ObsEntry(e[0].GetInt64(), e[1].GetInt32(), e[2].GetString(), e[3].GetString())).ToList();
            foreach (var p in r.GetProperty("frame_step").EnumerateObject()) { t.FrameStep.Add(p.Name); t.FrameStepSources[p.Name] = p.Value.GetString(); }
            foreach (var p in r.GetProperty("match_cuts").EnumerateObject())
                t.MatchCuts[p.Name] = p.Value.EnumerateObject().ToDictionary(m => m.Name, m => m.Value.EnumerateArray().Select(ParseRule).ToList());
            foreach (var p in r.GetProperty("sdk_match_cuts").EnumerateObject()) t.SdkMatchCuts[p.Name] = p.Value.EnumerateArray().Select(ParseRule).ToList();
            foreach (var p in r.GetProperty("capabilities").EnumerateObject()) t.Capabilities[p.Name] = p.Value.EnumerateArray().Select(e => e.GetString()).ToList();
            foreach (var p in r.GetProperty("build_rows").EnumerateObject())
                t.BuildRows[p.Name] = p.Value.EnumerateArray().Select(row => row.EnumerateArray().Select(c => c.GetString()).ToArray()).ToList();
            return t;
        }

        private static Cut ParseCut(JsonElement e) => new(e[0].GetInt64(), e[1].GetString(), e[2].GetString(), e[3].GetString());

        private static MatchRule ParseRule(JsonElement e)
        {
            var rule = new MatchRule();
            foreach (var p in e.EnumerateObject())
            {
                switch (p.Name)
                {
                    case "name": rule.Name = p.Value.GetString(); break;
                    case "size": rule.Size = p.Value.GetInt64(); break;
                    case "fingerprints": rule.Fingerprints = p.Value.EnumerateArray().Select(x => x.GetString()).ToList(); break;
                    case "cuts": rule.Cuts = p.Value.EnumerateArray().Select(ParseCut).ToList(); break;
                    case "functions": rule.Functions = p.Value.EnumerateArray().Select(ParseRule).ToList(); break;
                    default: throw new ArgumentException($"unknown match rule key {p.Name}");
                }
            }
            return rule;
        }
    }
}
