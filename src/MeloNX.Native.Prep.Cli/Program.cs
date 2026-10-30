using MeloNX.Native.Prep;
using MeloNX.Native.Prep.Rewriter;
using System;
using System.IO;

// nxrewrite: the C# rewriter with patch_nso.py's command line, for checking the port against the Python tool on a Mac or Linux machine.
// Usage: nxrewrite <NSO file> <output dir> <module name> --tables <patch_tables.json>   (DM_GAME, DM_PATCH_FRONT and DM_SPIN_LIST as for patch_nso.py)
//        nxrewrite --prepared <game dir> <title ID> --tables <patch_tables.json> --profiles <native_profiles.json>: the app's rewrite step (NativePrep.RewriteModules)
//          on <game dir>/ExeFS, into <game dir>/patched
if (args.Length == 4 && args[0] == "--frame-step")
{
    // The stub of a build run on a recording context at a given patch position and state page: what tools/native/frame_step_test.py compares with the Python stub
    var rec = new RecordingContext(Hex(args[2]), Hex(args[3]));
    FrameSteps.Run(args[1], null, rec);
    foreach (var e in rec.Events) Console.WriteLine(e);
    Console.WriteLine($"render_scale {rec.RenderScale}");
    return 0;
}
if (args.Length == 7 && args[0] == "--prepared" && args[3] == "--tables" && args[5] == "--profiles")
{
    var profile = NativeProfiles.Find(NativeProfiles.Load(args[6]), args[2]);
    if (profile == null) { Console.Error.WriteLine($"[RED] {args[2]} has no native mode profile"); return 1; }
    string ver = NativePrep.RewriteModules(args[1], profile, PatchTables.Load(args[4]), MeloNX.Native.Prep.Extract.GameExtractor.BuildIds(Path.Combine(args[1], "ExeFS")), Console.WriteLine);
    Console.WriteLine($"version {ver ?? "-"}");
    return 0;
}
if (args.Length < 5 || args[3] != "--tables")
{
    Console.Error.WriteLine("usage: nxrewrite <NSO file> <output dir> <module name> --tables <patch_tables.json>");
    return 2;
}
string src = args[0], outdir = args[1], name = args[2];
NsoModule mod;
try { mod = Nso.Read(src); }
catch (NsoError e) { Console.Error.WriteLine($"[RED] {e.Message}"); return 1; }
var tables = PatchTables.Load(args[4]);
string front = Environment.GetEnvironmentVariable("DM_PATCH_FRONT");
var options = new RewriteOptions
{
    Profile = Path.GetFileName((Environment.GetEnvironmentVariable("DM_GAME") ?? "").TrimEnd('/')),
    PatchFront = string.IsNullOrEmpty(front) ? null : Convert.ToInt64(front, front.StartsWith("0x") ? 16 : 10),
    SpinList = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DM_SPIN_LIST")),
};
var result = PatchNso.Rewrite(mod, name, tables, options);
Directory.CreateDirectory(outdir);
File.WriteAllBytes(Path.Combine(outdir, name + ".patched.bin"), result.PatchedBin);
foreach (var (file, text) in result.Files) File.WriteAllText(Path.Combine(outdir, file), text);
foreach (var line in result.Log) Console.WriteLine(line);
return 0;

static partial class Program
{
    static long Hex(string s) => s.StartsWith('-') ? -Convert.ToInt64(s[1..], 16) : Convert.ToInt64(s, 16);
}

sealed class RecordingContext : IFrameStepContext
{
    private readonly long _base;
    public readonly System.Collections.Generic.List<string> Events = new();
    private int _n;
    public RecordingContext(long @base, long state) { _base = @base; State = state; }
    public long State { get; }
    public int RenderScale { get; set; }
    public long Here() => _base + 4 * _n;
    public void Emit(long w) { Events.Add($"emit {(uint)w:x8}"); _n++; }
    public void Site(long off, string orig) => Events.Add($"site {off:x} {orig}");
    public void Put(long off, System.Collections.Generic.IReadOnlyList<long> words, string why) =>
        Events.Add($"put {off:x} {string.Join(",", System.Linq.Enumerable.Select(words, w => ((uint)w).ToString("x8")))} {why}");
}
