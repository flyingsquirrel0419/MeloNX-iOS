using LibHac;
using LibHac.Common;
using LibHac.Common.Keys;
using LibHac.Fs;
using LibHac.Fs.Fsa;
using LibHac.FsSystem;
using LibHac.Ncm;
using LibHac.Spl;
using LibHac.Tools.Fs;
using LibHac.Tools.FsSystem;
using LibHac.Tools.FsSystem.NcaUtils;
using LibHac.Tools.FsSystem.RomFs;
using LibHac.Tools.Ncm;
using System;
using System.Collections.Generic;
using System.IO;
using Path = System.IO.Path;

namespace MeloNX.Native.Prep.Extract
{
    public sealed class ExtractError : Exception
    {
        public ExtractError(string message) : base(message) { }
    }

    public sealed class Extracted
    {
        public string TitleId;              // the base program's, 16 lowercase hex digits
        public string DisplayVersion = "";
        public string Name = "";
        public Dictionary<string, string> BuildIds = new();   // ExeFS module → build ID (32 hex digits)
        public long RomFsFiles, RomFsBytes;
    }

    // nxnative's dm/tools/nx_extract (the NSP script's --romfs-image extraction) on MeloNX's LibHac, so the iPhone extracts its own game:
    // <out>/ExeFS/ expanded, the merged RomFS streamed into <out>/romfs.img (DMROMFS1, which dm/host/romfs_image.h mounts), and the control data (control.nacp, icon.jpg).
    // The base package may be an NSP or a cartridge dump (XCI); the update an NSP. Title keys come from the packages' common tickets; the other keys from MeloNX's key set.
    // Damaged files (a failed hash check) stop the extraction; nx_extract's --allow-damaged, legacy folder RomFS and manifest modes are left out.
    public static class GameExtractor
    {
        public static Extracted Run(KeySet keys, string basePath, string updatePath, string outDir, Action<string> log, Action<long, long> progress = null)
        {
            log ??= _ => { };
            var basePkg = OpenPackage(keys, basePath, ContentMetaType.Application, log);
            var updPkg = updatePath == null ? null : OpenPackage(keys, updatePath, null, log);
            Nca baseProg = Pick(basePkg, NcaContentType.Program) ?? throw new ExtractError("no Program NCA in the base package");
            Nca updProg = updPkg == null ? null : Pick(updPkg, NcaContentType.Program, baseProg.Header.TitleId) ?? throw new ExtractError("no Program NCA of the base game's program in the update");
            Nca ctrl = Pick(updPkg ?? basePkg, NcaContentType.Control, baseProg.Header.TitleId);
            var r = new Extracted { TitleId = baseProg.Header.TitleId.ToString("x16") };
            log($"title {r.TitleId}" + (updProg != null ? $", update {updProg.Header.TitleId:x16}" : ""));
            Directory.CreateDirectory(outDir);
            if (ctrl != null)
            {
                byte[] nacp = Nacp(ctrl);
                r.DisplayVersion = System.Text.Encoding.ASCII.GetString(nacp, 0x3060, 0x10).TrimEnd('\0');
                r.Name = TitleName(nacp);
                log($"display version {r.DisplayVersion}");
                File.WriteAllBytes(Path.Combine(outDir, "control.nacp"), nacp);
                var (icon, _) = Icon(ctrl);
                if (icon != null) File.WriteAllBytes(Path.Combine(outDir, "icon.jpg"), icon);
            }
            if (updProg == null && Sparse(baseProg)) throw new ExtractError("the base game's program is sparse: it can be read only with its update");

            // The update's ExeFS is complete; opened over the base it gives the same files
            IFileSystem exefs = updProg != null ? baseProg.OpenFileSystemWithPatch(updProg, NcaSectionType.Code, IntegrityCheckLevel.ErrorOnInvalid)
                                                : baseProg.OpenFileSystem(NcaSectionType.Code, IntegrityCheckLevel.ErrorOnInvalid);
            string exeDir = Path.Combine(outDir, "ExeFS");
            if (Directory.Exists(exeDir)) Directory.Delete(exeDir, true);
            Copy(exefs, exeDir);
            r.BuildIds = BuildIds(exeDir);
            foreach (var (m, bid) in r.BuildIds) log($"{m} build id {bid}");

            string image = Path.Combine(outDir, "romfs.img");
            if (!baseProg.SectionExists(NcaSectionType.Data) && (updProg == null || !updProg.SectionExists(NcaSectionType.Data)))
            {   // a program can carry all its assets in its code modules (ANIMAL WELL 1.0.10): an empty image
                WriteImage(null, image, r, progress);
                log("program has no data section: empty RomFS");
                return r;
            }
            IStorage romfs = updProg != null ? baseProg.OpenStorageWithPatch(updProg, NcaSectionType.Data, IntegrityCheckLevel.ErrorOnInvalid)
                                             : baseProg.OpenStorage(NcaSectionType.Data, IntegrityCheckLevel.ErrorOnInvalid);
            WriteImage(new RomFsFileSystem(romfs), image, r, progress);
            log($"romfs.img: {r.RomFsFiles} files {r.RomFsBytes / 1048576.0:F1} MB");
            return r;
        }

        // The build ID of every NSO module of an ExeFS folder (main, sdk, subsdk*, rtld...)
        public static Dictionary<string, string> BuildIds(string exeDir)
        {
            var ids = new SortedDictionary<string, string>(StringComparer.Ordinal);
            foreach (string p in Directory.GetFiles(exeDir))
            {
                if (new FileInfo(p).Length < 0x50) continue;
                byte[] h = new byte[0x50]; using (var f = File.OpenRead(p)) f.ReadExactly(h);
                if (h[0] == 'N' && h[1] == 'S' && h[2] == 'O' && h[3] == '0') ids[Path.GetFileName(p)] = Convert.ToHexString(h, 0x40, 16).ToLowerInvariant();
            }
            return new Dictionary<string, string>(ids);
        }

        // The title ID a package's meta NCAs name (the lowest: the base game's before an update's or a DLC's), or null
        public static string TitleOf(KeySet keys, string path)
        {
            ulong? id = null;
            foreach (Nca n in OpenPackage(keys, path, null, null))
                if (n.Header.ContentType == NcaContentType.Meta && (id == null || n.Header.TitleId < id)) id = n.Header.TitleId;
            return id?.ToString("x16");
        }

        static bool Sparse(Nca n)
        {
            for (int i = 0; i < 4; i++) if (n.Header.IsSectionEnabled(i) && n.Header.GetFsHeader(i).ExistsSparseLayer()) return true;
            return false;
        }

        static bool HashError(HorizonResultException e) => e.ResultValue.Module == 2 && e.ResultValue.Description >= 4600 && e.ResultValue.Description < 4700;

        // An NSP (PFS0) or an XCI's secure partition: its common tickets imported, its NCAs listed. With a content meta type, only the NCAs the package's content metas
        // of that type list: a cartridge dump that carries its update (1G+1U) holds the update's Program NCA under the same title ID
        static List<Nca> OpenPackage(KeySet keys, string path, ContentMetaType? only, Action<string> log)
        {
            IFileSystem pfs; var st0 = new LocalStorage(path, FileAccess.Read);
            byte[] magic = new byte[4]; st0.Read(0x100, magic).ThrowIfFailure();
            if (System.Text.Encoding.ASCII.GetString(magic) == "HEAD")
            {
                var xci = new Xci(keys, st0);
                if (!xci.HasPartition(XciPartitionType.Secure)) throw new ExtractError($"no secure partition in {Path.GetFileName(path)}");
                pfs = xci.OpenPartition(XciPartitionType.Secure);
            }
            else
            {
                var p = new PartitionFileSystem();
                if (p.Initialize(st0).IsFailure()) throw new ExtractError($"{Path.GetFileName(path)} is neither an NSP nor an XCI (NSZ and XCZ must be decompressed first)");
                pfs = p;
            }
            var ncas = new List<Nca>(); var ids = new List<string>();
            foreach (DirectoryEntryEx e in pfs.EnumerateEntries("*", SearchOptions.Default))
            {
                using var f = new UniqueRef<IFile>();
                pfs.OpenFile(ref f.Ref, e.FullPath.ToU8Span(), OpenMode.Read).ThrowIfFailure();
                IStorage st = f.Release().AsStorage();
                if (e.Name.EndsWith(".tik", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] t = new byte[0x2c0]; st.Read(0, t).ThrowIfFailure();
                    if (t[0x281] != 0) { log?.Invoke($"[RED] {e.Name} is not a common ticket"); continue; }
                    keys.ExternalKeySet.Add(new RightsId(t.AsSpan(0x2a0, 0x10)), new AccessKey(t.AsSpan(0x180, 0x10)));
                }
                else if (e.Name.EndsWith(".nca", StringComparison.OrdinalIgnoreCase))
                {
                    ncas.Add(new Nca(keys, st)); ids.Add(e.Name[..e.Name.IndexOf('.')].ToLowerInvariant());
                }
            }
            if (only == null) return ncas;
            var listed = new HashSet<string>();
            foreach (Nca n in ncas)
            {
                if (n.Header.ContentType != NcaContentType.Meta) continue;
                IFileSystem mfs = n.OpenFileSystem(NcaSectionType.Data, IntegrityCheckLevel.ErrorOnInvalid);
                foreach (DirectoryEntryEx e in mfs.EnumerateEntries("*.cnmt", SearchOptions.Default))
                {
                    using var f = new UniqueRef<IFile>();
                    mfs.OpenFile(ref f.Ref, e.FullPath.ToU8Span(), OpenMode.Read).ThrowIfFailure();
                    var cnmt = new Cnmt(f.Release().AsStream());
                    if (cnmt.Type == only) foreach (CnmtContentEntry c in cnmt.ContentEntries) listed.Add(Convert.ToHexString(c.NcaId).ToLowerInvariant());
                }
            }
            if (listed.Count == 0) return ncas;
            var kept = new List<Nca>(); int other = 0;
            for (int i = 0; i < ncas.Count; i++)
                if (listed.Contains(ids[i])) kept.Add(ncas[i]);
                else if (ncas[i].Header.ContentType != NcaContentType.Meta) other++;
            if (!kept.Exists(n => n.Header.ContentType == NcaContentType.Program))
            {   // renamed NCA files: nothing matches, so read every NCA
                log?.Invoke($"[RED] no NCA of {Path.GetFileName(path)} matches its {only} content meta by name (renamed NCA files?); reading all {ncas.Count}");
                return ncas;
            }
            if (other > 0) log?.Invoke($"leaving out {other} NCAs of {Path.GetFileName(path)} that its {only} content meta does not list (an update on the cartridge)");
            return kept;
        }

        // A multi-program application has a Program and a Control NCA per program index: with no title ID the lowest (program index 0, the game)
        static Nca Pick(List<Nca> l, NcaContentType t, ulong? id = null)
        {
            Nca r = null;
            foreach (Nca n in l)
                if (n.Header.ContentType == t && (id == null ? r == null || n.Header.TitleId < r.Header.TitleId : n.Header.TitleId == id)) r = n;
            return r;
        }

        static readonly string[] IconLangs = { "AmericanEnglish", "BritishEnglish", "Japanese", "French", "German", "LatinAmericanSpanish", "Spanish", "Italian",
                                               "Dutch", "CanadianFrench", "Portuguese", "Russian", "Korean", "TraditionalChinese", "SimplifiedChinese", "BrazilianPortuguese" };

        static (byte[], string) Icon(Nca ctrl)
        {
            IFileSystem fs = ctrl.OpenFileSystem(NcaSectionType.Data, IntegrityCheckLevel.ErrorOnInvalid);
            foreach (string lang in IconLangs)
            {
                using var f = new UniqueRef<IFile>();
                if (fs.OpenFile(ref f.Ref, $"/icon_{lang}.dat".ToU8Span(), OpenMode.Read).IsFailure()) continue;
                f.Get.GetSize(out long n).ThrowIfFailure();
                byte[] v = new byte[n]; f.Get.Read(out _, 0, v, ReadOption.None).ThrowIfFailure();
                return (v, lang);
            }
            return (null, null);
        }

        static byte[] Nacp(Nca ctrl)
        {
            IFileSystem fs = ctrl.OpenFileSystem(NcaSectionType.Data, IntegrityCheckLevel.ErrorOnInvalid);
            using var f = new UniqueRef<IFile>();
            fs.OpenFile(ref f.Ref, "/control.nacp".ToU8Span(), OpenMode.Read).ThrowIfFailure();
            f.Get.GetSize(out long n).ThrowIfFailure();
            byte[] v = new byte[n]; f.Get.Read(out _, 0, v, ReadOption.None).ThrowIfFailure();
            return v;
        }

        // The first non-empty name of the NACP's language entries; newer SDKs deflate those 0x3000 bytes (a u16 size + raw deflate, 32 languages × 0x300)
        static string TitleName(byte[] nacp)
        {
            byte[] t = nacp; int n = nacp[0] | nacp[1] << 8;
            if (n > 0 && n <= 0x2ffe)
                try
                {
                    using var z = new System.IO.Compression.DeflateStream(new MemoryStream(nacp, 2, n), System.IO.Compression.CompressionMode.Decompress);
                    var m = new MemoryStream(); z.CopyTo(m);
                    if (m.Length == 0x6000) t = m.ToArray();
                }
                catch (InvalidDataException) { }
            for (int i = 0; i < (t == nacp ? 16 : 32); i++)
            {
                int z = Array.IndexOf(t, (byte)0, i * 0x300, 0x200), len = (z < 0 ? i * 0x300 + 0x200 : z) - i * 0x300;
                if (len > 0) return System.Text.Encoding.UTF8.GetString(t, i * 0x300, len);
            }
            return "";
        }

        sealed class ImageEntry
        {
            public string Path; public byte[] Name; public bool Directory; public long Size; public ulong A, B;
            public List<ImageEntry> Children = new();
        }

        // The merged, integrity-checked RomFS streamed into one DMROMFS1 image: a 32-byte header, the file bytes, then the index (breadth first, each directory's children
        // sorted and contiguous) and its name pool. Byte for byte nx_extract's WriteImage, so the host's checks (romfs_image.h) hold
        static void WriteImage(IFileSystem fs, string dst, Extracted r, Action<long, long> progress)
        {
            var root = new ImageEntry { Path = "/", Name = Array.Empty<byte>(), Directory = true };
            var byPath = new Dictionary<string, ImageEntry>(StringComparer.Ordinal) { ["/"] = root };
            long total = 0;
            if (fs != null)
                foreach (DirectoryEntryEx e in fs.EnumerateEntries("*", SearchOptions.RecurseSubdirectories))
                {
                    string path = e.FullPath.TrimEnd('/'); if (path.Length == 0) continue;
                    byte[] name = System.Text.Encoding.UTF8.GetBytes(path.Substring(path.LastIndexOf('/') + 1));
                    if (name.Length == 0 || name.Length > 0x300) throw new IOException($"invalid RomFS name length: {path}");
                    bool dir = e.Type == DirectoryEntryType.Directory;
                    byPath.Add(path, new ImageEntry { Path = path, Name = name, Directory = dir, Size = e.Size });
                    if (!dir) total += e.Size;
                }
            foreach (var e in byPath.Values)
            {
                if (e == root) continue;
                string parent = e.Path.Substring(0, e.Path.LastIndexOf('/')); if (parent.Length == 0) parent = "/";
                byPath[parent].Children.Add(e);
            }
            var entries = new List<ImageEntry> { root };
            for (int i = 0; i < entries.Count; i++)
                if (entries[i].Directory)
                {
                    var e = entries[i]; e.Children.Sort((a, b) => a.Name.AsSpan().SequenceCompareTo(b.Name));
                    e.A = (ulong)entries.Count; e.B = (ulong)e.Children.Count; entries.AddRange(e.Children);
                }
            Directory.CreateDirectory(Path.GetDirectoryName(dst));
            string part = dst + ".part"; long files = 0, bytes = 0; var damaged = new List<string>();
            try
            {
                using (var output = File.Create(part))
                using (var writer = new BinaryWriter(output))
                {
                    writer.Write(new byte[32]); byte[] buffer = new byte[4 << 20];
                    foreach (var e in entries)
                    {
                        if (e.Directory) continue;
                        e.A = (ulong)output.Position; e.B = (ulong)e.Size; files++;
                        using var f = new UniqueRef<IFile>();
                        fs.OpenFile(ref f.Ref, e.Path.ToU8Span(), OpenMode.Read).ThrowIfFailure();
                        try { WriteStream(f.Get, output, e.Size, buffer); }
                        catch (HorizonResultException x) when (HashError(x)) { damaged.Add(e.Path); output.Position = (long)e.A; output.SetLength(output.Position); }
                        bytes += e.Size;
                        progress?.Invoke(bytes, total);
                    }
                    if (damaged.Count > 0)
                        throw new ExtractError($"the game files are damaged: {damaged.Count} files fail the NCA's hash check (first: {damaged[0]}); copy or download the game again");
                    long index = output.Position; using var names = new MemoryStream();
                    foreach (var e in entries)
                    {
                        writer.Write(e.A); writer.Write(e.B); writer.Write(checked((uint)names.Position));
                        writer.Write(checked((ushort)e.Name.Length)); writer.Write((byte)(e.Directory ? 0 : 1)); writer.Write((byte)0);
                        names.Write(e.Name);
                    }
                    names.Position = 0; names.CopyTo(output); long size = output.Position - index;
                    output.Position = 0; writer.Write(System.Text.Encoding.ASCII.GetBytes("DMROMFS1"));
                    writer.Write((ulong)index); writer.Write((ulong)size); writer.Write((ulong)entries.Count);
                }
                File.Move(part, dst, true);
                r.RomFsFiles = files; r.RomFsBytes = bytes;
            }
            catch { File.Delete(part); throw; }
        }

        static void WriteStream(IFile file, Stream output, long size, byte[] buffer)
        {
            for (long offset = 0; offset < size;)
            {
                file.Read(out long got, offset, buffer.AsSpan(0, (int)Math.Min(buffer.Length, size - offset)), ReadOption.None).ThrowIfFailure();
                if (got <= 0) throw new IOException($"cannot read @{offset}");
                output.Write(buffer, 0, (int)got); offset += got;
            }
        }

        static void Copy(IFileSystem fs, string dst)
        {
            byte[] buf = new byte[4 << 20];
            Directory.CreateDirectory(dst);
            foreach (DirectoryEntryEx e in fs.EnumerateEntries("*", SearchOptions.RecurseSubdirectories))
            {
                string op = Path.Combine(dst, e.FullPath.TrimStart('/'));
                if (e.Type == DirectoryEntryType.Directory) { Directory.CreateDirectory(op); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(op));
                using var f = new UniqueRef<IFile>();
                fs.OpenFile(ref f.Ref, e.FullPath.ToU8Span(), OpenMode.Read).ThrowIfFailure();
                using var o = File.Create(op);
                WriteStream(f.Get, o, e.Size, buf);
            }
        }
    }
}
