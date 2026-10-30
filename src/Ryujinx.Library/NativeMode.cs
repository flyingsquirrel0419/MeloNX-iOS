using MeloNX.Native.Prep;
using MeloNX.Native.Prep.Rewriter;
using Ryujinx.Common.Callbacks;
using Ryujinx.Common.Configuration;
using Ryujinx.Common.Logging;
using Ryujinx.Common.Utilities;
using Ryujinx.HLE.FileSystem;
using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Ryujinx.Library
{
    // Native mode (nxnative's engine inside MeloNX): the preparation of a game on the device. The Swift side calls these from a background thread.
    // Progress goes to the callback Swift registers as "native_prep" (RegisterCallback), one UTF-8 line per call:
    //   "log\t<text>"                    a line of the preparation's log
    //   "stage\t<name>\t<fraction>"      identify / extract / rewrite, and how far it is (0..1)
    class NativeMode
    {
        private const string Callback = "native_prep";

        private static readonly TitleUpdateMetadataJsonSerializerContext _titleSerializerContext = new(JsonHelper.GetDefaultSerializerOptions());

        // Prepares the game at basePath (NSP or XCI) into <root>/<title ID>/. updatePath may be NULL: then the update MeloNX has selected for the game, if any.
        // Returns NULL on success, else the error (free with free_native_string).
        [UnmanagedCallersOnly(EntryPoint = "native_prepare")]
        public static nint Prepare(nint basePathPtr, nint updatePathPtr, nint rootPtr, nint tablesPathPtr, nint profilesPathPtr)
        {
            try
            {
                string basePath = Marshal.PtrToStringUTF8(basePathPtr);
                string updatePath = updatePathPtr == 0 ? null : Marshal.PtrToStringUTF8(updatePathPtr);
                var keys = Library.VirtualFileSystem?.KeySet ?? throw new InvalidOperationException("MeloNX is not initialized (no key set)");
                if (updatePath == null)
                {
                    string title = MeloNX.Native.Prep.Extract.GameExtractor.TitleOf(keys, basePath);
                    updatePath = SelectedUpdate(title);
                }
                NativePrep.Run(new NativePrep.Request
                {
                    Keys = keys,
                    BasePath = basePath,
                    UpdatePath = updatePath,
                    Root = Marshal.PtrToStringUTF8(rootPtr),
                    TablesPath = Marshal.PtrToStringUTF8(tablesPathPtr),
                    ProfilesPath = Marshal.PtrToStringUTF8(profilesPathPtr),
                    Log = Log,
                    Stage = (name, fraction) => Send($"stage\t{name}\t{fraction.ToString("F3", CultureInfo.InvariantCulture)}"),
                });
                return 0;
            }
            catch (Exception e)
            {
                Log($"[RED] {e}");
                return Marshal.StringToCoTaskMemUTF8(e.Message);
            }
        }

        // The rewrite alone, on a game prepared before (its ExeFS kept): after an app update brings a newer rewriter or patch tables, without the game file
        [UnmanagedCallersOnly(EntryPoint = "native_rewrite")]
        public static nint Rewrite(nint gameDirPtr, nint titleIdPtr, nint tablesPathPtr, nint profilesPathPtr)
        {
            try
            {
                string dir = Marshal.PtrToStringUTF8(gameDirPtr), title = Marshal.PtrToStringUTF8(titleIdPtr);
                var profile = NativeProfiles.Find(NativeProfiles.Load(Marshal.PtrToStringUTF8(profilesPathPtr)), title)
                              ?? throw new InvalidOperationException($"{title} has no native mode profile");
                var buildIds = MeloNX.Native.Prep.Extract.GameExtractor.BuildIds(Path.Combine(dir, "ExeFS"));
                NativePrep.RewriteModules(dir, profile, PatchTables.Load(Marshal.PtrToStringUTF8(tablesPathPtr)), buildIds, Log,
                                          f => Send($"stage\trewrite\t{f.ToString("F3", CultureInfo.InvariantCulture)}"));
                return 0;
            }
            catch (Exception e)
            {
                Log($"[RED] {e}");
                return Marshal.StringToCoTaskMemUTF8(e.Message);
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "free_native_string")]
        public static void FreeString(nint ptr)
        {
            if (ptr != 0) Marshal.FreeCoTaskMem(ptr);
        }

        private static void Log(string line)
        {
            Logger.Info?.Print(LogClass.Application, $"native: {line}");
            Send($"log\t{line}");
        }

        private static void Send(string line) => CallbackRegistry.Invoke(Callback, Encoding.UTF8.GetBytes(line));

        // The update MeloNX's update manager selected for the title (games/<title ID>/updates.json), as GameInfo reads it
        private static string SelectedUpdate(string titleId)
        {
            if (!ulong.TryParse(titleId, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong id)) return null;
            string meta = Path.Combine(AppDataManager.GamesDirPath, (id & ~0xFUL).ToString("x16"), "updates.json");
            if (!File.Exists(meta)) return null;
            string path = JsonHelper.DeserializeFromFile(meta, _titleSerializerContext.TitleUpdateMetadata).Selected;
            if (string.IsNullOrEmpty(path)) return null;
            if (OperatingSystem.IsIOS()) path = Path.Combine(AppDataManager.BaseDirPath, path);
            return File.Exists(path) ? path : null;
        }
    }
}
