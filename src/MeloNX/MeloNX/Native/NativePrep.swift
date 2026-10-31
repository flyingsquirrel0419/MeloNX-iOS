//
//  NativePrep.swift
//  MeloNX
//
//  Native mode (nxnative's engine inside MeloNX): preparing a supported game on the device.
//  The work is done by native_prepare in Ryujinx.Library (src/Ryujinx.Library/NativeMode.cs, MeloNX.Native.Prep):
//  the game's code and RomFS are extracted with MeloNX's keys and the code is rewritten, into Documents/NativeGames/<title ID>/.
//  The bundle carries the profiles (native_profiles.json) and the rewriter's patch tables (patch_tables.json), generated at build time by tools/native.
//

import Foundation
import ObjectiveC

struct NativeProfile: Decodable {
    let id: String
    let name: String
    let modules: [String]
}

enum NativePrepStage: String {
    case identify, extract, rewrite
}

final class NativePrep {
    static let prepVersion = 1   // NativePrep.Version in MeloNX.Native.Prep: a game prepared by an older version is prepared again

    static var root: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("NativeGames", isDirectory: true)
    }

    static var profilesURL: URL? { Bundle.main.url(forResource: "native_profiles", withExtension: "json") }
    static var tablesURL: URL? { Bundle.main.url(forResource: "patch_tables", withExtension: "json") }

    static let profiles: [String: NativeProfile] = {
        guard let url = profilesURL, let data = try? Data(contentsOf: url),
              let list = try? JSONDecoder().decode([NativeProfile].self, from: data) else { return [:] }
        return Dictionary(list.map { ($0.id.uppercased(), $0) }, uniquingKeysWith: { a, _ in a })
    }()

    static func profile(for titleId: String) -> NativeProfile? {
        profiles[titleId.uppercased()]
    }

    static func directory(for titleId: String) -> URL {
        root.appendingPathComponent(titleId.uppercased(), isDirectory: true)
    }

    // native.json, written last by the preparation, with this app's preparation version
    static func isPrepared(_ titleId: String) -> Bool {
        let url = directory(for: titleId).appendingPathComponent("native.json")
        guard let data = try? Data(contentsOf: url),
              let info = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return (info["prep_version"] as? Int) == prepVersion
    }

    // prep.log: the last preparation's log, written as it went, so what happened is still there when iOS stopped the app during it
    static func lastLog(_ titleId: String) -> [String] {
        let url = directory(for: titleId).appendingPathComponent("prep.log")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    }

    // log.txt: the host's log of the last launch (src/MeloNX.NativeHost/native_boot.m), what is left of it when the game crashed
    // with launch.txt before it: the launch's own steps, which also cover a crash before log.txt opens
    static func launchLog(_ titleId: String) -> String? {
        let dir = directory(for: titleId)
        let parts = ["launch.txt", "log.txt"].compactMap { try? String(contentsOf: dir.appendingPathComponent($0), encoding: .utf8) }
        return parts.isEmpty ? nil : parts.joined(separator: "\n")
    }

    private static let queue = DispatchQueue(label: "melonx.native.prep", qos: .userInitiated)

    // Prepares the game at gameURL (NSP or XCI; the update MeloNX has selected for it is applied). The handlers run on the main queue.
    static func prepare(gameURL: URL,
                        onLog: @escaping (String) -> Void,
                        onStage: @escaping (NativePrepStage, Double) -> Void,
                        completion: @escaping (String?) -> Void) {
        guard let profilesURL, let tablesURL else {
            completion("This build has no native mode tables (native_profiles.json, patch_tables.json).")
            return
        }
        queue.async {
            CallbackManager.register(name: "native_prep") { data in
                guard let line = data.string else { return }
                let parts = line.split(separator: "\t", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
                DispatchQueue.main.async {
                    if parts.count == 3, parts[0] == "stage", let stage = NativePrepStage(rawValue: parts[1]) {
                        onStage(stage, Double(parts[2]) ?? 0)
                    } else if parts.count >= 2, parts[0] == "log" {
                        onLog(parts[1...].joined(separator: "\t"))
                    }
                }
            }
            try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

            let error: String? = gameURL.path.withCString { base in
                root.path.withCString { rootPtr in
                    tablesURL.path.withCString { tables in
                        profilesURL.path.withCString { profiles in
                            guard let err = native_prepare(base, nil, rootPtr, tables, profiles) else { return nil }
                            defer { free_native_string(err) }
                            return String(cString: err)
                        }
                    }
                }
            }
            CallbackManager.unregister(name: "native_prep")
            DispatchQueue.main.async { completion(error) }
        }
    }
}

// Starting a prepared game: nxnative's host, linked into the app by CI (tools/native/build_ios_host.sh). Its entry is an Objective-C class found by name
// (src/MeloNX.NativeHost/native_boot.m), so a build without the host still links
enum NativeLaunch {
    // +[DmNativeLauncher launchGameAt:titleId:], called through its implementation: (class, selector, folder, title ID) -> error or nil
    private typealias LaunchImp = @convention(c) (AnyClass, Selector, NSString, NSString) -> Unmanaged<NSString>?
    private static let selector = NSSelectorFromString("launchGameAt:titleId:")

    private static var launchImp: (AnyClass, LaunchImp)? {
        guard let cls = NSClassFromString("DmNativeLauncher"), let method = class_getClassMethod(cls, selector) else { return nil }
        return (cls, unsafeBitCast(method_getImplementation(method), to: LaunchImp.self))
    }

    static var available: Bool { launchImp != nil }

    // Presents the game full screen over the app; returns why it cannot start, or nil. The host runs once per app session and closes the app when the game exits
    static func launch(titleId: String) -> String? {
        guard let (cls, imp) = launchImp else { return "This build has no native mode host." }
        guard NativePrep.isPrepared(titleId) else { return "The game is not prepared." }
        let dir = NativePrep.directory(for: titleId).path as NSString
        return imp(cls, selector, dir, titleId.uppercased() as NSString)?.takeUnretainedValue() as String?
    }
}

@_silgen_name("native_prepare")
fileprivate func native_prepare(_ basePath: UnsafePointer<CChar>, _ updatePath: UnsafePointer<CChar>?, _ root: UnsafePointer<CChar>,
                                _ tablesPath: UnsafePointer<CChar>, _ profilesPath: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("free_native_string")
fileprivate func free_native_string(_ ptr: UnsafeMutablePointer<CChar>)
