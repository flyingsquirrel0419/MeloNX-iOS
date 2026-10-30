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

@_silgen_name("native_prepare")
fileprivate func native_prepare(_ basePath: UnsafePointer<CChar>, _ updatePath: UnsafePointer<CChar>?, _ root: UnsafePointer<CChar>,
                                _ tablesPath: UnsafePointer<CChar>, _ profilesPath: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("free_native_string")
fileprivate func free_native_string(_ ptr: UnsafeMutablePointer<CChar>)
