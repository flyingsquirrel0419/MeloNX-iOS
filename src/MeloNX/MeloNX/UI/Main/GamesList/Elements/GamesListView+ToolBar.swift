//
//  GamesListView+ToolBar.swift
//  MeloNX
//
//  Created by Stossy11 on 10/11/2025.
//

import SwiftUI
import UniformTypeIdentifiers

extension GamesListView {
    func toolbarHandler() -> some ToolbarContent {
        if #available(iOS 19.0, *) {
            return Group {
                ToolbarItem(placement: .topBarTrailing) {
                    addGameButton
                }
                .sharedBackgroundVisibility(.hidden)
                
                ToolbarItem(placement: .topBarLeading) {
                    optionsSection
                }
                .sharedBackgroundVisibility(.hidden)
            }
        } else {
            return Group {
                ToolbarItem(placement: .topBarTrailing) {
                    addGameButton
                }
                
                ToolbarItem(placement: .topBarLeading) {
                    optionsSection
                }
            }
        }
    }
    
    
    private var addGameButton: some View {
        Button {
            FileImporterManager.shared.importFiles(types: [.nsp, .xci, .item]) { result in
                ryujinxController.handleAddingGame(result: result)
            }
        } label: {
            Label("Add Game", systemImage: "plus")
                .labelStyle(.iconOnly)
                .font(.system(size: 16, weight: .semibold))
        }
        .accentColor(.blue)
    }

    private var optionsSection: some View {
        Menu {
            firmwareSection
            
            Divider()
            
            Button {
                FileImporterManager.shared.importFiles(types: [.nsp, .xci, .item]) { result in
                    ryujinxController.handleRunningGame(result: result)
                }
            } label: {
                Label("Open Game", systemImage: "square.and.arrow.down")
            }
            
            Button {
                ryujinxController.loadGames()
            } label: {
                Label("Reload Games", systemImage: "arrow.clockwise")
            }
            
            
            Button {
                URL.documentsDirectory.openInFiles()
            } label: {
                Label("Show MeloNX Folder", systemImage: "folder")
            }
            
            Divider()
            
            Button {
                self.activeSheet = .account
            } label: {
                Label("Profile Manager", systemImage: "person.2")
            }
            
        } label: {
            Label("Options", systemImage: "ellipsis.circle")
                .labelStyle(.iconOnly)
                .foregroundColor(.blue)
        }
    }

    private var firmwareSection: some View {
        Group {
            if ryujinxController.firmwareInstallState.isInstalling {
                Button {} label: {
                    Label("Installing Firmware\u{2026}", systemImage: "hourglass")
                }
                .disabled(true)
            } else if ryujinxController.firmwareInstalled {
                Section("Firmware: \(ryujinxController.firmwareVersion)") {
                    Menu("Applets") {
                        Button {
                            let game = GameInfo(containerFolder: URL(string: "none")!, fileType: .item, fileURL: URL(string: "0x0100000000001009")!, titleName: "Mii Maker", titleId: "0", developer: "Nintendo", version: ryujinxController.firmwareVersion)
                            self.ryujinxController.startGame(game)
                        } label: {
                            Label("Launch Mii Maker", systemImage: "person.crop.circle")
                        }
                    }
                    
                    Button {
                        importFirmware()
                    } label: {
                        Label("Update Firmware", systemImage: "arrow.down.circle")
                    }
                }
            } else {
                Button {
                    importFirmware()
                } label: {
                    Label("Install Firmware", systemImage: "square.and.arrow.down")
                }
            }
        }
    }
    
    private func importFirmware() {
        FileImporterManager.shared.importFiles(types: [.folder, .zip, .xci], securityScoped: false) { result in
            ryujinxController.handleFirmwareImport(result: result)
        }
    }
    
    // moved the context stuff here because i felt it was cluttering up GamesListView
    // MARK: context stuff :3 -
    
    func gameContextMenu(for game: GameInfo) -> some View {
        Group {
            Section {
                Button {
                    ryujinxController.startGame(game)
                } label: {
                    Label("Play Now", systemImage: "play.fill")
                }
                
                Button {
                    activeSheet = .gameInfo(game: game)
                } label: {
                    Label("Game Info", systemImage: "info.circle")
                }
                
                Button {
                    activeSheet = .perGameSettings(game: game)
                } label: {
                    Label("\(game.titleName) Settings", systemImage: ryujinxController.hasPerGameConfig(game.titleId) ? "checkmark.circle" : "gear")
                }
                
                Button {
                    controllerEditor = game
                } label: {
                    Label("Controller Layout", systemImage: "formfitting.gamecontroller")
                }
            }
            
            Section {
                Button {
                    activeSheet = .update(game: game)
                } label: {
                    Label("Update Manager", systemImage: "arrow.up.circle")
                }
                
                Button {
                    activeSheet = .dlc(game: game)
                } label: {
                    Label("DLC Manager", systemImage: "plus.circle")
                }
                
                Button {
                    activeSheet = .mods(game: game)
                } label: {
                    Label("Mod Manager", systemImage: "folder.circle")
                }

                if NativePrep.profile(for: game.titleId) != nil {
                    Button {
                        activeSheet = .nativePrep(game: game)
                    } label: {
                        Label("Native Mode", systemImage: "bolt.circle")
                    }
                }
                
                Menu {
                    ForEach(SaveDataType.allCases) { type in
                        Button {
                            ryujinxController.openSaveDirectory(for: game, type: type)
                        } label: {
                            Label(type.name, systemImage: type.symbol)
                        }
                    }
                } label: {
                    Label("Open Save Directory", systemImage: "folder")
                }
            }
            
            Section {
                
                Button(role: .destructive) {
                    ryujinxController.clearShaderCacheWithConfirmation(game)
                } label: {
                    Label("Clear Shader Cache", systemImage: "trash")
                }
                
                Button(role: .destructive) {
                    deleteGame(game: game)
                } label: {
                    Label("Delete Game", systemImage: "trash")
                }
            }
        }
    }
    
    func gameContextUIMenu(for index: Int) -> UIMenu {
        let game = ryujinxController.games[index]
        
        let playAction = UIAction(
            title: "Play Now",
            image: UIImage(systemName: "play.fill")
        ) { _ in
            ryujinxController.startGame(game)
        }
        
        let infoAction = UIAction(
            title: "Game Info",
            image: UIImage(systemName: "info.circle")
        ) { _ in
            activeSheet = .gameInfo(game: game)
        }
        
        let settingsAction = UIAction(
            title: "\(game.titleName) Settings",
            image: UIImage(systemName: ryujinxController.hasPerGameConfig(game.titleId) ? "checkmark.circle" : "gear")
        ) { _ in
            activeSheet = .perGameSettings(game: game)
        }
        
        let controllerLayoutAction = UIAction(
            title: "Controller Layout",
            image: UIImage(systemName: "formfitting.gamecontroller")
        ) { _ in
            controllerEditor = game
        }
        
        let coreSection = UIMenu(
            title: "",
            options: .displayInline,
            children: [playAction, infoAction, settingsAction, controllerLayoutAction]
        )
        
        let updateAction = UIAction(
            title: "Update Manager",
            image: UIImage(systemName: "arrow.up.circle")
        ) { _ in
            activeSheet = .update(game: game)
        }
        
        let dlcAction = UIAction(
            title: "DLC Manager",
            image: UIImage(systemName: "plus.circle")
        ) { _ in
            activeSheet = .dlc(game: game)
        }
        
        let modsAction = UIAction(
            title: "Mod Manager",
            image: UIImage(systemName: "folder.circle")
        ) { _ in
            activeSheet = .mods(game: game)
        }
        
        let saveDirectoryMenu = UIMenu(
            title: "Open Save Directory",
            image: UIImage(systemName: "folder"),
            children: SaveDataType.allCases.map { type in
                UIAction(
                    title: type.name,
                    image: UIImage(systemName: type.symbol)
                ) { _ in
                    ryujinxController.openSaveDirectory(for: game, type: type)
                }
            }
        )
        
        let nativeActions: [UIMenuElement] = NativePrep.profile(for: game.titleId) == nil ? [] : [
            UIAction(title: "Native Mode", image: UIImage(systemName: "bolt.circle")) { _ in
                activeSheet = .nativePrep(game: game)
            }
        ]

        let managersSection = UIMenu(
            title: "",
            options: .displayInline,
            children: [updateAction, dlcAction, modsAction] + nativeActions + [saveDirectoryMenu]
        )
        
        let clearShaderCacheAction = UIAction(
            title: "Clear Shader Cache",
            image: UIImage(systemName: "trash"),
            attributes: .destructive
        ) { _ in
            ryujinxController.clearShaderCacheWithConfirmation(game)
        }
        
        let deleteGameAction = UIAction(
            title: "Delete Game",
            image: UIImage(systemName: "trash"),
            attributes: .destructive
        ) { _ in
            deleteGame(game: game)
        }
        
        let destructiveSection = UIMenu(
            title: "",
            options: .displayInline,
            children: [clearShaderCacheAction, deleteGameAction]
        )
        
        return UIMenu(
            title: "",
            children: [coreSection, managersSection, destructiveSection]
        )
    }
}

