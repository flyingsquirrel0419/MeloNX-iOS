//
//  GamesListView.swift
//  MeloNX
//
//  Created by Stossy11 on 10/11/2025.
//

import SwiftUI
import UniformTypeIdentifiers
import Melo_Controller

enum ActiveSheet: Identifiable, Equatable{
    case gameInfo(game: GameInfo)
    case perGameSettings(game: GameInfo)
    // needs to be a full screen sheet so commented out
    // case gameController(game: Game)
    case dlc(game: GameInfo)
    case update(game: GameInfo)
    case mods(game: GameInfo)
    case nativePrep(game: GameInfo)
    case account

    var id: String {
        switch self {
        case .gameInfo(let game),
             .perGameSettings(let game),
             // .gameController(let game),
             .dlc(let game),
             .mods(let game),
             .nativePrep(let game),
             .update(let game):
            return "\(type(of: self))-\(game.id)"
        case .account:
            return "account"
        }
    }
}



func bindingGame(_ game: Binding<GameInfo?>) -> Binding<Bool> {
    Binding(
        get: { game.wrappedValue != nil },
        set: { newValue in
            if !newValue {
                game.wrappedValue = nil
            }
        }
    )
}

extension UTType {
    static let nsp = UTType(exportedAs: "com.nintendo.switch-package")
    static let xci = UTType(exportedAs: "com.nintendo.switch-cartridge")
}

struct GamesListView: View {
    @EnvironmentObject public var ryujinxController: RyujinxController
    @StateObject var nativeSettings = NativeSettingsManager.shared
    @State var showingAccounts = false
    @State var activeSheet: ActiveSheet?
    @State var controllerEditor: GameInfo?
    
    // Theme
    @Environment(\.appTheme) var theme
    
    // CarouselView
    @State var selectedIndex: Int = 0
    
    @State var spinTrigger: Int = 0
    @State var spinReset: Bool = false
    
    var controllerEdit: Binding<Bool> {
        bindingGame($controllerEditor)
    }
    
    @Environment(\.horizontalSizeClass) var horizontalSizeClass
    @Environment(\.verticalSizeClass) var verticalSizeClass
    
    var games: Binding<[GameInfo]> {
        Binding(
            get: { ryujinxController.games },
            set: { ryujinxController.games = $0 }
        )
    }
    
    var body: some View {
        NavigationStack {
            VStack {
                if ryujinxController.games.isEmpty {
                    emptyStateView
                        .toolbar {
                            toolbarHandler()
                        }
                } else {
                    Group {
                        switch nativeSettings.cardLayout(CardType.card).value {
                        case .list:
                            GameRowsView(games: ryujinxController.games, isActive: isNavigable) { game in
                                ryujinxController.startGame(game)
                            } menu: { game in
                                gameContextMenu(for: game)
                            }
                            .modifier(HiddenScrollBackground())
                            .themedBackground()
                            .toolbar {
                                toolbarHandler()
                            }
                        case .carousel:
                            ZStack {
                                Text("")
                                    .toolbar {
                                        toolbarHandler()
                                    }
                                
                                let cartridges: [CartridgeData] = ryujinxController.games.compactMap({ CartridgeData(labelImage: $0.icon ?? UIImage(), colors: [UIColor(hex: "171717"), .yellow]) })
                                
                                CartridgeCarouselView(cartridges: cartridges, selectedIndex: $selectedIndex, uiMenu: gameContextUIMenu, spinTrigger: $spinTrigger, reset: $spinReset, spun: { index in
                                    let game = ryujinxController.games[index]
                                    DispatchQueue.main.async {
                                        ryujinxController.startGame(game)
                                    }
                                })
                                .menuNavigation(isActive: isNavigable) { event in
                                    navigateCarousel(event)
                                }
                            }
                            .modifier(HiddenScrollBackground())
                            .themedBackground()
                            .if(!(horizontalSizeClass == .compact && verticalSizeClass == .regular)) { view in
                                view
                                    .ignoresSafeArea(.all, edges: UIDevice.current.userInterfaceIdiom == .pad ? .bottom : .top)
                            }
                            
                        default:
                            GameGridView(
                                games: ryujinxController.games,
                                cardType: nativeSettings.cardLayout(CardType.card).value,
                                isActive: isNavigable
                            ) { game in
                                ryujinxController.startGame(game)
                            } menu: { game in
                                gameContextMenu(for: game)
                            }
                            .modifier(HiddenScrollBackground())
                            .themedBackground()
                            .toolbar {
                                toolbarHandler()
                            }
                        }
                    }
                }
            }
        }
        .overlay {
            if ryujinxController.isJITEnabled {
                VStack {
                    HStack {
                        Spacer()
                        Circle()
                            .frame(width: 12, height: 12)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .foregroundColor(checkAppEntitlement("com.apple.developer.kernel.increased-memory-limit") ? Color.green : Color.orange)
                            .padding()
                    }
                    Spacer()
                }
                .offset(x: 0, y: -25)
            }
        }
        .navigationTitle("Library")
        .accentColor(theme.accent.primary)
        .fullScreenCover(isPresented: controllerEdit) {
            ControllerView(controller: VirtualControllerManager.shared, isEditing: true, gameId: controllerEditor?.titleId ?? "", gameName: controllerEditor?.titleName)
                .interactiveDismissDisabled(true)
        }
        .sheet(item: $activeSheet) { sheet in
            switch sheet {
            case .gameInfo(let game):
                GameInfoSheet(game: game)
            case .perGameSettings(let game):
                PerGameSettingsView(game.titleId)
            case .dlc(let game):
                DLCManagerSheet(game: game)
            case .update(let game):
                UpdateManagerSheet(game: game)
            case .mods(let game):
                ModsManagerSheet(game: game)
            case .nativePrep(let game):
                if #available(iOS 16.0, *) {
                    NativePrepSheet(game: game)
                }
            case .account:
                AccountManagerView()
            }
        }
    }
    
    private var emptyStateView: some View {
        Group {
            if #available(iOS 17, *) {
                ContentUnavailableView(
                    "No Games Found",
                    systemImage: "square.and.arrow.down",
                    description: Text("Tap the + button to add legally dumped ROMs!")
                )
            } else {
                VStack(spacing: 20) {
                    Spacer()
                    
                    Image(systemName: "square.and.arrow.down")
                        .font(.system(size: 64))
                        .foregroundColor(.secondary)
                    
                    Text("No Games Found")
                        .font(.title2)
                        .fontWeight(.semibold)
                    
                    Text("Tap the + button to add legally dumped ROMs!")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                    
                    Spacer()
                }
                .frame(maxWidth: .infinity)
                .listRowInsets(EdgeInsets())
            }
        }
    }
    
    
    
    private var isNavigable: Bool {
        activeSheet == nil && controllerEditor == nil
    }
    
    private func navigateCarousel(_ event: MenuNavigation) {
        guard !ryujinxController.games.isEmpty else { return }

        switch event {
        case .left:
            selectedIndex = max(0, selectedIndex - 1)

        case .right:
            selectedIndex = min(ryujinxController.games.count - 1, selectedIndex + 1)

        case .confirm:
            spinTrigger += 1

        case .up, .down, .cancel:
            break
        }
    }

    func deleteGame(game: GameInfo) {
        let fileManager = FileManager.default
        do {
            try fileManager.removeItem(at: game.fileURL)
            
        } catch {
        }
    }
}

struct ClearListBackground: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        DispatchQueue.main.async {
            view.superview?.superview?.backgroundColor = .clear
        }
        return view
    }
    func updateUIView(_ uiView: UIView, context: Context) {}
}

struct HiddenScrollBackground: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 16.0, *) {
            content.scrollContentBackground(.hidden)
        } else {
            content
                .background(ClearListBackground())
                .onAppear {
                    UITableView.appearance().backgroundColor = .clear
                }
        }
    }
}
