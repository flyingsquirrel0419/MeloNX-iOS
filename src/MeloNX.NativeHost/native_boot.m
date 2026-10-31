// MeloNX native mode: starts nxnative's host inside MeloNX on a game prepared on the device (src/MeloNX.Native.Prep, Documents/NativeGames/<title ID>/).
// It takes the place of nxnative's dm/ios/Sources/main.m, which owns its app (main, UIApplicationMain, its scene delegate) and finds the game in its bundle: here the
// game is a folder the preparation wrote, and the host's view controller (front_ios.m) is presented over MeloNX's own window. What main.m's boot_env sets up, this
// sets from that folder:
//   patched/      the rewritten modules (argv[1] of the host: <module>.patched.bin, .fixups.tsv, .gates.tsv)
//   romfs.img     DM_ROMFS
//   save/ temp/   DM_SAVE, DM_TEMP
//   shaders/      DM_NVN_SHMAP (shader_map.tsv) and DM_MSL_DIR: the shader libraries, which the device does not make yet; an empty map lets the game run with its draws dropped
//   log.txt       the host's stderr (log.prev.txt keeps the one before)
//   env.txt       KEY=VALUE switches, as Documents/env.txt in nxnative's app
// The host runs once per process: it cannot be stopped and started again, and it ends the process when the game exits (hle_lifecycle.c).
#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "game_profile.h"
#include "front.h"

int dm_main(int argc, char **argv);   // dm/host/main.c compiled with -Dmain=dm_main
void dm_host_preload_start(int argc, char **argv);
UIViewController *front_ios_root(void);
void front_ios_focus_event(int ev);
void front_ios_audio_session(void);

static char *g_argv[4]; static int g_argc;
static int g_boot_ok;
static char g_message[640];

// front_ios.m asks these of main.m
const char *front_ios_boot_message(void) { return g_message[0] ? g_message : NULL; }
const char *front_ios_device_message(void) { return NULL; }   // checked before the launch (dm_native_launch)
int front_ios_boot_ok(void) { return g_boot_ok; }
// Launcher.swift: nxnative's own settings screen before the game, which MeloNX does not carry (its settings come from env.txt for now)
bool dm_show_launcher(void *view_controller, void (*done)(void)) { (void)view_controller; (void)done; return false; }

static void *boot_thread(void *p) {
    (void)p;
    static char alt[65536]; stack_t ss = {.ss_sp = alt, .ss_size = sizeof alt}; sigaltstack(&ss, 0);   // crash printing must work on the host thread too
    int rc = dm_main(g_argc, g_argv);
    fprintf(stderr, "boot: dm_main returned %d\n", rc);
    return NULL;
}
void front_ios_boot(void) {   // front_ios.m, once its Metal view exists
    static int once; if (once++ || !g_boot_ok) return;
    front_ios_audio_session();
    pthread_attr_t a; pthread_attr_init(&a); pthread_attr_setstacksize(&a, 64u << 20);
    pthread_t t; pthread_create(&t, &a, boot_thread, NULL); pthread_detach(t);
}

static void apply_env_file(NSString *path) {
    NSString *txt = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    for (NSString *raw in [txt componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *ln = [raw stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet]; NSRange eq = [ln rangeOfString:@"="];
        if (!ln.length || [ln hasPrefix:@"#"] || eq.location == NSNotFound || !eq.location) continue;
        NSString *k = [ln substringToIndex:eq.location], *v = [ln substringFromIndex:eq.location + 1];
        setenv(k.UTF8String, v.UTF8String, 1);
        fprintf(stderr, "boot: env %s=%s (env.txt)\n", k.UTF8String, v.UTF8String);
    }
}

static UIViewController *top_view_controller(void) {
    UIWindow *key = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if (![s isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *w in ((UIWindowScene *)s).windows) if (w.isKeyWindow) key = w;
        if (!key) key = ((UIWindowScene *)s).windows.firstObject;
    }
    UIViewController *vc = key.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

// The scene's lifecycle, as main.m's scene delegate hands it to front_ios.m
static void observe_lifecycle(void) {
    NSNotificationCenter *nc = NSNotificationCenter.defaultCenter;
    NSArray *names = @[UIApplicationWillResignActiveNotification, UIApplicationDidEnterBackgroundNotification, UIApplicationWillEnterForegroundNotification, UIApplicationDidBecomeActiveNotification];
    for (int i = 0; i < 4; i++) [nc addObserverForName:names[i] object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *n) { (void)n; front_ios_focus_event(i); }];
}

// Called by the app (NativeLaunch.swift) on the main thread. Returns NULL when the game is starting, else why it cannot (a static string).
// The app finds it with dlsym: used keeps the executable's dead stripping from dropping it
__attribute__((used, visibility("default"))) const char *dm_native_launch(const char *game_dir_c, const char *title_id, const char *language) {
    static int launched;
    if (launched) return "native mode already ran a game in this session: close MeloNX and open it again";
    if (!dm_select_game(title_id)) return "this build has no native mode profile for the game";
    id<MTLDevice> gpu = MTLCreateSystemDefaultDevice();
    if (!gpu.supportsBCTextureCompression) return "this device's GPU cannot read BC-compressed textures (it needs an A17 Pro / M1 or later)";
    if (@available(iOS 26.0, *)) { if (![gpu supportsFamily:MTLGPUFamilyMetal4]) return "this device's GPU has no Metal 4, which native mode's graphics need"; }
    else return "native mode needs iOS 26 or later (Metal 4)";

    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *dir = @(game_dir_c);
    NSString *patched = [dir stringByAppendingPathComponent:@"patched"], *romfs = [dir stringByAppendingPathComponent:@"romfs.img"];
    if (![fm fileExistsAtPath:patched] || ![fm fileExistsAtPath:romfs]) return "the game is not prepared (no patched/ or romfs.img)";
    launched = 1;

    for (NSString *d in @[@"save", @"temp", @"shaders"]) [fm createDirectoryAtPath:[dir stringByAppendingPathComponent:d] withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *log = [dir stringByAppendingPathComponent:@"log.txt"], *prev = [dir stringByAppendingPathComponent:@"log.prev.txt"];
    [fm removeItemAtPath:prev error:nil]; [fm moveItemAtPath:log toPath:prev error:nil];
    if (freopen(log.fileSystemRepresentation, "w", stderr)) setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(stderr, "boot: MeloNX native mode, game %s (%s), folder %s\n", title_id, DM_GAME_NAME, game_dir_c);

    apply_env_file([dir stringByAppendingPathComponent:@"env.txt"]);
    front_hud_env();
    if (language && *language && !getenv("DM_LANG")) setenv("DM_LANG", language, 0);
    fprintf(stderr, "boot: game language %s\n", getenv("DM_LANG") ?: "en-US");

    NSString *shmap = [dir stringByAppendingPathComponent:@"shaders/shader_map.tsv"];
    if (![fm fileExistsAtPath:shmap]) {
        [@"# no shaders: the device does not make the shader libraries yet; every draw is dropped\n" writeToFile:shmap atomically:YES encoding:NSUTF8StringEncoding error:nil];
        fprintf(stderr, "[RED] boot: no shader map: the game runs with its draws dropped (no picture)\n");
    }
    setenv("DM_ROMFS", romfs.fileSystemRepresentation, 0);
    setenv("DM_SAVE", [dir stringByAppendingPathComponent:@"save"].fileSystemRepresentation, 0);
    setenv("DM_TEMP", [dir stringByAppendingPathComponent:@"temp"].fileSystemRepresentation, 0);
    setenv("DM_NVN_SHMAP", shmap.fileSystemRepresentation, 0);
    setenv("DM_MSL_DIR", [dir stringByAppendingPathComponent:@"shaders/msl"].fileSystemRepresentation, 0);
    setenv("DM_FONT_DIR", [dir stringByAppendingPathComponent:@"font"].fileSystemRepresentation, 0);
    chdir(dir.fileSystemRepresentation);
    g_argv[0] = strdup("dmhost"); g_argv[1] = strdup(patched.fileSystemRepresentation); g_argc = 2;
    dm_host_preload_start(g_argc, g_argv);
    g_boot_ok = 1;

    observe_lifecycle();
    UIViewController *root = front_ios_root();
    root.modalPresentationStyle = UIModalPresentationFullScreen;
    [top_view_controller() presentViewController:root animated:NO completion:nil];
    return NULL;
}

// What the app calls (NativeLaunch.swift): an Objective-C class, which the app finds by name at run time (NSClassFromString), so a build without the host still links
// and the executable's dead stripping and symbol stripping cannot hide it
@interface DmNativeLauncher : NSObject
+ (NSString *)launchGameAt:(NSString *)dir titleId:(NSString *)titleId;
@end
@implementation DmNativeLauncher
+ (NSString *)launchGameAt:(NSString *)dir titleId:(NSString *)titleId {
    const char *err = dm_native_launch(dir.fileSystemRepresentation, titleId.UTF8String, NULL);
    return err ? @(err) : nil;
}
@end
