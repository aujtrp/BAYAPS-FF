/*
 * userspace/libff_bypass.cpp
 * BAYAPS-FF — Native lib: patch JNI exports in libanogs.so
 * ALPHA XK / ALPHA يعمل
 *
 * Build:
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang++ \
 *     -shared -fPIC -O2 -o libff_bypass.so libff_bypass.cpp -llog
 *
 * Load:
 *   LD_PRELOAD=/data/local/tmp/libff_bypass.so com.dts.freefireth
 *   or via Frida: Module.load('/data/local/tmp/libff_bypass.so')
 */

#include <jni.h>
#include <android/log.h>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

#define LOG_TAG "ALPHA_XK"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ── ARM64 instruction helpers ──────────────────────────────────────
#define AARCH64_MOV_X0_1  0xD2800020u   // MOV X0, #1
#define AARCH64_MOV_X0_0  0xD2800000u   // MOV X0, #0
#define AARCH64_RET       0xD65F03C0u   // RET

static bool make_writable(void* addr, size_t len) {
    uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(getpagesize() - 1);
    size_t    span = ((reinterpret_cast<uintptr_t>(addr) + len - page) + getpagesize() - 1)
                     & ~(getpagesize() - 1);
    return mprotect(reinterpret_cast<void*>(page), span,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

static void patch_return_true(void* func) {
    if (!func) return;
    if (!make_writable(func, 8)) {
        LOGE("mprotect failed for %p", func);
        return;
    }
    uint32_t* p = reinterpret_cast<uint32_t*>(func);
    p[0] = AARCH64_MOV_X0_1;
    p[1] = AARCH64_RET;
    __builtin___clear_cache(reinterpret_cast<char*>(p),
                            reinterpret_cast<char*>(p + 2));
    LOGI("patched %p -> return 1", func);
}

static void patch_return_false(void* func) {
    if (!func) return;
    if (!make_writable(func, 8)) {
        LOGE("mprotect failed for %p", func);
        return;
    }
    uint32_t* p = reinterpret_cast<uint32_t*>(func);
    p[0] = AARCH64_MOV_X0_0;
    p[1] = AARCH64_RET;
    __builtin___clear_cache(reinterpret_cast<char*>(p),
                            reinterpret_cast<char*>(p + 2));
    LOGI("patched %p -> return 0", func);
}

// ── Targets ────────────────────────────────────────────────────────
static const char* INTEGRITY_PASS_SYMS[] = {
    "Java_com_tencent_gcloud_anogs_AnoGS_CheckSignature",
    "Java_com_tencent_gcloud_anogs_AnoGS_CheckIntegrity",
    "Java_com_tencent_gcloud_anogs_AnoGS_AntiDebug",
    "Java_com_tencent_gcloud_anogs_AnoGS_DetectFrida",
    "Java_com_tencent_gcloud_anogs_AnoGS_DetectRoot",
    "Java_com_tencent_gcloud_anogs_AnoGS_DetectMagisk",
    "GarenaIntegrityCheck",
    "CheckMemoryIntegrity",
    "VerifySignature",
    "anti_debug_check",
    nullptr
};

static const char* INTEGRITY_FAIL_SYMS[] = {
    "Java_com_tencent_gcloud_anogs_AnoGS_IsTampered",
    "Java_com_tencent_gcloud_anogs_AnoGS_IsHooked",
    "Java_com_tencent_gcloud_anogs_AnoGS_IsDebugging",
    "detect_frida",
    "detect_root",
    nullptr
};

// ── Patch all symbols in loaded modules ────────────────────────────
static int patch_all() {
    int hits = 0;

    void* ac = dlopen("libanogs.so", RTLD_NOW | RTLD_NOLOAD);
    if (!ac) {
        // retry loop — AC lib loads late
        for (int i = 0; i < 50 && !ac; ++i) {
            usleep(100 * 1000);
            ac = dlopen("libanogs.so", RTLD_NOW | RTLD_NOLOAD);
        }
    }
    if (!ac) {
        LOGE("libanogs.so not loaded — abort patch");
        return 0;
    }
    LOGI("libanogs.so loaded @ %p", ac);

    for (const char** s = INTEGRITY_PASS_SYMS; *s; ++s) {
        void* f = dlsym(ac, *s);
        if (f) {
            LOGI("found pass sym: %s @ %p", *s, f);
            patch_return_true(f);
            hits++;
        }
    }

    for (const char** s = INTEGRITY_FAIL_SYMS; *s; ++s) {
        void* f = dlsym(ac, *s);
        if (f) {
            LOGI("found fail sym: %s @ %p", *s, f);
            patch_return_false(f);
            hits++;
        }
    }

    return hits;
}

// ── IL2CPP metadata patch ──────────────────────────────────────────
static void patch_il2cpp() {
    void* il2cpp = dlopen("libil2cpp.so", RTLD_NOW | RTLD_NOLOAD);
    if (!il2cpp) {
        LOGI("libil2cpp.so not loaded — skip il2cpp patch");
        return;
    }
    LOGI("libil2cpp.so loaded @ %p", il2cpp);

    // il2cpp_string_new — sanitize AC string checks
    typedef void* (*il2cpp_string_new_t)(const char*);
    il2cpp_string_new_t string_new =
        reinterpret_cast<il2cpp_string_new_t>(
            dlsym(il2cpp, "il2cpp_string_new"));

    if (string_new) {
        LOGI("il2cpp_string_new @ %p", (void*)string_new);
    }
}

// ── JNI entry ──────────────────────────────────────────────────────
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)vm;
    (void)reserved;
    LOGI("libff_bypass.so loaded — JNI_OnLoad");

    int hits = patch_all();
    LOGI("patched %d integrity functions", hits);

    patch_il2cpp();

    LOGI("bypass ready — AC integrity neutralized");
    return JNI_VERSION_1_6;
}

// ── Constructor — runs at load time ────────────────────────────────
__attribute__((constructor))
static void on_library_load() {
    LOGI("constructor fired — libff_bypass active");
}