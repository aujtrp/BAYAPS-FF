/*
 * il2cpp/patch_metadata.js
 * BAYAPS-FF — Frida script: hook IL2CPP runtime + patch sensitive methods
 * ALPHA XK / ALPHA يعمل
 *
 * Run:
 *   frida -H 127.0.0.1:6767 -f com.dts.freefireth -l patch_metadata.js --no-pause
 */

'use strict';

const LOG_PREFIX = '[ALPHA XK]';

const IL2CPP_LIB = 'libil2cpp.so';

// ── Target patterns in method names ────────────────
const TARGET_PATTERNS = [
    /AntiCheat/i,
    /Integrity/i,
    /Detect/i,
    /Hooked/i,
    /Tampered/i,
    /IsDebug/i,
    /VerifySignature/i,
    /AntiDebug/i,
    /CheckRoot/i,
    /DetectFrida/i,
    /DetectMagisk/i,
];

// ── Target IL2CPP exports ──────────────────────────
const IL2CPP_EXPORTS = [
    'il2cpp_runtime_invoke',
    'il2cpp_string_new',
    'il2cpp_class_from_name',
    'il2cpp_method_get_name',
    'il2cpp_class_get_method_from_name',
];

// ── Logger ─────────────────────────────────────────
function log(tag, msg) {
    console.log(`${LOG_PREFIX}[${tag}] ${msg}`);
}

// ── Wait for libil2cpp to load ─────────────────────
function waitForIl2Cpp(callback) {
    let tries = 0;
    const timer = setInterval(() => {
        tries++;
        const mod = Process.findModuleByName(IL2CPP_LIB);
        if (mod) {
            clearInterval(timer);
            log('il2cpp', `${IL2CPP_LIB} @ ${mod.base} size=${mod.size}`);
            callback(mod);
            return;
        }
        if (tries >= 30) {
            clearInterval(timer);
            log('il2cpp', 'gave up after 30 tries');
        }
    }, 500);
}

// ── Hook il2cpp_runtime_invoke ─────────────────────
function hookRuntimeInvoke(mod) {
    const addr = mod.findExportByName('il2cpp_runtime_invoke');
    if (!addr) {
        log('invoke', 'il2cpp_runtime_invoke not found');
        return;
    }

    log('invoke', `hooking @ ${addr}`);

    Interceptor.attach(addr, {
        onEnter(args) {
            this.block = false;

            try {
                // MethodInfo layout (IL2CPP 24+):
                //   +0x00: methodPointer
                //   +0x08: invoker_method
                //   +0x10: name (char*)
                const methodInfo = args[0];
                if (methodInfo.isNull()) return;

                const namePtr = methodInfo.add(0x10).readPointer();
                if (namePtr.isNull()) return;

                const name = namePtr.readCString();
                if (!name) return;

                // Check against patterns
                for (const pat of TARGET_PATTERNS) {
                    if (pat.test(name)) {
                        log('invoke', `intercepted: ${name}`);
                        this.block = true;
                        this.name = name;
                        return;
                    }
                }
            } catch (e) {
                // structure mismatch — ignore
            }
        },
        onLeave(retval) {
            if (this.block) {
                retval.replace(ptr(0));
            }
        }
    });
}

// ── Hook il2cpp_string_new ─────────────────────────
function hookStringNew(mod) {
    const addr = mod.findExportByName('il2cpp_string_new');
    if (!addr) return;

    log('string', `hooking @ ${addr}`);

    Interceptor.attach(addr, {
        onEnter(args) {
            this.block = false;
            try {
                const str = args[0].readCString();
                if (!str) return;
                if (/frida|magisk|zygisk|hooked|tampered/i.test(str)) {
                    log('string', `sanitized: ${str.slice(0, 60)}`);
                    args[0] = Memory.allocUtf8String('');
                    this.block = true;
                }
            } catch (e) {}
        }
    });
}

// ── Hook il2cpp_class_get_method_from_name ─────────
function hookMethodLookup(mod) {
    const addr = mod.findExportByName('il2cpp_class_get_method_from_name');
    if (!addr) return;

    log('lookup', `hooking @ ${addr}`);

    Interceptor.attach(addr, {
        onEnter(args) {
            this.block = false;
            try {
                const namePtr = args[1];
                if (namePtr.isNull()) return;
                const name = namePtr.readCString();
                if (!name) return;

                for (const pat of TARGET_PATTERNS) {
                    if (pat.test(name)) {
                        log('lookup', `blocked method lookup: ${name}`);
                        this.block = true;
                        return;
                    }
                }
            } catch (e) {}
        },
        onLeave(retval) {
            if (this.block) {
                retval.replace(ptr(0));
            }
        }
    });
}

// ── Anti-debug: clock_gettime jitter ───────────────
function patchClock() {
    const addr = Module.findExportByName(null, 'clock_gettime');
    if (!addr) return;

    log('clock', 'hooking clock_gettime');

    Interceptor.attach(addr, {
        onEnter(args) {
            this.tv = args[1];
        },
        onLeave() {
            // add small jitter to timing checks
            try {
                const tv = this.tv;
                if (tv && !tv.isNull()) {
                    const nsec = tv.add(8).readU64();
                    tv.add(8).writeU64(nsec.add(100));
                }
            } catch (e) {}
        }
    });
}

// ── Bootstrap ──────────────────────────────────────
function bootstrap() {
    log('init', 'patch_metadata.js loaded');

    waitForIl2Cpp((mod) => {
        hookRuntimeInvoke(mod);
        hookStringNew(mod);
        hookMethodLookup(mod);
        patchClock();
        log('ready', 'il2cpp hooks active');
    });
}

setImmediate(bootstrap);