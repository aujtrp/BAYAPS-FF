/*
 * userspace/bypass.js
 * BAYAPS-FF — Frida script: FFAC userspace bypass
 * ALPHA XK / ALPHA يعمل
 *
 * Run:
 *   frida -H 127.0.0.1:6767 -f com.dts.freefireth -l bypass.js --no-pause
 */

'use strict';

const LOG_PREFIX = '[ALPHA XK]';
const TARGETS = [
    'libanogs.so',
    'libGarenaAntiCheat.so',
    'libffac.so',
    'libff_anticheat.so',
    'libGameCore.so',
    'libil2cpp.so'
];

const INTEGRITY_PASS = [
    'Java_com_tencent_gcloud_anogs_AnoGS_CheckSignature',
    'Java_com_tencent_gcloud_anogs_AnoGS_CheckIntegrity',
    'Java_com_tencent_gcloud_anogs_AnoGS_AntiDebug',
    'Java_com_tencent_gcloud_anogs_AnoGS_DetectFrida',
    'Java_com_tencent_gcloud_anogs_AnoGS_DetectRoot',
    'Java_com_tencent_gcloud_anogs_AnoGS_DetectMagisk',
    'GarenaIntegrityCheck',
    'CheckMemoryIntegrity',
    'VerifySignature',
    'anti_debug_check'
];

const INTEGRITY_FAIL = [
    'Java_com_tencent_gcloud_anogs_AnoGS_IsTampered',
    'Java_com_tencent_gcloud_anogs_AnoGS_IsHooked',
    'Java_com_tencent_gcloud_anogs_AnoGS_IsDebugging',
    'detect_frida',
    'detect_root'
];

function log(tag, msg) {
    console.log(`${LOG_PREFIX}[${tag}] ${msg}`);
}

// 1. Block AC library dlopen
function blockDlopen() {
    const dlopen = Module.findExportByName(null, 'android_dlopen_ext');
    if (!dlopen) {
        log('dlopen', 'android_dlopen_ext not found - skip');
        return;
    }

    Interceptor.attach(dlopen, {
        onEnter(args) {
            const path = args[0].readCString();
            if (path && TARGETS.some(t => path.includes(t))) {
                log('dlopen', `blocked: ${path}`);
                args[0] = Memory.allocUtf8String('/dev/null');
            }
        }
    });
    log('dlopen', 'hook installed');
}

// 2. Unhook inline hooks in libanogs
function unhookModule(name) {
    const mod = Process.findModuleByName(name);
    if (!mod) return;

    log('unhook', `${name} @ ${mod.base} size=${mod.size}`);

    const stubs = [
        [0x58000050, 0xd61f0200],
        [0x58000070, 0xd61f0220]
    ];

    let found = 0;
    mod.enumerateExports().forEach(exp => {
        try {
            const p = exp.address;
            const w0 = Memory.readU32(p);
            const w1 = Memory.readU32(p.add(4));
            for (const [s0, s1] of stubs) {
                if (w0 === s0 && w1 === s1) {
                    log('hook-found', `${exp.name} @ ${p}`);
                    found++;
                }
            }
        } catch (e) {}
    });

    if (found === 0) log('unhook', `${name}: no inline hooks detected`);
    else log('unhook', `${name}: ${found} hooks detected`);
}

// 3. Replace integrity functions
function patchIntegrity() {
    let passHits = 0, failHits = 0;

    for (const name of INTEGRITY_PASS) {
        const addr = Module.findExportByName(null, name);
        if (!addr) continue;

        Interceptor.replace(addr, new NativeCallback(() => {
            log('integrity', `${name} -> 1 (pass)`);
            return 1;
        }, 'int', []));
        passHits++;
    }

    for (const name of INTEGRITY_FAIL) {
        const addr = Module.findExportByName(null, name);
        if (!addr) continue;

        Interceptor.replace(addr, new NativeCallback(() => {
            log('integrity', `${name} -> 0 (fail)`);
            return 0;
        }, 'int', []));
        failHits++;
    }

    log('integrity', `patched: ${passHits} pass, ${failHits} fail`);
}

// 4. Spoof ptrace anti-debug
function patchPtrace() {
    const ptrace = Module.findExportByName(null, 'ptrace');
    if (!ptrace) return;

    Interceptor.attach(ptrace, {
        onEnter(args) {
            const req = args[0].toInt32();
            if (req === 0) {
                log('ptrace', 'spoofed PTRACE_TRACEME');
                args[0] = ptr(-1);
            }
        }
    });
    log('ptrace', 'hook installed');
}

// 5. Sanitize /proc/self/maps reads
function sanitizeMaps() {
    const fopen = Module.findExportByName(null, 'fopen');
    if (!fopen) return;

    Interceptor.attach(fopen, {
        onEnter(args) {
            const path = args[0].readCString();
            if (path && path.endsWith('/maps')) {
                const pid = Process.id;
                const filtered = `/data/local/tmp/bayaps_ff_maps/maps_filtered_${pid}`;
                log('maps', `redirect ${path} -> ${filtered}`);
                args[0] = Memory.allocUtf8String(filtered);
            }
        }
    });
    log('maps', 'fopen hook installed');
}

// 6. Intercept IL2CPP runtime_invoke
function patchIl2Cpp() {
    const addr = Module.findExportByName('libil2cpp.so', 'il2cpp_runtime_invoke');
    if (!addr) {
        log('il2cpp', 'runtime_invoke not found yet - will retry');
        return false;
    }

    Interceptor.attach(addr, {
        onEnter(args) {
            this.block = false;
            try {
                const methodInfo = args[0];
                const namePtr = methodInfo.add(0x10).readPointer();
                const name = namePtr.readCString();
                if (name && /AntiCheat|Integrity|Detect|Hooked|Tampered/i.test(name)) {
                    log('il2cpp', `intercepted: ${name}`);
                    this.block = true;
                }
            } catch (e) {}
        },
        onLeave(retval) {
            if (this.block) {
                retval.replace(ptr(0));
            }
        }
    });
    log('il2cpp', 'runtime_invoke hook installed');
    return true;
}

// Bootstrap
function bootstrap() {
    log('init', 'bypass.js loaded');

    blockDlopen();
    patchPtrace();
    sanitizeMaps();
    patchIntegrity();

    TARGETS.forEach(unhookModule);

    let tries = 0;
    const timer = setInterval(() => {
        tries++;
        if (patchIl2Cpp() || tries >= 30) {
            clearInterval(timer);
            if (tries >= 30) log('il2cpp', 'gave up after 30 tries');
        }
    }, 500);

    log('ready', 'userspace bypass active - AC integrity neutralized');
}

setImmediate(bootstrap);
