#!/system/bin/sh
#
# kernel/zygisk_detach.sh
# BAYAPS-FF — Detach FFAC + spoof build props
# ALPHA XK / ALPHA يعمل
#
# Run as root. Idempotent: safe to re-run.
# Requires: Magisk 26+, Zygisk enabled, Shamiko installed.

set -u

PKG_FF="com.dts.freefireth"
PKG_FFMAX="com.dts.freefiremax"
PKG_GMS="com.google.android.gms"
PKG_GMS_UNSTABLE="com.google.android.gms.unstable"
PKG_PLAY="com.google.android.play.games"

LOG_TAG="[ALPHA XK]"
ZYGISK_DB="/data/adb/zygisk"

log() {
    echo "$LOG_TAG $1"
    echo "$LOG_TAG $1" >> /data/local/tmp/bayaps_ff.log
}

# ── 1. Sanity checks ───────────────────────────────────────────────
if [ "$(id -u)" != "0" ]; then
    log "ERROR: must run as root"
    exit 1
fi

if [ ! -d /data/adb ]; then
    log "ERROR: Magisk not detected"
    exit 1
fi

if ! command -v resetprop >/dev/null 2>&1; then
    log "ERROR: resetprop not in PATH (install Magisk)"
    exit 1
fi

log "start — target: $PKG_FF"

# ── 2. ptrace_scope — allow attach ─────────────────────────────────
if [ -w /proc/sys/kernel/yama/ptrace_scope ]; then
    echo 0 > /proc/sys/kernel/yama/ptrace_scope
    log "ptrace_scope=0"
fi

# ── 3. Spoof build properties ──────────────────────────────────────
spoof_prop() {
    local key="$1"
    local val="$2"
    local cur
    cur="$(getprop "$key" 2>/dev/null)"
    if [ "$cur" != "$val" ]; then
        resetprop -n "$key" "$val" 2>/dev/null && \
            log "prop $key = $val (was: $cur)"
    fi
}

spoof_prop ro.build.tags            release-keys
spoof_prop ro.build.type            user
spoof_prop ro.build.user            android-build
spoof_prop ro.build.host            build-host
spoof_prop ro.debuggable            0
spoof_prop ro.secure                1
spoof_prop ro.adb.secure            1
spoof_prop ro.boot.verifiedbootstate green
spoof_prop ro.boot.flash.locked     1
spoof_prop ro.boot.vbmeta.device_state locked
spoof_prop ro.kernel.qemu           0
spoof_prop ro.hardware.keystore     samsung
spoof_prop ro.product.model         SM-G998B
spoof_prop ro.product.manufacturer  samsung
spoof_prop ro.product.brand         samsung
spoof_prop ro.product.device        o1s
spoof_prop ro.product.name          o1sxx
spoof_prop ro.build.fingerprint     samsung/o1sxx/o1s:13/TP1A.220624.014/G998BXXU5CVDD:user/release-keys
spoof_prop ro.magisk.hidden         1

# ── 4. Zygisk DenyList ─────────────────────────────────────────────
mkdir -p "$ZYGISK_DB"
for pkg in "$PKG_FF" "$PKG_FFMAX" "$PKG_GMS" "$PKG_GMS_UNSTABLE" "$PKG_PLAY"; do
    for f in denylist zygisk_denylist; do
        target="$ZYGISK_DB/$f"
        if [ -f "$target" ]; then
            grep -qxF "$pkg" "$target" || echo "$pkg" >> "$target"
        else
            echo "$pkg" > "$target"
        fi
    done
    log "denylist += $pkg"
done

# ── 5. Shamiko whitelist mode ──────────────────────────────────────
if [ -d /data/adb/shamiko ]; then
    touch /data/adb/shamiko/whitelist
    log "shamiko whitelist mode enabled"
fi

# ── 6. Stop / start FFAC service ───────────────────────────────────
stop_service() {
    local svc="$1"
    if command -v stop >/dev/null 2>&1; then
        stop "$svc" 2>/dev/null && log "stopped $svc"
    fi
}

start_service() {
    local svc="$1"
    if command -v start >/dev/null 2>&1; then
        start "$svc" 2>/dev/null && log "started $svc"
    fi
}

for svc in garena_ac ffac_service tencent_ac; do
    if [ -n "$(getprop | grep -i "$svc" 2>/dev/null)" ]; then
        stop_service "$svc"
        sleep 1
        start_service "$svc"
    fi
done

# ── 7. Kill running instances if service restart not enough ────────
for pkg in "$PKG_FF" "$PKG_FFMAX"; do
    pid="$(pidof "$pkg" 2>/dev/null)"
    if [ -n "$pid" ]; then
        log "killing $pkg (pid=$pid) — restart manually"
        kill -9 "$pid" 2>/dev/null
    fi
done

# ── 8. Verify ──────────────────────────────────────────────────────
sleep 1
VB_STATE="$(getprop ro.boot.verifiedbootstate)"
TAGS="$(getprop ro.build.tags)"
DEBUG="$(getprop ro.debuggable)"

log "verify: verifiedbootstate=$VB_STATE tags=$TAGS debuggable=$DEBUG"

if [ "$VB_STATE" = "green" ] && [ "$TAGS" = "release-keys" ] && [ "$DEBUG" = "0" ]; then
    log "OK — properties spoofed correctly"
else
    log "WARN — property spoof may not have applied fully"
fi

log "done — start Free Fire now"

exit 0
