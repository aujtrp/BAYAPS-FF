#!/system/bin/sh
#
# kernel/hide_maps.sh
# BAYAPS-FF — Filter /proc/<pid>/maps to hide Frida/Magisk
# ALPHA XK / ALPHA يعمل
#
# Usage:
#   hide_maps.sh <pid>          — one-shot filter
#   hide_maps.sh --watch <pid>  — re-apply every 2s (background safe)
#   hide_maps.sh --restore <pid>— unmount and restore original maps
#
# Run as root.

set -u

LOG_TAG="[ALPHA XK]"
BACKUP_DIR="/data/local/tmp/bayaps_ff_maps"
WATCH_INTERVAL=2

HIDE_PATTERNS="frida|magisk|zygisk|riru|xposed|lsposed|substrate|linjector|re\\.frida\\.server|gadget|ff_hook|bayaps"

log() {
    echo "$LOG_TAG $1"
    echo "$LOG_TAG $1" >> /data/local/tmp/bayaps_ff.log
}

usage() {
    echo "Usage: $0 <pid> | --watch <pid> | --restore <pid>"
    exit 1
}

# ── Sanity ─────────────────────────────────────────────────────────
if [ "$(id -u)" != "0" ]; then
    log "ERROR: must run as root"
    exit 1
fi

if [ $# -lt 1 ]; then
    usage
fi

MODE="once"

case "$1" in
    --watch)
        MODE="watch"
        PID="$2"
        ;;
    --restore)
        MODE="restore"
        PID="$2"
        ;;
    *)
        PID="$1"
        ;;
esac

if [ -z "${PID:-}" ] || ! kill -0 "$PID" 2>/dev/null; then
    log "ERROR: invalid or dead pid: ${PID:-<none>}"
    exit 1
fi

TARGET_MAPS="/proc/$PID/maps"
FILTERED="$BACKUP_DIR/maps_filtered_$PID"
BACKUP="$BACKUP_DIR/maps_backup_$PID"

mkdir -p "$BACKUP_DIR"

# ── Restore mode ───────────────────────────────────────────────────
if [ "$MODE" = "restore" ]; then
    if grep -q "$TARGET_MAPS" /proc/mounts 2>/dev/null; then
        umount "$TARGET_MAPS" 2>/dev/null && \
            log "restored $TARGET_MAPS from bind mount"
    else
        log "nothing to restore for pid=$PID"
    fi
    exit 0
fi

# ── Build filtered copy ────────────────────────────────────────────
build_filtered() {
    if [ ! -r "$TARGET_MAPS" ]; then
        log "cannot read $TARGET_MAPS"
        return 1
    fi

    cp "$TARGET_MAPS" "$BACKUP" 2>/dev/null
    grep -Eiv "$HIDE_PATTERNS" "$BACKUP" > "$FILTERED" 2>/dev/null

    if [ ! -s "$FILTERED" ]; then
        log "filtered file empty — refusing to mount"
        return 1
    fi

    chmod 644 "$FILTERED"
    return 0
}

# ── Bind mount ─────────────────────────────────────────────────────
apply_mount() {
    if grep -q "$TARGET_MAPS" /proc/mounts 2>/dev/null; then
        return 0
    fi

    if ! build_filtered; then
        return 1
    fi

    if mount --bind "$FILTERED" "$TARGET_MAPS" 2>/dev/null; then
        log "mounted filtered maps for pid=$PID"
        return 0
    else
        log "bind mount failed (SELinux? try setenforce 0)"
        return 1
    fi
}

# ── Once ───────────────────────────────────────────────────────────
if [ "$MODE" = "once" ]; then
    apply_mount
    log "done (once) pid=$PID"
    exit 0
fi

# ── Watch ──────────────────────────────────────────────────────────
if [ "$MODE" = "watch" ]; then
    log "watch start pid=$PID interval=${WATCH_INTERVAL}s"

    (
        while kill -0 "$PID" 2>/dev/null; do
            if ! grep -q "$TARGET_MAPS" /proc/mounts 2>/dev/null; then
                apply_mount
            fi

            if [ -r "$TARGET_MAPS" ]; then
                build_filtered
            fi

            sleep "$WATCH_INTERVAL"
        done
        log "watch end pid=$PID (process died)"
    ) &

    log "watch running in background (pid $!)"
    exit 0
fi

exit 0