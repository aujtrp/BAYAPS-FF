# BAYAPS-FF
Baypas
# FF AC Bypass — Devtrp x'

## Layer

| Layer | File | Fungsi |
|---|---|---|
| Kernel | `kernel/zygisk_detach.sh` | Detach FFAC, spoof build prop |
| Kernel | `kernel/hide_maps.sh` | Filter /proc/maps dari scan AC |
| Userspace | `userspace/bypass.js` | Frida hook dlopen, ptrace, fopen |
| Userspace | `userspace/libff_bypass.cpp` | Inline patch libanogs JNI exports |
| IL2CPP | `il2cpp/dump_offsets.py` | Dump metadata offset class target |
| IL2CPP | `il2cpp/patch_metadata.js` | Hook il2cpp_runtime_invoke |

## Deploy (VM/rooted device only)

1. Root + Magisk + Zygisk aktif + DenyList kosong.
2. Push semua file: `adb push ff_bypass /data/local/tmp/`.
3. Kernel layer: `adb shell su -c sh /data/local/tmp/ff_bypass/kernel/zygisk_detach.sh`.
4. Userspace: `frida -U -f com.dts.freefireth -l bypass.js --no-pause`.
5. Native: `LD_PRELOAD=/data/local/tmp/libff_bypass.so` di wrapper FF.
6. IL2CPP: dump dulu, update offset, baru run patch.

## Sequence Detection yang Harus Dihindari

- Frida default port 27042 — ganti: `frida-server -l 0.0.0.0:6767`
- Nama file `frida-server` — rename `fs6767`
- `/proc/self/task/*/status` TracerPid — zygisk handle ini
- `dl_iterate_phdr` scan — zygisk detach handle
- IL2CPP metadata hash check — patch layer `il2cpp/patch_metadata.js`
- Timing check native clock — inject delay di `clock_gettime` via Frida

## Verification

- Cek log Frida: semua integrity func log `→ 1` / `→ 0`.
- Cek FF gak crash startup (kalau crash, AC ada cek tambahan — dump `libanogs.so` symbol).
- Cek maps: `cat /data/local/tmp/maps_filtered_<pid>` — pattern harus hilang.
- Cek /proc/<pid>/status `TracerPid: 0` setelah zygisk attach.