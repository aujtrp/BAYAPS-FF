# BAYAPS-FF — Free Fire Anti-Cheat Bypass

Toolkit for bypassing Free Fire anti-cheat on Android.
For security research and isolated test environments only.

---

## Layers

| Layer | File | Function |
|---|---|---|
| Kernel | `kernel/zygisk_detach.sh` | Detach FFAC service + spoof build props |
| Kernel | `kernel/hide_maps.sh` | Filter `/proc/<pid>/maps` to hide Frida/Magisk |
| Userspace | `userspace/bypass.js` | Frida script: block AC lib load + unhook inline hooks |
| Userspace | `userspace/libff_bypass.cpp` | Native lib: patch JNI exports in `libanogs.so` |
| IL2CPP | `il2cpp/dump_offsets.py` | Extract offsets from `global-metadata.dat` |
| IL2CPP | `il2cpp/patch_metadata.js` | Hook IL2CPP runtime + patch sensitive methods |

---

## Requirements

- Android arm64 device (Android 10+)
- Root via Magisk 26+ with Zygisk enabled
- Shamiko (for DenyList enforcement)
- Frida server (custom port, e.g. 6767)
- NDK r26b (for native build)
- Il2CppDumper (for offset extraction)
- Free Fire APK (`com.dts.freefireth`)

---

## Deploy (VM / rooted device only)

### 1. Device setup

```bash
adb push fs6767 /data/local/tmp/
adb shell su -c "chmod 755 /data/local/tmp/fs6767"
adb shell su -c "/data/local/tmp/fs6767 -l 0.0.0.0:6767 &"
adb forward tcp:6767 tcp:6767