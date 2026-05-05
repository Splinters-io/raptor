# Frida Setup — Android

## Rooted Device

```bash
# Download frida-server for your device architecture
ARCH=arm64  # or arm, x86, x86_64
wget https://github.com/frida/frida/releases/latest/download/frida-server-16.x.x-android-$ARCH.xz
unxz frida-server-*
adb push frida-server-* /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Disable SELinux (required on most devices)
adb shell su -c setenforce 0

# Start frida-server
adb shell su -c /data/local/tmp/frida-server &

# Verify from host
frida-ps -U
```

## Non-Rooted (frida-gadget injection)

```bash
# Decompile APK
apktool d target.apk -o target_dir

# Inject frida-gadget.so into lib/<arch>/
cp frida-gadget-16.x.x-android-arm64.so target_dir/lib/arm64-v8a/libfrida-gadget.so

# Add System.loadLibrary("frida-gadget") to smali entry point
# Or inject into the native lib loading path

# Rebuild and sign
apktool b target_dir -o patched.apk
jarsigner -keystore debug.keystore patched.apk alias
adb install patched.apk
```

## RAPTOR Usage

```bash
# USB device (rooted)
python3 packages/frida/scanner.py --device usb --attach com.target.app --template ssl-unpin

# Spawn app
python3 packages/frida/scanner.py --device usb --spawn com.target.app --template api-trace
```
