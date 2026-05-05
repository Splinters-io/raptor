# Frida Setup — iOS

## Jailbroken Device

```bash
# Add Frida repo to Cydia/Sileo
# Repo: https://build.frida.re

# Install frida from package manager on device
# Package: re.frida.server

# Verify from host (USB)
frida-ps -U

# Or via network
frida-ps -H 192.168.1.X
```

## Non-Jailbroken (frida-gadget via resigned IPA)

```bash
# Extract IPA
unzip target.ipa -d target_dir

# Inject frida-gadget
cp FridaGadget.dylib target_dir/Payload/Target.app/Frameworks/
# Add load command to binary:
insert_dylib @executable_path/Frameworks/FridaGadget.dylib target_dir/Payload/Target.app/Target

# Re-sign with your dev cert
codesign -f -s "Apple Development: you@email.com" --entitlements ent.plist target_dir/Payload/Target.app/Frameworks/FridaGadget.dylib
codesign -f -s "Apple Development: you@email.com" --entitlements ent.plist target_dir/Payload/Target.app/Target

# Repackage and install
cd target_dir && zip -r ../patched.ipa Payload/
ios-deploy --bundle patched.ipa
```

## RAPTOR Usage

```bash
# Jailbroken, USB
python3 packages/frida/scanner.py --device usb --attach com.target.app --template ssl-unpin

# Network
python3 packages/frida/scanner.py --device 192.168.1.X:27042 --attach com.target.app --template crypto-trace
```
