# Frida Setup — Windows

## Install

```powershell
pip install frida-tools
```

## Permissions

Run as Administrator to instrument system services and protected processes.

```powershell
# Elevated PowerShell
frida-ps  # List processes

# Attach to a service
python packages\frida\scanner.py --attach svchost.exe --template api-trace
```

## Anti-Virus

Real-time AV may interfere with Frida injection. Temporarily disable or add exclusions:

- Windows Defender: Settings → Virus & threat protection → Exclusions → Add python.exe and frida-server.exe
- Most AV flags Frida's code injection as suspicious — this is expected behaviour

## Protected Processes (PPL)

Windows Protected Process Light (PPL) blocks injection into certain services (csrss, lsass by default). Options:

- Use frida-server with kernel driver (requires test signing or vulnerable driver)
- Target non-PPL processes instead
- Use `--spawn` mode which doesn't require injection into running process

## RAPTOR Usage

```powershell
# Spawn and instrument
python packages\frida\scanner.py --spawn C:\path\to\target.exe --template api-trace

# Attach to running process
python packages\frida\scanner.py --attach target.exe --template crypto-trace

# Remote device (e.g., Android connected via USB forwarding)
python packages\frida\scanner.py --device 127.0.0.1:27042 --attach com.target.app
```
