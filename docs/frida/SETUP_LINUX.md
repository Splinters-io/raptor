# Frida Setup — Linux

## Install

```bash
pip install frida-tools
```

## Permissions

Frida uses `ptrace`. On hardened systems:

```bash
# Check ptrace scope
cat /proc/sys/kernel/yama/ptrace_scope
# 0 = no restrictions, 1 = only parent can ptrace, 2 = admin only, 3 = disabled

# Temporarily allow (requires root)
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Or run Frida as root for system processes
sudo frida -p 1234
```

## System Services

```bash
# Attach to a system service (requires root)
sudo python3 packages/frida/scanner.py --attach sshd --template api-trace

# Spawn a binary
python3 packages/frida/scanner.py --spawn ./target_binary --template memory-scan
```

## Containers

For Docker targets, run frida-server inside the container or use `--pid` from the host with `--cap-add=SYS_PTRACE`:

```bash
docker run --cap-add=SYS_PTRACE -p 27042:27042 target_image
python3 packages/frida/scanner.py --device 127.0.0.1:27042 --attach target_process
```
