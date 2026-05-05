#!/usr/bin/env python3
"""
RAPTOR Frida Dynamic Instrumentation Scanner

Features:
- Attach to running processes or spawn new ones
- Load custom Frida scripts or use built-in templates
- API hooking, SSL unpinning, memory analysis
- LLM-powered analysis of runtime behavior
- Integration with RAPTOR reporting

Usage:
    python3 scanner.py --target <pid|process_name|binary_path> [options]
    python3 scanner.py --spawn /path/to/binary [options]
    python3 scanner.py --attach 1234 --script custom.js
    python3 scanner.py --target com.example.app --template ssl-unpin
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

try:
    import frida
except ImportError:
    print("✗ Frida not installed. Install with: pip install frida-tools")
    sys.exit(1)

# Setup logging
script_root = Path(__file__).parent.parent.parent
log_dir = script_root / "out" / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_dir / f"raptor_frida_{int(time.time())}.log")
    ]
)
logger = logging.getLogger("frida")


class FridaScanner:
    """RAPTOR Frida scanner for dynamic instrumentation."""

    def __init__(self, output_dir: Optional[Path] = None, device: str = "local"):
        """
        Initialize Frida scanner.

        Args:
            output_dir: Directory for output files
            device: Device specifier — "local", "usb", or "host:port" for remote
        """
        self.script_root = Path(__file__).parent.parent.parent
        self.templates_dir = Path(__file__).parent / "templates"
        self.output_dir = output_dir or (self.script_root / "out" / f"frida_scan_{int(time.time())}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.device = self._resolve_device(device)
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.findings: List[Dict[str, Any]] = []
        self._max_findings = 10000
        self._detached = False
        self._lock = __import__("threading").Lock()

        logger.info("Frida scanner initialized")
        logger.info(f"Device: {self.device}")

    def _resolve_device(self, device_spec: str) -> frida.core.Device:
        """Resolve device from specifier string."""
        if device_spec == "local":
            return frida.get_local_device()
        if device_spec == "usb":
            try:
                return frida.get_usb_device(timeout=5)
            except frida.TimedOutError:
                logger.error("No USB device found (is frida-server running on device?)")
                raise
        if ":" in device_spec:
            mgr = frida.get_device_manager()
            return mgr.add_remote_device(device_spec)
        try:
            return frida.get_device(device_spec, timeout=5)
        except Exception:
            logger.error(f"Device not found: {device_spec}")
            raise
        logger.info(f"Output directory: {self.output_dir}")

    def attach_to_process(self, target: str) -> frida.core.Session:
        """
        Attach to a running process.

        Args:
            target: Process ID (int) or process name (str)

        Returns:
            Frida session
        """
        try:
            if target.isdigit():
                pid = int(target)
                logger.info(f"Attaching to PID {pid}...")
                self.session = self.device.attach(pid)
            else:
                logger.info(f"Attaching to process '{target}'...")
                self.session = self.device.attach(target)

            self.session.on("detached", self._on_detached)
            logger.info(f"Attached to process successfully")
            return self.session

        except frida.ProcessNotFoundError:
            logger.error(f"Process not found: {target}")
            raise
        except Exception as e:
            logger.error(f"Failed to attach: {e}")
            raise

    def spawn_process(self, binary_path: str, args: List[str] = None) -> frida.core.Session:
        """
        Spawn a new process and attach.

        Args:
            binary_path: Path to binary to spawn
            args: Command-line arguments for the binary

        Returns:
            Frida session
        """
        try:
            logger.info(f"Spawning process: {binary_path}")
            if args:
                logger.info(f"Arguments: {' '.join(args)}")

            pid = self.device.spawn([binary_path] + (args or []))
            self.session = self.device.attach(pid)
            self.session.on("detached", self._on_detached)
            logger.info(f"Spawned process (PID {pid})")

            return self.session

        except Exception as e:
            logger.error(f"Failed to spawn process: {e}")
            raise

    def _on_detached(self, reason: str, crash):
        """Handle session detach (target crash, kill, etc)."""
        self._detached = True
        if reason == "process-terminated":
            logger.warning(f"Target process terminated")
        elif reason == "process-crashed":
            logger.error(f"Target process CRASHED")
            if crash:
                with self._lock:
                    self.findings.append({
                        "type": "finding",
                        "title": "Process Crash",
                        "severity": "high",
                        "detail": f"Process crashed: {crash.summary if hasattr(crash, 'summary') else str(crash)}",
                    })
        else:
            logger.warning(f"Detached: {reason}")

    def load_script(self, script_source: str, script_name: str = "custom") -> frida.core.Script:
        """
        Load and run a Frida script.

        Args:
            script_source: JavaScript source code
            script_name: Name for the script (for logging)

        Returns:
            Loaded Frida script
        """
        if not self.session:
            raise RuntimeError("No active session. Attach to a process first.")

        try:
            logger.info(f"Loading script: {script_name}")
            self.script = self.session.create_script(script_source)
            self.script.on('message', self._on_message)
            self.script.load()
            logger.info(f"✓ Script loaded and running")

            return self.script

        except Exception as e:
            logger.error(f"✗ Failed to load script: {e}")
            raise

    def load_template(self, template_name: str) -> frida.core.Script:
        """
        Load a built-in Frida script template.

        Args:
            template_name: Name of the template (without .js extension)

        Returns:
            Loaded Frida script
        """
        template_path = self.templates_dir / f"{template_name}.js"

        if not template_path.exists():
            available = [f.stem for f in self.templates_dir.glob("*.js")]
            logger.error(f"✗ Template not found: {template_name}")
            logger.info(f"Available templates: {', '.join(available)}")
            raise FileNotFoundError(f"Template not found: {template_name}")

        script_source = template_path.read_text()
        return self.load_script(script_source, script_name=template_name)

    def _on_message(self, message: Dict, data: Optional[bytes]):
        """Handle messages from Frida script (called from Frida's background thread)."""
        msg_type = message.get('type')

        if msg_type == 'send':
            payload = message.get('payload', {})

            if isinstance(payload, dict):
                level = payload.get('level', 'info')
                text = payload.get('message', str(payload))

                if level == 'error':
                    logger.error(f"[Script] {text}")
                elif level == 'warning':
                    logger.warning(f"[Script] {text}")
                else:
                    logger.info(f"[Script] {text}")

                if payload.get('type') == 'finding':
                    with self._lock:
                        if len(self.findings) < self._max_findings:
                            self.findings.append(payload)
                        elif len(self.findings) == self._max_findings:
                            logger.warning(f"Max findings ({self._max_findings}) reached, further findings dropped")
                            self.findings.append({"type": "finding", "title": "TRUNCATED", "detail": "Max findings reached"})
                    logger.info(f"Finding recorded: {payload.get('title', 'Unnamed')}")
            else:
                logger.info(f"[Script] {payload}")

        elif msg_type == 'error':
            stack = message.get('stack', 'No stack trace')
            logger.error(f"[Script Error] {message.get('description', 'Unknown error')}")
            logger.error(f"Stack: {stack}")

    def resume_process(self):
        """Resume a spawned process."""
        if self.session:
            try:
                self.device.resume(self.session._impl.pid)
                logger.info("Process resumed")
            except Exception as e:
                logger.warning(f"Could not resume process: {e}")

    def detach(self):
        """Detach from the process."""
        if self.script:
            try:
                self.script.unload()
                logger.info("✓ Script unloaded")
            except:
                pass

        if self.session:
            try:
                self.session.detach()
                logger.info("✓ Detached from process")
            except:
                pass

    def generate_report(self) -> Path:
        """
        Generate a JSON report of findings.

        Returns:
            Path to the report file
        """
        report_path = self.output_dir / "frida_report.json"

        report = {
            "tool": "RAPTOR Frida Scanner",
            "version": "1.0.0",
            "timestamp": time.time(),
            "findings_count": len(self.findings),
            "findings": self.findings
        }

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"✓ Report saved: {report_path}")
        return report_path

    def generate_sarif(self) -> Path:
        """Generate SARIF 2.1.0 report for integration with other tools."""
        severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

        results = []
        for f in self.findings:
            results.append({
                "ruleId": f.get("category", "frida/dynamic-finding"),
                "level": severity_map.get(f.get("severity", "info"), "note"),
                "message": {"text": f.get("detail", f.get("title", "Dynamic finding"))},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("location", {}).get("file", "unknown")},
                        "region": {"startLine": f.get("location", {}).get("line", 1)}
                    }
                }] if f.get("location") else []
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "RAPTOR Frida", "version": "1.0.0"}},
                "results": results
            }]
        }

        sarif_path = self.output_dir / "frida-results.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif, f, indent=2)
        logger.info(f"SARIF report: {sarif_path}")
        return sarif_path

    def print_summary(self):
        """Print scan summary."""
        print("\n" + "="*70)
        print("FRIDA SCAN COMPLETE")
        print("="*70)
        print(f"Findings: {len(self.findings)}")
        print(f"Output: {self.output_dir}")
        print("="*70 + "\n")


def main():
    """Main entry point for Frida scanner."""
    parser = argparse.ArgumentParser(
        description="RAPTOR Frida Dynamic Instrumentation Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Attach to running process by PID
  python3 scanner.py --attach 1234 --template api-trace

  # Attach to process by name
  python3 scanner.py --attach Safari --template ssl-unpin

  # Spawn and instrument a binary
  python3 scanner.py --spawn /usr/local/bin/myapp --template memory-scan

  # Use custom script
  python3 scanner.py --attach 1234 --script my_hook.js

  # Mobile app instrumentation
  python3 scanner.py --attach com.example.app --template mobile-basics

Available Templates:
  api-trace       - Trace API calls
  ssl-unpin       - SSL certificate pinning bypass
  memory-scan     - Memory scanning and dumping
  crypto-trace    - Cryptographic operations tracing
  mobile-basics   - Basic mobile app instrumentation
  anti-debug      - Anti-debugging bypass
        """
    )

    # Target selection
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--attach', metavar='TARGET',
                             help='Attach to running process (PID or name)')
    target_group.add_argument('--spawn', metavar='BINARY',
                             help='Spawn new process from binary')

    # Script selection
    script_group = parser.add_mutually_exclusive_group()
    script_group.add_argument('--template', metavar='NAME',
                             help='Use built-in template script')
    script_group.add_argument('--script', metavar='PATH',
                             help='Load custom Frida script')

    # Options
    parser.add_argument('--device', default='local',
                       help='Device: "local", "usb", or "host:port" for remote')
    parser.add_argument('--args', nargs='+',
                       help='Arguments for spawned process')
    parser.add_argument('--duration', type=int, default=30,
                       help='Run duration in seconds (default: 30)')
    parser.add_argument('--out', metavar='DIR',
                       help='Output directory')
    parser.add_argument('--no-resume', action='store_true',
                       help='Don\'t resume spawned process')

    args = parser.parse_args()

    # Initialize scanner
    output_dir = Path(args.out) if args.out else None
    scanner = FridaScanner(output_dir=output_dir, device=args.device)

    # Run lifecycle
    lifecycle_available = False
    output_dir_str = str(scanner.output_dir)
    try:
        import subprocess as _sp
        lifecycle = scanner.script_root / "libexec" / "raptor-run-lifecycle"
        if lifecycle.exists():
            target_path = args.attach or args.spawn or "unknown"
            result = _sp.run(
                [str(lifecycle), "start", "frida", "--target", target_path, "--out", output_dir_str],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                lifecycle_available = True
                for line in result.stdout.splitlines():
                    if line.startswith("OUTPUT_DIR="):
                        output_dir_str = line.split("=", 1)[1]
    except Exception:
        pass

    try:
        # Attach or spawn
        if args.attach:
            scanner.attach_to_process(args.attach)
        else:
            scanner.spawn_process(args.spawn, args.args or [])

        # Load script
        if args.template:
            scanner.load_template(args.template)
        elif args.script:
            script_path = Path(args.script)
            if not script_path.exists():
                logger.error(f"Script not found: {script_path}")
                return 1
            script_source = script_path.read_text()
            scanner.load_script(script_source, script_name=script_path.name)
        else:
            logger.info("No script specified, using basic API tracing")
            scanner.load_template('api-trace')

        # Resume if spawned
        if args.spawn and not args.no_resume:
            scanner.resume_process()

        # Run for specified duration, checking for detachment
        logger.info(f"Running for {args.duration} seconds...")
        logger.info("Press Ctrl+C to stop early")
        elapsed = 0
        while elapsed < args.duration and not scanner._detached:
            time.sleep(1)
            elapsed += 1
        if scanner._detached:
            logger.warning("Session detached during instrumentation")

    except KeyboardInterrupt:
        logger.info("\nStopped by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        if lifecycle_available:
            _sp.run([str(lifecycle), "fail", output_dir_str, str(e)], capture_output=True)
        return 1
    finally:
        scanner.detach()
        scanner.generate_report()
        scanner.generate_sarif()
        scanner.print_summary()
        if lifecycle_available:
            _sp.run([str(lifecycle), "complete", output_dir_str], capture_output=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
