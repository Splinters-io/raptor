#!/usr/bin/env python3
"""
RAPTOR Autonomous Frida Analysis

Combines static analysis + LLM reasoning + dynamic instrumentation
for intelligent, goal-directed security testing.

Workflow:
1. Static analysis identifies interesting functions/APIs
2. LLM decides which Frida hooks would be most valuable
3. Generate custom Frida scripts targeting specific behaviors
4. Run instrumentation and collect runtime data
5. LLM analyzes findings and suggests next steps
6. Iterate until security goals achieved
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

import os
sys.path.insert(0, os.environ["RAPTOR_DIR"])

try:
    from packages.llm_analysis.llm.client import LLMClient
except ImportError:
    print("✗ LLM client not available")
    LLMClient = None

from packages.frida.scanner import FridaScanner

logger = logging.getLogger("frida.autonomous")


class AutonomousFridaAnalyzer:
    """
    Autonomous Frida analyzer that uses LLM to guide instrumentation.
    """

    def __init__(self, target: str, goal: str = "Find security vulnerabilities",
                 target_args: List[str] = None, device: Optional[str] = None,
                 mode: str = "spawn"):
        """
        Initialize autonomous analyzer.

        Args:
            target: Binary path, process name, or PID
            goal: Security testing goal (guides LLM decisions)
            target_args: Arguments to pass to spawned binary
            device: Frida device identifier (e.g., 'local', 'usb', or host:port)
            mode: 'spawn' to start a new process, 'attach' to hook a running one
        """
        self.target = target
        self.goal = goal
        self.target_args = target_args or []
        self.device = device
        self.mode = mode
        self.llm_client = LLMClient() if LLMClient else None
        self.frida_scanner = FridaScanner(device=device) if device else FridaScanner()
        self.iteration = 0
        self.max_iterations = 5
        self.findings_history: List[Dict] = []

    def analyze_static(self) -> Dict[str, Any]:
        """
        Perform static analysis to identify interesting functions/APIs.
        Uses r2 (radare2) for function, import, and string enumeration.
        Falls back to BinaryContextAnalyzer if r2 is unavailable.

        Returns:
            Dict of static analysis results
        """
        logger.info(f"Static analysis of {self.target}")

        static_info = {
            "binary_path": self.target,
            "interesting_functions": [],
            "imported_libraries": [],
            "security_features": [],
            "strings": []
        }

        # Try r2 first
        r2_path = shutil.which('r2') or shutil.which('radare2')
        if r2_path:
            static_info = self._analyze_with_r2(r2_path, static_info)
        else:
            logger.warning("r2 not available, falling back to BinaryContextAnalyzer")
            static_info = self._analyze_with_context_analyzer(static_info)

        return static_info

    def _analyze_with_r2(self, r2_path: str, static_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use radare2 to extract functions, imports, and strings.

        Args:
            r2_path: Path to r2 binary
            static_info: Base static info dict to populate

        Returns:
            Populated static_info dict
        """
        try:
            result = subprocess.run(
                [r2_path, '-q', '-c', 'aaa;aflj;iij;izj', self.target],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                logger.warning(f"r2 returned non-zero: {result.stderr[:200]}")
                return self._analyze_with_context_analyzer(static_info)

            # r2 outputs multiple JSON arrays separated by newlines
            # Parse each JSON block from the output
            output = result.stdout.strip()
            json_blocks = []
            depth = 0
            current_block = []

            for char in output:
                if char == '[' and depth == 0:
                    depth = 1
                    current_block = [char]
                elif char == '[':
                    depth += 1
                    current_block.append(char)
                elif char == ']' and depth == 1:
                    depth = 0
                    current_block.append(char)
                    json_blocks.append(''.join(current_block))
                elif char == ']':
                    depth -= 1
                    current_block.append(char)
                elif depth > 0:
                    current_block.append(char)

            # Parse blocks: aflj (functions), iij (imports), izj (strings)
            functions_data = []
            imports_data = []
            strings_data = []

            for i, block in enumerate(json_blocks):
                try:
                    parsed = json.loads(block)
                    if i == 0:
                        functions_data = parsed
                    elif i == 1:
                        imports_data = parsed
                    elif i == 2:
                        strings_data = parsed
                except json.JSONDecodeError:
                    continue

            # Extract interesting functions (security-relevant)
            security_keywords = {
                'malloc', 'free', 'realloc', 'calloc',
                'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf',
                'gets', 'fgets', 'scanf', 'fscanf',
                'memcpy', 'memmove', 'memset',
                'system', 'exec', 'popen', 'fork',
                'open', 'read', 'write', 'close', 'ioctl',
                'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv',
                'crypt', 'rand', 'srand',
                'setuid', 'setgid', 'chroot', 'chown', 'chmod',
                'dlopen', 'dlsym',
                'SSL_', 'EVP_', 'AES_', 'RSA_',
            }

            for func in functions_data:
                name = func.get('name', '')
                # Strip common prefixes
                clean_name = name.lstrip('sym.').lstrip('imp.').lstrip('_')
                if any(kw in clean_name for kw in security_keywords):
                    static_info['interesting_functions'].append({
                        'name': name,
                        'offset': func.get('offset', 0),
                        'size': func.get('size', 0)
                    })

            # Extract imports
            for imp in imports_data:
                lib = imp.get('libname', imp.get('lib', ''))
                if lib and lib not in static_info['imported_libraries']:
                    static_info['imported_libraries'].append(lib)

            # Extract security-relevant strings (limited to avoid noise)
            security_string_patterns = [
                'password', 'passwd', 'secret', 'token', 'key', 'auth',
                'admin', 'root', 'login', 'crypt', 'hash',
                '/etc/', '/tmp/', '/dev/', 'http://', 'https://',
                'cmd', 'shell', 'exec', 'eval',
            ]
            for s in strings_data[:5000]:  # Limit to prevent huge output
                string_val = s.get('string', '')
                if any(pat in string_val.lower() for pat in security_string_patterns):
                    static_info['strings'].append({
                        'value': string_val[:256],  # Truncate long strings
                        'offset': s.get('vaddr', s.get('offset', 0)),
                        'section': s.get('section', '')
                    })

            logger.info(
                f"r2 analysis: {len(static_info['interesting_functions'])} interesting functions, "
                f"{len(static_info['imported_libraries'])} libraries, "
                f"{len(static_info['strings'])} security-relevant strings"
            )

        except subprocess.TimeoutExpired:
            logger.warning("r2 analysis timed out, falling back to BinaryContextAnalyzer")
            return self._analyze_with_context_analyzer(static_info)
        except Exception as e:
            logger.warning(f"r2 analysis failed: {e}, falling back to BinaryContextAnalyzer")
            return self._analyze_with_context_analyzer(static_info)

        return static_info

    def _analyze_with_context_analyzer(self, static_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fall back to BinaryContextAnalyzer when r2 is unavailable.

        Args:
            static_info: Base static info dict to populate

        Returns:
            Populated static_info dict
        """
        try:
            from packages.frida.binary_context_analyzer import BinaryContextAnalyzer

            analyzer = BinaryContextAnalyzer(self.target)
            deps = analyzer.analyze_static_dependencies()
            static_info['imported_libraries'] = deps

            # Detect format info
            binary_format = analyzer.detect_binary_format()
            static_info['security_features'].append(f'format:{binary_format}')

            packing = analyzer.detect_packed_binary()
            if packing['is_packed']:
                static_info['security_features'].append(
                    f'packed:{packing["packer_detected"] or "unknown"}'
                )

            logger.info(
                f"BinaryContextAnalyzer fallback: {len(deps)} dependencies, "
                f"format={binary_format}"
            )
        except Exception as e:
            logger.warning(f"BinaryContextAnalyzer fallback also failed: {e}")

        return static_info

    def llm_decide_hooks(self, static_info: Dict, previous_findings: List[Dict]) -> Dict[str, Any]:
        """
        Use LLM to decide which Frida hooks to install based on:
        - Static analysis results
        - Security goal
        - Previous findings

        Returns:
            Dict with hook strategy and generated script
        """
        if not self.llm_client:
            logger.warning("LLM not available, using default hooks")
            return {
                "strategy": "default",
                "hooks": [{"function": "write", "extract": "buffer contents"}],
                "reasoning": "LLM unavailable, using basic API tracing"
            }

        prompt = f"""
You are a security researcher using Frida for dynamic instrumentation.

GOAL: {self.goal}
TARGET: {self.target}
ITERATION: {self.iteration + 1}/{self.max_iterations}

STATIC ANALYSIS:
{json.dumps(static_info, indent=2)}

PREVIOUS FINDINGS:
{json.dumps(previous_findings[-10:], indent=2) if previous_findings else "None yet"}

Based on the goal, decide which functions to hook and WHAT DATA TO EXTRACT.
Don't just log "function called" - extract the actual security-relevant data.

Examples of useful extractions:
- write(): capture buffer contents, look for credentials/tokens
- connect(): extract IP address and port from sockaddr struct
- open(): capture file paths being accessed
- SSL_write(): capture pre-encryption plaintext
- recv()/read(): capture incoming data

Respond with JSON:
{{
    "strategy": "brief description",
    "hooks": [
        {{
            "function": "write",
            "module": "libsystem_kernel.dylib",
            "extract": "buffer contents as string, flag if contains auth/password/token",
            "security_focus": "credential leakage, sensitive data exposure"
        }},
        {{
            "function": "connect",
            "module": "libsystem_kernel.dylib",
            "extract": "parse sockaddr to get IP:port",
            "security_focus": "network connections, C2 communication"
        }}
    ],
    "reasoning": "why these hooks achieve the goal"
}}
        """

        try:
            response = self.llm_client.generate(prompt)
            content = response.content
            start = content.find('{')
            end = content.rfind('}') + 1
            if start != -1 and end > start:
                json_str = content[start:end]
                decision = json.loads(json_str)
            else:
                raise ValueError("No JSON object found in response")
            logger.info(f"LLM Strategy: {decision.get('strategy')}")
            return decision

        except Exception as e:
            logger.error(f"LLM decision failed: {e}")
            return {
                "strategy": "fallback",
                "hooks": [{"function": "write", "extract": "buffer contents"}],
                "reasoning": f"LLM error: {e}"
            }

    def generate_frida_script(self, hook_decision: Dict) -> str:
        """
        Generate custom Frida script with LLM-generated hook implementations.

        Args:
            hook_decision: Hook strategy from LLM including extraction requirements

        Returns:
            JavaScript source code for Frida
        """
        hooks = hook_decision.get('hooks', [])

        # Handle old format (list of strings) vs new format (list of dicts)
        if hooks and isinstance(hooks[0], str):
            hooks = [{"function": h, "extract": "basic call logging"} for h in hooks]

        # Ask LLM to generate actual hook implementations
        hook_code = self._llm_generate_hook_code(hooks)

        # Get cross-platform boilerplate
        try:
            from packages.frida.platform import get_full_platform_boilerplate_js
            platform_js = get_full_platform_boilerplate_js()
        except ImportError:
            platform_js = self._fallback_platform_js()

        # Build complete script with boilerplate + LLM-generated hooks
        script_parts = [
            "// Auto-generated by RAPTOR Autonomous Frida",
            f"// Strategy: {hook_decision.get('strategy')}",
            f"// Goal: {self.goal}",
            "",
            "// === UTILITIES ===",
            "function log(msg, level) {",
            "    send({ level: level || 'info', message: msg });",
            "}",
            "",
            "function sendFinding(title, severity, details, data) {",
            "    send({",
            "        type: 'finding',",
            "        level: severity,",
            "        title: title,",
            "        details: details,",
            "        data: data || null,",
            "        timestamp: Date.now()",
            "    });",
            "}",
            "",
            "// === CROSS-PLATFORM SUPPORT ===",
            platform_js,
            "",
            "log('RAPTOR Autonomous Frida loaded', 'info');",
            "",
            "// === LLM-GENERATED HOOKS ===",
            hook_code
        ]

        return "\n".join(script_parts)

    def _llm_generate_hook_code(self, hooks: List[Dict]) -> str:
        """
        Use LLM to generate actual JavaScript hook implementations.
        Uses methodology-driven prompts for exploitation-focused analysis.

        Args:
            hooks: List of hook specifications with extraction requirements

        Returns:
            JavaScript code implementing the hooks
        """
        if not self.llm_client:
            return self._fallback_hook_code(hooks)

        # Import methodology engine
        try:
            from packages.frida.methodology import generate_methodology_prompt
            prompt = generate_methodology_prompt(self.goal, "binary")
        except ImportError:
            # Fallback to basic prompt if methodology module not available
            prompt = self._basic_hook_prompt(hooks)

        # Append hook specifications
        hooks_desc = json.dumps(hooks, indent=2)
        prompt += f"""

ADDITIONAL HOOK SPECIFICATIONS FROM STRATEGY:
{hooks_desc}

REFERENCE - Function argument extraction:
- write(fd, buf, len): args[0]=fd, args[1]=buf, args[2]=len
- connect(sockfd, addr, len): args[1]=sockaddr struct
- open(path, flags): args[0]=path string
- malloc(size): args[0]=size, retval=pointer
- free(ptr): args[0]=pointer to free

Generate ONLY JavaScript code. No markdown, no explanation.
"""

        try:
            response = self.llm_client.generate(prompt)
            content = response.content

            # Extract code from response (remove markdown if present)
            if '```javascript' in content:
                start = content.find('```javascript') + 13
                end = content.find('```', start)
                code = content[start:end].strip()
            elif '```js' in content:
                start = content.find('```js') + 5
                end = content.find('```', start)
                code = content[start:end].strip()
            elif '```' in content:
                start = content.find('```') + 3
                end = content.find('```', start)
                code = content[start:end].strip()
            else:
                code = content.strip()

            logger.info(f"LLM generated {len(code)} bytes of hook code")
            return code

        except Exception as e:
            logger.error(f"LLM hook generation failed: {e}")
            return self._fallback_hook_code(hooks)

    def _fallback_hook_code(self, hooks: List[Dict]) -> str:
        """Generate basic hook code when LLM is unavailable."""
        parts = []
        for idx, hook in enumerate(hooks):
            func = hook.get('function', 'unknown') if isinstance(hook, dict) else hook
            module = hook.get('module', '') if isinstance(hook, dict) else ''
            parts.append(f"""
// Fallback hook: {func}
try {{
    var ptr_{idx} = findSymbol('{func}', '{module}');
    if (ptr_{idx}) {{
        Interceptor.attach(ptr_{idx}, {{
            onEnter: function(args) {{
                log('{func}() called', 'info');
            }}
        }});
        log('{func} hooked', 'info');
    }}
}} catch(e) {{ log('Error: ' + e.message, 'error'); }}
""")
        return "\n".join(parts)

    def _fallback_platform_js(self) -> str:
        """Fallback cross-platform JS when platform module unavailable."""
        return """
// Platform detection
var PLATFORM = (function() {
    var p = Process.platform;
    if (p === 'darwin') return 'macos';
    if (p === 'linux') return 'linux';
    if (p === 'windows') return 'windows';
    return 'unknown';
})();

// Cross-platform library list
var PLATFORM_LIBS = {
    'linux': ['libc.so.6', 'libpthread.so.0', 'libdl.so.2'],
    'macos': ['libsystem_kernel.dylib', 'libsystem_c.dylib', 'libSystem.B.dylib'],
    'ios': ['libsystem_kernel.dylib', 'libsystem_c.dylib', 'libSystem.B.dylib'],
    'windows': ['ntdll.dll', 'kernel32.dll', 'ws2_32.dll', 'msvcrt.dll'],
    'android': ['libc.so', 'libdl.so']
};

function getExport(modName, funcName) {
    try { return Process.getModuleByName(modName).getExportByName(funcName); }
    catch(e) { return null; }
}

function findSymbol(name, preferredModule) {
    if (preferredModule) {
        var ptr = getExport(preferredModule, name);
        if (ptr) return ptr;
    }
    var libs = PLATFORM_LIBS[PLATFORM] || PLATFORM_LIBS['linux'];
    for (var i = 0; i < libs.length; i++) {
        var ptr = getExport(libs[i], name);
        if (ptr) return ptr;
    }
    try {
        return Module.findExportByName(null, name);
    } catch(e) { return null; }
}

function findFunction(name) { return findSymbol(name, null); }
"""

    def _basic_hook_prompt(self, hooks: List[Dict]) -> str:
        """Basic hook generation prompt when methodology module unavailable."""
        return f"""
Generate Frida JavaScript hooks for exploitation-focused security analysis.

GOAL: {self.goal}

EXPLOITATION MINDSET:
- What can be stolen? (credentials, keys, sensitive data)
- What can be corrupted? (memory, files, state)
- What can be controlled? (execution flow, data)
- What can be bypassed? (auth, validation, checks)

REQUIREMENTS:
1. Hook functions that handle security-relevant operations
2. Extract ACTUAL DATA that could be weaponized
3. Rate findings by exploitability: critical/high/medium/low/info
4. No app-specific assumptions - work on ANY target

Use these helpers (already defined):
- findSymbol(name, preferredModule) - resolve function
- sendFinding(title, severity, details, data) - report finding
- log(msg, level) - debug logging
"""

    def llm_analyze_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Use LLM to analyze runtime findings and suggest next steps.

        Args:
            findings: List of findings from Frida

        Returns:
            Analysis and recommendations
        """
        if not self.llm_client:
            return {
                "analysis": "LLM unavailable",
                "continue": False
            }

        prompt = f"""
You are analyzing runtime behavior from Frida instrumentation.

GOAL: {self.goal}
ITERATION: {self.iteration + 1}/{self.max_iterations}

RUNTIME FINDINGS:
{json.dumps(findings, indent=2)}

Analyze these findings:
1. Do they reveal security issues?
2. Do they help achieve our goal?
3. Should we continue instrumenting (what to hook next)?
4. Or have we found what we needed?

Respond with JSON:
{{
    "security_issues": ["issue1", "issue2", ...],
    "goal_progress": "how close are we to the goal (0-100%)",
    "continue": true/false,
    "next_focus": "what to investigate next",
    "recommendations": "suggested next steps"
}}
        """

        try:
            response = self.llm_client.generate(prompt)
            # Extract JSON from response (may contain text before/after JSON)
            content = response.content
            start = content.find('{')
            end = content.rfind('}') + 1
            if start != -1 and end > start:
                json_str = content[start:end]
                analysis = json.loads(json_str)
            else:
                raise ValueError("No JSON object found in response")
            logger.info(f"LLM Analysis: {analysis.get('goal_progress')}% complete")
            return analysis

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {
                "analysis": f"Error: {e}",
                "continue": self.iteration < self.max_iterations
            }

    def run_autonomous(self, duration_per_iteration: int = 30) -> List[Dict]:
        """
        Run autonomous analysis loop.

        Args:
            duration_per_iteration: How long to run each instrumentation (seconds)

        Returns:
            List of all findings
        """
        logger.info(f"Starting autonomous Frida analysis")
        logger.info(f"Goal: {self.goal}")
        logger.info(f"Target: {self.target}")

        all_findings = []

        while self.iteration < self.max_iterations:
            logger.info(f"\n{'='*70}")
            logger.info(f"ITERATION {self.iteration + 1}/{self.max_iterations}")
            logger.info(f"{'='*70}")

            # Step 1: Static analysis (only on first iteration)
            if self.iteration == 0:
                static_info = self.analyze_static()
            else:
                static_info = {}

            # Step 2: LLM decides which hooks to use
            hook_decision = self.llm_decide_hooks(static_info, all_findings)

            # Step 3: Generate Frida script
            frida_script = self.generate_frida_script(hook_decision)

            # Step 4: Run instrumentation
            try:
                if self.mode == 'attach':
                    self.frida_scanner.attach_to_process(self.target)
                else:
                    self.frida_scanner.spawn_process(self.target, self.target_args)
                self.frida_scanner.load_script(frida_script, f"auto_iteration_{self.iteration}")
                if self.mode != 'attach':
                    self.frida_scanner.resume_process()

                logger.info(f"Running instrumentation for {duration_per_iteration}s...")
                import time
                time.sleep(duration_per_iteration)

                # Collect findings
                iteration_findings = self.frida_scanner.findings
                all_findings.extend(iteration_findings)

                logger.info(f"Iteration {self.iteration + 1} found {len(iteration_findings)} findings")

            except Exception as e:
                logger.error(f"Instrumentation failed: {e}")
                break
            finally:
                self.frida_scanner.detach()

            # Step 5: LLM analyzes findings and decides if we should continue
            analysis = self.llm_analyze_findings(all_findings)

            if not analysis.get('continue', False):
                logger.info("LLM determined goal achieved or no further value")
                break

            self.iteration += 1

        # Final report
        logger.info(f"\nAutonomous analysis complete: {len(all_findings)} total findings")
        self.frida_scanner.findings = all_findings
        self.frida_scanner.generate_report()

        return all_findings


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="RAPTOR Autonomous Frida Analysis"
    )
    parser.add_argument('--target', required=True,
                       help='Binary to analyze')
    parser.add_argument('--goal', default='Find security vulnerabilities',
                       help='Security testing goal')
    parser.add_argument('--max-iterations', type=int, default=5,
                       help='Maximum analysis iterations')
    parser.add_argument('--duration', type=int, default=30,
                       help='Duration per iteration (seconds)')
    parser.add_argument('--device', default=None,
                       help='Frida device identifier (local, usb, or host:port)')
    parser.add_argument('--mode', choices=['spawn', 'attach'], default='spawn',
                       help='spawn a new process or attach to running (default: spawn)')
    parser.add_argument('target_args', nargs='*', default=[],
                       help='Arguments to pass to target (after --)')

    args = parser.parse_args()

    analyzer = AutonomousFridaAnalyzer(
        args.target, args.goal, args.target_args, device=args.device, mode=args.mode
    )
    analyzer.max_iterations = args.max_iterations
    findings = analyzer.run_autonomous(args.duration)

    print(f"\n✓ Found {len(findings)} security findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
