#!/usr/bin/env python3
"""
RAPTOR Binary Context Analyzer

Combines Frida runtime analysis with static analysis of the entire
execution environment:
- Binary dependencies
- Symlinks and TOCTOU
- LD_PRELOAD opportunities
- Environment variables
- SUID/SGID binaries
- File descriptors and IPC

Feeds findings back to:
- Semgrep/CodeQL: Analyze dependency source code
- LLM: Reason about attack surface
- Fuzzing: Target vulnerable components
- Meta-orchestrator: Coordinate comprehensive analysis
"""

import json
import math
import struct
import sys
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

import os; sys.path.insert(0, os.environ["RAPTOR_DIR"])

from packages.frida.scanner import FridaScanner

logger = logging.getLogger("binary-context")


class BinaryContextAnalyzer:
    """
    Analyzes complete binary execution context and feeds findings
    to other RAPTOR tools for comprehensive security assessment.
    """

    def __init__(self, binary_path: str):
        """
        Initialize binary context analyzer.

        Args:
            binary_path: Path to binary to analyze
        """
        self.binary_path = Path(binary_path)
        self.frida_scanner = FridaScanner()
        self.context = {
            'libraries': [],
            'dependencies': {},
            'symlinks': [],
            'env_vars': {},
            'suid_sgid': False,
            'file_descriptors': [],
            'ipc_mechanisms': [],
            'toctou_risks': [],
            'ld_preload_opportunities': []
        }

    def detect_binary_format(self) -> str:
        """
        Detect the binary format by reading magic bytes.

        Returns:
            One of: 'elf', 'macho', 'pe', 'jar', 'dex', 'unknown'
        """
        try:
            with open(self.binary_path, 'rb') as f:
                magic = f.read(8)
        except (OSError, IOError) as e:
            logger.error(f"Cannot read binary: {e}")
            return 'unknown'

        # ELF: 0x7f 'E' 'L' 'F'
        if magic[:4] == b'\x7fELF':
            return 'elf'

        # Mach-O: various magic numbers (32/64 bit, big/little endian)
        macho_magics = (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                        b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe')
        if magic[:4] in macho_magics:
            return 'macho'

        # PE: starts with MZ
        if magic[:2] == b'MZ':
            return 'pe'

        # JAR (ZIP archive with PK magic)
        if magic[:2] == b'PK':
            return 'jar'

        # DEX: 'dex\n035\0' or similar version strings
        if magic[:4] == b'dex\n':
            return 'dex'

        return 'unknown'

    def detect_dotnet_assembly(self) -> bool:
        """
        Detect if a PE binary is a .NET assembly by checking for CLI header.

        Returns:
            True if the PE contains a CLI header (COM descriptor directory entry)
        """
        try:
            with open(self.binary_path, 'rb') as f:
                # Verify MZ signature
                mz = f.read(2)
                if mz != b'MZ':
                    return False

                # Get PE header offset from e_lfanew at offset 0x3C
                f.seek(0x3C)
                pe_offset_bytes = f.read(4)
                if len(pe_offset_bytes) < 4:
                    return False
                pe_offset = struct.unpack('<I', pe_offset_bytes)[0]

                # Verify PE signature
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return False

                # Read COFF header (20 bytes)
                coff_header = f.read(20)
                if len(coff_header) < 20:
                    return False
                size_of_optional = struct.unpack('<H', coff_header[16:18])[0]

                if size_of_optional == 0:
                    return False

                # Read optional header magic to determine PE32 vs PE32+
                opt_start = f.tell()
                opt_magic = f.read(2)
                if len(opt_magic) < 2:
                    return False
                magic_val = struct.unpack('<H', opt_magic)[0]

                # COM descriptor (CLR runtime header) is data directory index 14
                # PE32: optional header data dirs start at offset 96
                # PE32+: optional header data dirs start at offset 112
                if magic_val == 0x10b:  # PE32
                    data_dir_offset = opt_start + 96
                elif magic_val == 0x20b:  # PE32+
                    data_dir_offset = opt_start + 112
                else:
                    return False

                # Each data directory entry is 8 bytes (RVA + Size)
                # Index 14 = CLR Runtime Header
                clr_entry_offset = data_dir_offset + (14 * 8)
                f.seek(clr_entry_offset)
                clr_entry = f.read(8)
                if len(clr_entry) < 8:
                    return False

                clr_rva, clr_size = struct.unpack('<II', clr_entry)
                return clr_rva != 0 and clr_size != 0

        except (OSError, IOError, struct.error) as e:
            logger.debug(f"Error checking .NET assembly: {e}")
            return False

    def detect_packed_binary(self) -> Dict[str, Any]:
        """
        Detect if the binary is packed or obfuscated.

        Checks:
        - UPX magic bytes
        - Abnormal section names
        - High entropy sections

        Returns:
            Dict with packing indicators
        """
        result = {
            'is_packed': False,
            'indicators': [],
            'packer_detected': None,
            'high_entropy_sections': []
        }

        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
        except (OSError, IOError) as e:
            logger.error(f"Cannot read binary for packing detection: {e}")
            return result

        # Check for UPX magic bytes
        # UPX typically has "UPX!" in the binary and section names like UPX0, UPX1
        if b'UPX!' in data:
            result['is_packed'] = True
            result['indicators'].append('UPX magic bytes found')
            result['packer_detected'] = 'UPX'

        # Check section names for packing indicators
        abnormal_sections = []
        known_packers_sections = {
            b'UPX0': 'UPX', b'UPX1': 'UPX', b'UPX2': 'UPX',
            b'.aspack': 'ASPack', b'.adata': 'ASPack',
            b'.themida': 'Themida', b'.vmp0': 'VMProtect',
            b'.vmp1': 'VMProtect', b'.enigma': 'Enigma',
            b'.nsp0': 'NsPack', b'.nsp1': 'NsPack',
            b'.petite': 'Petite', b'.yP': 'Y0da Protector',
            b'.packed': 'Generic packer',
        }

        for section_name, packer in known_packers_sections.items():
            if section_name in data:
                abnormal_sections.append(section_name.decode('ascii', errors='replace'))
                if not result['packer_detected']:
                    result['packer_detected'] = packer

        if abnormal_sections:
            result['is_packed'] = True
            result['indicators'].append(
                f'Abnormal section names: {", ".join(abnormal_sections)}'
            )

        # Check for high entropy sections (indicates compression/encryption)
        # Sample chunks of the binary and calculate Shannon entropy
        chunk_size = 4096
        high_entropy_threshold = 7.2  # Out of max 8.0

        for offset in range(0, min(len(data), 1024 * 1024), chunk_size):
            chunk = data[offset:offset + chunk_size]
            if len(chunk) < chunk_size:
                break
            entropy = self._calculate_entropy(chunk)
            if entropy > high_entropy_threshold:
                result['high_entropy_sections'].append({
                    'offset': hex(offset),
                    'entropy': round(entropy, 3)
                })

        if len(result['high_entropy_sections']) > 3:
            result['is_packed'] = True
            result['indicators'].append(
                f'{len(result["high_entropy_sections"])} high-entropy regions detected '
                f'(threshold: {high_entropy_threshold})'
            )

        if result['is_packed']:
            logger.warning(
                f"Binary appears packed/obfuscated: {result['packer_detected'] or 'unknown packer'}"
            )

        return result

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy for a byte sequence."""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        length = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    def detect_jar_or_dex(self) -> Optional[Dict[str, Any]]:
        """
        Detect Java JAR or Android DEX format.

        Returns:
            Dict with format info, or None if not JAR/DEX
        """
        try:
            with open(self.binary_path, 'rb') as f:
                magic = f.read(8)
        except (OSError, IOError):
            return None

        # JAR: ZIP format (PK\x03\x04)
        if magic[:4] == b'PK\x03\x04':
            info = {'format': 'jar', 'description': 'Java JAR (ZIP archive)'}
            # Try to verify it's actually a JAR by checking for META-INF
            try:
                import zipfile
                if zipfile.is_zipfile(str(self.binary_path)):
                    with zipfile.ZipFile(str(self.binary_path), 'r') as zf:
                        names = zf.namelist()
                        if any('META-INF' in n for n in names):
                            info['confirmed_jar'] = True
                        if any(n.endswith('.class') for n in names):
                            info['contains_classes'] = True
                        if 'classes.dex' in names:
                            info['format'] = 'apk'
                            info['description'] = 'Android APK (contains classes.dex)'
            except Exception:
                pass
            logger.info(f"Detected {info['format'].upper()} format")
            return info

        # DEX: dex\n followed by version (e.g., 035\0)
        if magic[:4] == b'dex\n':
            version = magic[4:7].decode('ascii', errors='replace')
            info = {
                'format': 'dex',
                'description': f'Android DEX (Dalvik Executable, version {version})'
            }
            logger.info(f"Detected DEX format (version {version})")
            return info

        return None

    def analyze_static_dependencies(self) -> List[str]:
        """
        Analyze static dependencies using platform-appropriate tools.
        Supports ELF (ldd), Mach-O (otool), and Windows PE (objdump/dumpbin).

        Returns:
            List of dependency paths
        """
        logger.info("Analyzing static dependencies...")

        dependencies = []
        binary_format = self.detect_binary_format()

        try:
            if binary_format == 'pe' or sys.platform == 'win32':
                dependencies = self._analyze_pe_imports()
            elif binary_format == 'macho' or sys.platform == 'darwin':
                result = subprocess.run(
                    ['otool', '-L', str(self.binary_path)],
                    capture_output=True,
                    text=True
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('/'):
                        dep_path = line.split()[0]
                        dependencies.append(dep_path)
            else:
                # ELF / Linux default
                result = subprocess.run(
                    ['ldd', str(self.binary_path)],
                    capture_output=True,
                    text=True
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if '=>' in line:
                        parts = line.split('=>')
                        if len(parts) >= 2:
                            dep_path = parts[1].strip().split()[0]
                            dependencies.append(dep_path)

            self.context['dependencies']['static'] = dependencies
            logger.info(f"Found {len(dependencies)} static dependencies")

            return dependencies

        except Exception as e:
            logger.error(f"Failed to analyze static dependencies: {e}")
            return []

    def _analyze_pe_imports(self) -> List[str]:
        """
        Extract imports from a Windows PE binary using objdump or dumpbin.

        Returns:
            List of imported DLL names
        """
        imports = []

        # Try objdump first (cross-platform, available via binutils/mingw)
        objdump_path = shutil.which('objdump')
        if objdump_path:
            try:
                result = subprocess.run(
                    [objdump_path, '-x', str(self.binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    in_import_section = False
                    for line in result.stdout.splitlines():
                        # objdump -x shows "DLL Name: kernel32.dll" in import tables
                        if 'DLL Name:' in line:
                            dll_name = line.split('DLL Name:')[-1].strip()
                            if dll_name:
                                imports.append(dll_name)
                            in_import_section = True
                        # Also catch import table entries like "kernel32.dll"
                        elif in_import_section and line.strip().endswith('.dll'):
                            imports.append(line.strip())

                    if imports:
                        logger.info(f"PE imports via objdump: {len(imports)} DLLs")
                        return imports
            except (subprocess.TimeoutExpired, OSError) as e:
                logger.debug(f"objdump failed: {e}")

        # Fall back to dumpbin on Windows
        if sys.platform == 'win32':
            dumpbin_path = shutil.which('dumpbin')
            if dumpbin_path:
                try:
                    result = subprocess.run(
                        [dumpbin_path, '/IMPORTS', str(self.binary_path)],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            stripped = line.strip()
                            # dumpbin /IMPORTS shows DLL names as standalone lines
                            # ending with .dll (case-insensitive)
                            if stripped.lower().endswith('.dll') and ' ' not in stripped:
                                imports.append(stripped)

                        if imports:
                            logger.info(f"PE imports via dumpbin: {len(imports)} DLLs")
                            return imports
                except (subprocess.TimeoutExpired, OSError) as e:
                    logger.debug(f"dumpbin failed: {e}")

        if not imports:
            logger.warning("No PE import extraction tool available (tried objdump, dumpbin)")

        return imports

    def check_suid_sgid(self) -> Dict[str, Any]:
        """
        Check if binary has SUID/SGID bits set.

        Returns:
            Dict with SUID/SGID status
        """
        logger.info("Checking SUID/SGID bits...")

        import stat

        try:
            st = self.binary_path.stat()
            is_suid = bool(st.st_mode & stat.S_ISUID)
            is_sgid = bool(st.st_mode & stat.S_ISGID)

            self.context['suid_sgid'] = {
                'suid': is_suid,
                'sgid': is_sgid,
                'owner': st.st_uid,
                'group': st.st_gid,
                'permissions': oct(st.st_mode)
            }

            if is_suid or is_sgid:
                logger.warning(f"SUID/SGID binary detected: SUID={is_suid}, SGID={is_sgid}")

            return self.context['suid_sgid']

        except Exception as e:
            logger.error(f"Failed to check SUID/SGID: {e}")
            return {}

    def find_symlinks(self) -> List[Dict[str, str]]:
        """
        Find symlinks related to the binary.

        Returns:
            List of symlink info
        """
        logger.info("Searching for symlinks...")

        symlinks = []

        # Check if binary itself is a symlink
        if self.binary_path.is_symlink():
            target = self.binary_path.resolve()
            symlinks.append({
                'path': str(self.binary_path),
                'target': str(target),
                'type': 'binary'
            })
            logger.warning(f"Binary is symlink: {self.binary_path} -> {target}")

        # Check dependencies for symlinks
        for dep_path in self.context['dependencies'].get('static', []):
            dep = Path(dep_path)
            if dep.exists() and dep.is_symlink():
                target = dep.resolve()
                symlinks.append({
                    'path': str(dep),
                    'target': str(target),
                    'type': 'dependency'
                })

        self.context['symlinks'] = symlinks
        logger.info(f"Found {len(symlinks)} symlinks")

        return symlinks

    def check_ld_preload_opportunities(self) -> List[Dict[str, Any]]:
        """
        Identify LD_PRELOAD injection opportunities.

        Returns:
            List of potential injection points
        """
        logger.info("Analyzing LD_PRELOAD opportunities...")

        opportunities = []

        # Check if binary uses any hookable functions
        hookable_functions = [
            'malloc', 'free', 'read', 'write', 'open', 'close',
            'socket', 'connect', 'send', 'recv', 'system', 'exec'
        ]

        try:
            if sys.platform == 'darwin':
                result = subprocess.run(
                    ['nm', '-u', str(self.binary_path)],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['nm', '-D', str(self.binary_path)],
                    capture_output=True,
                    text=True
                )

            for line in result.stdout.splitlines():
                for func in hookable_functions:
                    if func in line:
                        opportunities.append({
                            'function': func,
                            'risk': 'Can be intercepted via LD_PRELOAD',
                            'impact': 'High if SUID/SGID'
                        })

            self.context['ld_preload_opportunities'] = opportunities
            logger.info(f"Found {len(opportunities)} LD_PRELOAD opportunities")

            return opportunities

        except Exception as e:
            logger.error(f"Failed to analyze LD_PRELOAD opportunities: {e}")
            return []

    def run_frida_analysis(self, duration: int = 30) -> Dict[str, Any]:
        """
        Run Frida with binary-environment template.

        Args:
            duration: How long to run analysis

        Returns:
            Frida findings
        """
        logger.info(f"Running Frida analysis for {duration}s...")

        try:
            self.frida_scanner.spawn_process(str(self.binary_path))
            self.frida_scanner.load_template('binary-environment')
            self.frida_scanner.resume_process()

            import time
            time.sleep(duration)

            self.frida_scanner.detach()

            # Extract runtime context
            for finding in self.frida_scanner.findings:
                if finding.get('type') == 'libraries':
                    self.context['libraries'] = finding.get('data', [])
                elif finding.get('type') == 'dependency_tree':
                    self.context['dependencies']['runtime'] = finding.get('data', {})
                elif finding.get('title') == 'Potential TOCTOU Vulnerability':
                    self.context['toctou_risks'].append(finding.get('details', {}))

            logger.info(f"Frida analysis complete: {len(self.frida_scanner.findings)} findings")

            return {'findings': self.frida_scanner.findings}

        except Exception as e:
            logger.error(f"Frida analysis failed: {e}")
            return {}

    def feed_to_static_analysis(self) -> List[str]:
        """
        Generate list of source files to analyze with Semgrep/CodeQL.

        Returns:
            List of paths to analyze
        """
        logger.info("Identifying source files for static analysis...")

        sources_to_analyze = []

        # Analyze all dependencies
        all_deps = (
            self.context['dependencies'].get('static', []) +
            list(self.context['dependencies'].get('runtime', {}).keys())
        )

        for dep_path in all_deps:
            dep = Path(dep_path)
            if dep.exists():
                sources_to_analyze.append(str(dep))

                # Also check if source is available (e.g., in /usr/src)
                # This is simplified - real implementation would map binaries to source
                logger.info(f"Dependency to analyze: {dep}")

        return sources_to_analyze

    def generate_attack_surface_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive attack surface report.

        Returns:
            Attack surface analysis
        """
        logger.info("Generating attack surface report...")

        attack_surface = {
            'summary': {
                'binary': str(self.binary_path),
                'suid_sgid': self.context['suid_sgid'],
                'total_dependencies': len(self.context['dependencies'].get('static', [])),
                'symlinks': len(self.context['symlinks']),
                'toctou_risks': len(self.context['toctou_risks']),
                'ld_preload_opportunities': len(self.context['ld_preload_opportunities'])
            },
            'high_priority_risks': [],
            'recommendations': []
        }

        # Identify high-priority risks
        if self.context['suid_sgid'].get('suid') or self.context['suid_sgid'].get('sgid'):
            attack_surface['high_priority_risks'].append({
                'risk': 'SUID/SGID Binary',
                'severity': 'critical',
                'description': 'All vulnerabilities become privilege escalation'
            })

        if self.context['toctou_risks']:
            attack_surface['high_priority_risks'].append({
                'risk': 'TOCTOU Vulnerabilities',
                'severity': 'high',
                'count': len(self.context['toctou_risks']),
                'description': 'Race conditions in file operations'
            })

        if self.context['ld_preload_opportunities']:
            attack_surface['high_priority_risks'].append({
                'risk': 'LD_PRELOAD Injection',
                'severity': 'high' if self.context['suid_sgid'] else 'medium',
                'count': len(self.context['ld_preload_opportunities']),
                'description': 'Library injection attack vectors'
            })

        # Generate recommendations
        attack_surface['recommendations'].append(
            'Run static analysis on all dependencies'
        )

        if self.context['toctou_risks']:
            attack_surface['recommendations'].append(
                'Fix TOCTOU vulnerabilities by using openat() family functions'
            )

        if self.context['suid_sgid']:
            attack_surface['recommendations'].append(
                'CRITICAL: All findings in this binary are privilege escalation risks'
            )

        return attack_surface

    def run_comprehensive_analysis(self, frida_duration: int = 30) -> Dict[str, Any]:
        """
        Run complete binary context analysis.

        Args:
            frida_duration: How long to run Frida

        Returns:
            Complete analysis results
        """
        logger.info("="*70)
        logger.info("BINARY CONTEXT ANALYSIS")
        logger.info("="*70)
        logger.info(f"Binary: {self.binary_path}")
        logger.info("="*70)

        # Step 0: Detect binary format and special types
        binary_format = self.detect_binary_format()
        self.context['binary_format'] = binary_format
        logger.info(f"Binary format: {binary_format}")

        packing_info = self.detect_packed_binary()
        self.context['packing'] = packing_info
        if packing_info['is_packed']:
            logger.warning(f"Packed binary detected: {packing_info['packer_detected']}")

        if binary_format == 'pe':
            is_dotnet = self.detect_dotnet_assembly()
            self.context['dotnet_assembly'] = is_dotnet
            if is_dotnet:
                logger.info(".NET assembly detected (CLI header present)")

        jar_dex_info = self.detect_jar_or_dex()
        if jar_dex_info:
            self.context['managed_format'] = jar_dex_info

        # Step 1: Static analysis
        self.analyze_static_dependencies()
        self.check_suid_sgid()
        self.find_symlinks()
        self.check_ld_preload_opportunities()

        # Step 2: Dynamic analysis
        self.run_frida_analysis(frida_duration)

        # Step 3: Generate reports
        attack_surface = self.generate_attack_surface_report()
        sources_to_analyze = self.feed_to_static_analysis()

        # Step 4: Output results
        results = {
            'context': self.context,
            'attack_surface': attack_surface,
            'sources_for_static_analysis': sources_to_analyze,
            'frida_findings': self.frida_scanner.findings
        }

        logger.info("="*70)
        logger.info("ANALYSIS COMPLETE")
        logger.info("="*70)
        logger.info(f"Format: {binary_format}")
        logger.info(f"Packed: {packing_info['is_packed']}")
        logger.info(f"Dependencies: {len(self.context['dependencies'].get('static', []))}")
        logger.info(f"TOCTOU risks: {len(self.context['toctou_risks'])}")
        logger.info(f"LD_PRELOAD opportunities: {len(self.context['ld_preload_opportunities'])}")
        logger.info(f"Symlinks: {len(self.context['symlinks'])}")
        logger.info("="*70)

        return results


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="RAPTOR Binary Context Analyzer"
    )
    parser.add_argument('--binary', required=True,
                       help='Binary to analyze')
    parser.add_argument('--duration', type=int, default=30,
                       help='Frida analysis duration (seconds)')
    parser.add_argument('--out', help='Output file for results')

    args = parser.parse_args()

    analyzer = BinaryContextAnalyzer(args.binary)
    results = analyzer.run_comprehensive_analysis(args.duration)

    # Save results
    if args.out:
        output_path = Path(args.out)
    else:
        import time
        output_path = Path('out') / f'binary_context_{int(time.time())}.json'

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n✓ Analysis complete: {output_path}")

    # Print summary
    print("\nATTACK SURFACE SUMMARY:")
    print(json.dumps(results['attack_surface'], indent=2))

    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
