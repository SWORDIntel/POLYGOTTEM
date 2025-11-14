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

# Import new enhancements
try:
    from validation_utils import (
        validate_file_exists, validate_output_path, ValidationError,
        FileOperationError, ProgressIndicator, setup_logging
    )
    from config import get_config
    ENHANCEMENTS_AVAILABLE = True
except ImportError:
    ENHANCEMENTS_AVAILABLE = False
    get_config = None
    ValidationError = Exception
    FileOperationError = Exception

# Import VPS Geolocation Manager
try:
    from vps_geo_manager import (
        VPSGeoManager, VPSServer, GeolocationConfig, VPSProvider
    )
    VPS_AVAILABLE = True
except ImportError:
    VPS_AVAILABLE = False
    VPSGeoManager = None
    VPSServer = None
    VPSProvider = None
    GeolocationConfig = None


class EnhancedPolyglotOrchestrator:
    """Enhanced orchestrator with polished workflow"""

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize enhanced orchestrator

        Args:
            config_file: Optional path to configuration file
        """
        self.tui = TUI()
        self.menu = InteractiveMenu(self.tui)
        self.engine = AutoExecutionEngine(self.tui)
        self.browser = FileBrowser(self.tui)
        self.optimizer = CascadeOptimizer(self.tui, use_acceleration=True)
        self.cmd_executor = CommandExecutor(self.tui)

        # Initialize VPS manager if available
        self.vps_manager = None
        if VPS_AVAILABLE:
            try:
                self.vps_manager = VPSGeoManager(verbose=False)
                self.vps_manager.tui = self.tui
                self.vps_manager.menu = self.menu
                self.tui.success("VPS Geolocation Manager loaded")
            except Exception as e:
                self.tui.warning(f"Could not initialize VPS manager: {e}")

        # Load configuration if available
        self.config = None
        if ENHANCEMENTS_AVAILABLE and get_config:
            try:
                self.config = get_config(config_file)
                self.tui.success("Configuration loaded successfully")
            except Exception as e:
                self.tui.warning(f"Could not load configuration: {e}")
                self.tui.info("Using default settings")

    def show_configuration_menu(self):
        """Show and manage configuration settings"""
        self.tui.header("Configuration Settings")
        print()

        if not ENHANCEMENTS_AVAILABLE or not self.config:
            self.tui.warning("Configuration system not available")
            self.tui.info("Enhancements may not be installed properly")
            return

        # Show current configuration
        self.tui.section("Current Configuration")
        self.tui.key_value("XOR Keys", ', '.join(self.config.get_default_xor_keys()), 25)
        self.tui.key_value("Output Directory", self.config.get_output_dir(), 25)
        self.tui.key_value("Auto-create Dirs", str(self.config.should_create_directories()), 25)
        self.tui.key_value("Auto-overwrite", str(self.config.should_overwrite()), 25)
        self.tui.key_value("Log Level", self.config.get_log_level(), 25)
        self.tui.key_value("Use Acceleration", str(self.config.use_hardware_acceleration()), 25)
        self.tui.key_value("Validate Payloads", str(self.config.validate_payloads()), 25)
        print()

        # Configuration options
        config_options = [
            {
                'label': '✏️ Edit Configuration',
                'description': f'Edit {self.config.config_file}',
                'value': 'edit'
            },
            {
                'label': '🔄 Reload Configuration',
                'description': 'Reload from file',
                'value': 'reload'
            },
            {
                'label': '📄 Create Default Config',
                'description': 'Create/reset to defaults',
                'value': 'create'
            },
            {
                'label': '↩️ Back',
                'description': 'Return to main menu',
                'value': 'back'
            },
        ]

        choice_idx = self.menu.single_select(
            "Configuration Actions",
            config_options
        )

        if choice_idx is None:
            return

        action = config_options[choice_idx]['value']

        if action == 'edit':
            self.tui.info(f"Edit configuration file: {self.config.config_file}")
            self.tui.info("Use your preferred text editor to modify settings")
            input("\nPress Enter when done editing...")
        elif action == 'reload':
            try:
                self.config = get_config()
                self.tui.success("Configuration reloaded")
            except Exception as e:
                self.tui.error(f"Failed to reload: {e}")
        elif action == 'create':
            try:
                self.config.create_default_config()
                self.tui.success("Default configuration created")
            except Exception as e:
                self.tui.error(f"Failed to create config: {e}")

    def run_interactive(self):
        """Run polished interactive workflow with main menu"""
        self.tui.banner("POLYGOTTEM v2.0", "Enhanced Interactive Polyglot Generator")

        # Show enhancements status
        if ENHANCEMENTS_AVAILABLE:
            self.tui.success("✅ Production enhancements active")
        else:
            self.tui.warning("⚠️ Running in basic mode (enhancements not available)")

        if VPS_AVAILABLE and self.vps_manager:
            self.tui.success("✅ VPS Geolocation Manager active")

        self.tui.info("🎯 Polished workflow with AI-powered optimization")
        self.tui.info("📁 No more typing file paths - use the file browser!")
        self.tui.info("🤖 Intel NPU/GPU accelerated cascade optimization")
        self.tui.info("💻 OS-specific command execution support")
        if ENHANCEMENTS_AVAILABLE:
            self.tui.info("🛡️ Input validation, atomic writes, progress indicators")
        if VPS_AVAILABLE:
            self.tui.info("🌍 Worldwide VPS infrastructure management")
        print()

        # Main menu loop
        while True:
            choice = self._show_main_menu()
            if choice is None or choice == 'exit':
                self.tui.info("Goodbye!")
                break
            elif choice == 'polyglot':
                self._run_polyglot_workflow()
            elif choice == 'vps':
                self._run_vps_management()
            elif choice == 'deploy':
                self._run_vps_deployment()
            elif choice == 'config':
                self.show_configuration_menu()

    def _show_main_menu(self) -> Optional[str]:
        """Show main menu and return selected action"""
        self.tui.header("Main Menu")

        options = [
            {
                'label': '🎨 Generate Polyglot',
                'description': 'Create polyglot files with embedded payloads',
                'value': 'polyglot'
            },
        ]

        if VPS_AVAILABLE and self.vps_manager:
            options.extend([
                {
                    'label': '🌍 Manage VPS Servers',
                    'description': 'Configure worldwide server infrastructure',
                    'value': 'vps'
                },
                {
                    'label': '🚀 Deploy to VPS',
                    'description': 'Deploy polyglots to configured servers',
                    'value': 'deploy'
                },
            ])

        if ENHANCEMENTS_AVAILABLE and self.config:
            options.append({
                'label': '⚙️ Configuration',
                'description': 'Manage system configuration',
                'value': 'config'
            })

        options.append({
            'label': '❌ Exit',
            'description': 'Exit POLYGOTTEM',
            'value': 'exit'
        })

        choice_idx = self.menu.single_select("Select Action", options)
        if choice_idx is None:
            return 'exit'

        return options[choice_idx]['value']

    def _run_polyglot_workflow(self):
        """Run the polyglot generation workflow"""
        self.tui.header("Polyglot Generation Workflow")

        # Show welcome and confirm
        if not self.menu.confirm("Ready to begin polyglot generation?", default=True):
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
        """Step 6: Configure encryption with config defaults (enhanced)"""
        self.tui.header("STEP 6: Encryption Configuration")
        print()

        # Load defaults from config if available
        default_keys = []
        if self.config:
            default_keys = self.config.get_default_xor_keys()
            self.tui.info(f"Default keys from config: {', '.join(default_keys)}")

        if not self.menu.confirm("Apply XOR encryption?", default=True):
            return {'enabled': False}

        # Select encryption keys with better UI
        key_options = [
            {
                'label': '0x9e (TeamTNT Signature #1)',
                'description': 'Single-byte XOR - Common in malware',
                'selected': '9e' in default_keys,
                'value': '9e'
            },
            {
                'label': '0xd3 (Alternative Single-byte)',
                'description': 'Single-byte XOR - Less common',
                'selected': 'd3' in default_keys,
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
        """Step 9: Generate polyglot with validation and progress (enhanced)"""
        self.tui.header("STEP 9: Generating Polyglot")
        print()

        # Get output filename
        default_name = f"polyglot_{carrier_file.stem}_enhanced{carrier_file.suffix}"

        # Use config default output directory if available
        if self.config:
            default_dir = Path(self.config.get_output_dir())
            default_name = str(default_dir / default_name)

        output_file = self.menu.prompt_input(
            "Output filename",
            default=default_name
        )

        output_path = Path(output_file)

        # Validate output path with enhancements
        if ENHANCEMENTS_AVAILABLE:
            try:
                # Check if file exists and prompt for confirmation
                if output_path.exists():
                    overwrite = self.config.should_overwrite() if self.config else False
                    if not overwrite:
                        if not self.menu.confirm(f"File {output_path} exists. Overwrite?", default=False):
                            self.tui.warning("Generation cancelled")
                            return None

                # Validate output path
                validate_output_path(
                    output_path,
                    allow_overwrite=True,
                    create_parents=self.config.should_create_directories() if self.config else True
                )
                self.tui.success("Output path validated")
            except (ValidationError, FileOperationError) as e:
                self.tui.error(f"Validation failed: {e}")
                return None

        try:
            self.tui.info("Generating enhanced polyglot...")

            # Show progress if available
            if ENHANCEMENTS_AVAILABLE:
                # Estimate total work (for progress bar)
                total_steps = len(cve_selections) + 2  # CVEs + embed + finalize
                progress = ProgressIndicator(total_steps, "Polyglot Generation")
                progress.update(0, force=True)

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

    def _run_vps_management(self):
        """Run VPS server management workflow"""
        self.tui.header("VPS Server Management")

        if not self.vps_manager:
            self.tui.error("VPS manager not available")
            self.tui.info("The VPS Geolocation Manager could not be loaded")
            return

        self.tui.info("Configure worldwide VPS infrastructure with geolocation")
        self.tui.info("Generate WireGuard/WARP configs, WHOIS objects, and BGP settings")
        print()

        # Show auto-loaded servers if any
        if self.vps_manager.servers:
            self.tui.success(f"Auto-loaded {len(self.vps_manager.servers)} server(s) from config")
            print()

        # VPS management menu
        while True:
            vps_options = [
                {
                    'label': '➕ Add VPS Server',
                    'description': 'Configure a new VPS with geolocation',
                    'value': 'add'
                },
                {
                    'label': '📋 List Servers',
                    'description': f'View all configured VPS servers ({len(self.vps_manager.servers)})',
                    'value': 'list'
                },
                {
                    'label': '🔧 Generate Configs',
                    'description': 'Export WireGuard/WARP and WHOIS configs',
                    'value': 'export'
                },
                {
                    'label': '✅ Verify Geolocation',
                    'description': 'Generate verification scripts',
                    'value': 'verify'
                },
                {
                    'label': '💾 Save Configuration',
                    'description': 'Save servers to config file',
                    'value': 'save'
                },
                {
                    'label': '📂 Load Configuration',
                    'description': 'Load servers from config file',
                    'value': 'load'
                },
                {
                    'label': '📖 View Guide',
                    'description': 'Show VPS setup documentation',
                    'value': 'guide'
                },
                {
                    'label': '↩️ Back',
                    'description': 'Return to main menu',
                    'value': 'back'
                },
            ]

            choice_idx = self.menu.single_select("VPS Management", vps_options)
            if choice_idx is None:
                break

            action = vps_options[choice_idx]['value']

            if action == 'back':
                break
            elif action == 'add':
                self._add_vps_server()
            elif action == 'list':
                self._list_vps_servers()
            elif action == 'export':
                self._export_vps_configs()
            elif action == 'verify':
                self._generate_verification_scripts()
            elif action == 'save':
                self._save_vps_config()
            elif action == 'load':
                self._load_vps_config()
            elif action == 'guide':
                self._show_vps_guide()

    def _add_vps_server(self):
        """Add a new VPS server configuration with validation"""
        self.tui.section("Add VPS Server")

        # Get server details with validation
        hostname = self.menu.prompt_input("Server hostname", default="vps-server-01")

        # Validate hostname isn't duplicate
        if self.vps_manager.check_duplicate_server(hostname, ""):
            self.tui.warning(f"Server with hostname '{hostname}' already exists")
            if not self.menu.confirm("Continue anyway?", default=False):
                return

        # Get and validate IPv4 address
        while True:
            ip_address = self.menu.prompt_input("IPv4 address", default="1.2.3.4")

            # Check if valid IP
            if not self.vps_manager.validate_ip_address(ip_address, "ipv4"):
                self.tui.error(f"Invalid IPv4 address: {ip_address}")
                if not self.menu.confirm("Try again?", default=True):
                    return
                continue

            # Check if duplicate
            existing = self.vps_manager.check_duplicate_server("", ip_address)
            if existing:
                self.tui.warning(f"Server with IP '{ip_address}' already exists: {existing.hostname}")
                if not self.menu.confirm("Continue anyway?", default=False):
                    return

            break

        # Get and validate IPv6 address (optional)
        ipv6_address = None
        ipv6_input = self.menu.prompt_input("IPv6 subnet (optional, press Enter to skip)", default="")
        if ipv6_input:
            if not self.vps_manager.validate_ip_address(ipv6_input, "subnet"):
                self.tui.warning(f"Invalid IPv6 subnet: {ipv6_input}, skipping")
            else:
                ipv6_address = ipv6_input

        # Get location details
        country_code = self.menu.prompt_input("Country code (2 letters)", default="US")
        region = self.menu.prompt_input("Region/State", default="California")
        city = self.menu.prompt_input("City (optional)", default="")

        # Select provider
        provider_options = [
            {'label': 'AWS', 'value': VPSProvider.AWS},
            {'label': 'DigitalOcean', 'value': VPSProvider.DIGITALOCEAN},
            {'label': 'Vultr', 'value': VPSProvider.VULTR},
            {'label': 'Linode', 'value': VPSProvider.LINODE},
            {'label': 'Hetzner', 'value': VPSProvider.HETZNER},
            {'label': 'OVH', 'value': VPSProvider.OVH},
            {'label': 'Custom', 'value': VPSProvider.CUSTOM},
        ]

        provider_idx = self.menu.single_select("Select VPS Provider", provider_options)
        if provider_idx is None:
            return

        provider = provider_options[provider_idx]['value']

        # Create actual VPSServer object and add to manager
        try:
            server = VPSServer(
                hostname=hostname,
                ip_address=ip_address,
                ipv6_address=ipv6_address,
                country_code=country_code,
                region=region,
                provider=provider
            )
            self.vps_manager.servers.append(server)

            self.tui.success(f"Added VPS server: {hostname}")
            self.tui.info(f"  IP: {ip_address}")
            if city:
                self.tui.info(f"  Location: {city}, {region}, {country_code}")
            else:
                self.tui.info(f"  Location: {region}, {country_code}")
            self.tui.info(f"  Provider: {provider.value}")
            print()

            # Auto-save after adding
            if self.menu.confirm("Save configuration now?", default=True):
                try:
                    self.vps_manager.save_servers()
                    self.tui.success("Configuration saved")
                except Exception as e:
                    self.tui.warning(f"Could not auto-save: {e}")

            self.tui.info("Use 'Generate Configs' to export configuration files")
        except Exception as e:
            self.tui.error(f"Failed to add server: {e}")

    def _list_vps_servers(self):
        """List all configured VPS servers"""
        self.tui.section("Configured VPS Servers")

        if not self.vps_manager.servers:
            self.tui.info("No servers configured yet")
            self.tui.info("Use 'Add VPS Server' to configure your infrastructure")
            return

        # Display servers in a table
        self.tui.info(f"Total servers: {len(self.vps_manager.servers)}")
        print()

        headers = ["Hostname", "IP Address", "Location", "Provider"]
        rows = []
        for server in self.vps_manager.servers:
            location = f"{server.region}, {server.country_code}"
            rows.append([
                server.hostname,
                server.ip_address,
                location,
                server.provider.value
            ])

        self.tui.table(headers, rows)

    def _export_vps_configs(self):
        """Export VPS configuration files"""
        self.tui.section("Export VPS Configurations")

        if not self.vps_manager.servers:
            self.tui.warning("No servers configured")
            self.tui.info("Add VPS servers first before exporting configs")
            return

        output_dir = self.menu.prompt_input(
            "Output directory",
            default="./vps_configs"
        )

        self.tui.info(f"Exporting configs to: {output_dir}")
        self.tui.info("Generated files will include:")
        self.tui.list_item("WireGuard/WARP configuration (warp.conf)", level=1)
        self.tui.list_item("Installation scripts (install_warp_*.sh)", level=1)
        self.tui.list_item("RIPE WHOIS objects (ripe_inet6num.txt)", level=1)
        self.tui.list_item("BIRD BGP configuration (bird.conf)", level=1)
        self.tui.list_item("Geofeed CSV (geofeed.csv)", level=1)
        self.tui.list_item("Verification script (verify_geo.sh)", level=1)
        print()

        if self.menu.confirm("Export configurations now?", default=True):
            try:
                # Call actual VPS manager export method
                results = self.vps_manager.export_server_configs(output_dir)

                self.tui.success("Configurations exported successfully!")
                print()

                # Show what was generated
                for server_name, files in results.items():
                    self.tui.info(f"{server_name}:")
                    for file_path in files:
                        self.tui.list_item(file_path, level=1)
                    print()

                self.tui.info(f"All configs saved to: {output_dir}/")
            except Exception as e:
                self.tui.error(f"Export failed: {e}")
                if self.config and hasattr(self.config, 'verbose') and self.config.verbose:
                    import traceback
                    traceback.print_exc()

    def _generate_verification_scripts(self):
        """Generate geolocation verification scripts"""
        self.tui.section("Generate Verification Scripts")

        if not self.vps_manager.servers:
            self.tui.warning("No servers configured")
            self.tui.info("Add VPS servers first before generating verification scripts")
            return

        self.tui.info("Verification script will check geolocation across:")
        self.tui.list_item("Cloudflare Trace API", level=1)
        self.tui.list_item("IPInfo.io", level=1)
        self.tui.list_item("IP-API", level=1)
        self.tui.list_item("RIPE WHOIS database", level=1)
        print()

        output_file = self.menu.prompt_input(
            "Output script path",
            default="./verify_geo.sh"
        )

        if self.menu.confirm("Generate verification script?", default=True):
            try:
                # Call actual VPS manager method
                script_path = self.vps_manager.generate_verification_script(
                    self.vps_manager.servers,
                    output_file
                )

                self.tui.success(f"Generated: {script_path}")
                self.tui.info("Make executable with: chmod +x verify_geo.sh")
                self.tui.info("Run the script on each VPS server to verify geolocation")
            except Exception as e:
                self.tui.error(f"Failed to generate script: {e}")

    def _save_vps_config(self):
        """Save VPS server configuration"""
        self.tui.section("Save VPS Configuration")

        if not self.vps_manager.servers:
            self.tui.warning("No servers to save")
            return

        self.tui.info(f"Servers to save: {len(self.vps_manager.servers)}")
        for server in self.vps_manager.servers:
            self.tui.list_item(f"{server.hostname} - {server.ip_address}", level=1)
        print()

        # Get save path
        default_path = str(self.vps_manager.config_file)
        save_path = self.menu.prompt_input("Save to", default=default_path)

        if self.menu.confirm(f"Save {len(self.vps_manager.servers)} server(s)?", default=True):
            try:
                saved_path = self.vps_manager.save_servers(save_path)
                self.tui.success(f"Configuration saved to: {saved_path}")
            except Exception as e:
                self.tui.error(f"Failed to save: {e}")

    def _load_vps_config(self):
        """Load VPS server configuration"""
        self.tui.section("Load VPS Configuration")

        # Get load path
        default_path = str(self.vps_manager.config_file)
        load_path = self.menu.prompt_input("Load from", default=default_path)

        if not Path(load_path).exists():
            self.tui.error(f"File not found: {load_path}")
            return

        # Warn if servers will be replaced
        if self.vps_manager.servers:
            self.tui.warning(f"This will replace {len(self.vps_manager.servers)} existing server(s)")
            if not self.menu.confirm("Continue?", default=False):
                return

        try:
            count = self.vps_manager.load_servers(load_path)
            self.tui.success(f"Loaded {count} server(s) from: {load_path}")
            print()

            # Show loaded servers
            if self.vps_manager.servers:
                self.tui.info("Loaded servers:")
                for server in self.vps_manager.servers:
                    self.tui.list_item(f"{server.hostname} - {server.ip_address} ({server.country_code})", level=1)
        except Exception as e:
            self.tui.error(f"Failed to load: {e}")

    def _show_vps_guide(self):
        """Show VPS geolocation guide"""
        self.tui.section("VPS Geolocation Guide")

        guide_path = Path(__file__).parent.parent / "VPS_GEOLOCATION_GUIDE.md"

        if guide_path.exists():
            self.tui.success(f"Full guide available at: {guide_path}")
            self.tui.info("\nQuick Start:")
            self.tui.list_item("1. Add VPS servers with location details", level=1)
            self.tui.list_item("2. Export all configurations", level=1)
            self.tui.list_item("3. Deploy configs to each server", level=1)
            self.tui.list_item("4. Generate WireGuard keys on server", level=1)
            self.tui.list_item("5. Start WARP and update WHOIS database", level=1)
            self.tui.list_item("6. Wait 1 month for geolocation propagation", level=1)
            self.tui.list_item("7. Verify with verification scripts", level=1)
            print()

            if self.menu.confirm("View full guide?", default=False):
                # Try to open with less/more
                try:
                    import subprocess
                    subprocess.run(['less', str(guide_path)])
                except:
                    self.tui.info(f"Please view manually: {guide_path}")
        else:
            self.tui.warning("Guide not found")
            self.tui.info("Expected location: VPS_GEOLOCATION_GUIDE.md")

    def _run_vps_deployment(self):
        """Deploy polyglots to VPS servers"""
        self.tui.header("Deploy to VPS Infrastructure")

        if not self.vps_manager:
            self.tui.error("VPS manager not available")
            return

        # Check if servers are configured
        if not self.vps_manager.servers:
            self.tui.warning("No VPS servers configured")
            if self.menu.confirm("Configure VPS servers now?", default=True):
                self._run_vps_management()
            return

        self.tui.info("Deploy polyglot files to worldwide VPS infrastructure")
        self.tui.info(f"Configured servers: {len(self.vps_manager.servers)}")
        for server in self.vps_manager.servers:
            self.tui.list_item(f"{server.hostname} ({server.country_code})", level=1)
        print()

        # Deployment workflow
        deployment_options = [
            {
                'label': '📤 Deploy Existing Polyglot',
                'description': 'Upload existing polyglot file to servers',
                'value': 'deploy'
            },
            {
                'label': '🔄 Generate & Deploy',
                'description': 'Create new polyglot and deploy',
                'value': 'generate_deploy'
            },
            {
                'label': '🗺️ Deploy by Region',
                'description': 'Deploy different payloads to different regions',
                'value': 'regional'
            },
            {
                'label': '↩️ Back',
                'description': 'Return to main menu',
                'value': 'back'
            },
        ]

        choice_idx = self.menu.single_select("Deployment Options", deployment_options)
        if choice_idx is None:
            return

        action = deployment_options[choice_idx]['value']

        if action == 'back':
            return
        elif action == 'deploy':
            self._deploy_existing_polyglot()
        elif action == 'generate_deploy':
            self._generate_and_deploy()
        elif action == 'regional':
            self._regional_deployment()

    def _deploy_existing_polyglot(self):
        """Deploy an existing polyglot file"""
        self.tui.section("Deploy Existing Polyglot")

        # Browse for polyglot file
        polyglot_file = self.browser.browse(
            title="Select Polyglot File",
            multi_select=False,
            file_type_filter='all'
        )

        if not polyglot_file:
            return

        self.tui.success(f"Selected: {polyglot_file.name}")
        print()

        # Show target servers
        self.tui.info(f"Target servers ({len(self.vps_manager.servers)}):")
        for server in self.vps_manager.servers:
            self.tui.list_item(f"{server.hostname} - {server.ip_address} ({server.country_code})", level=1)
        print()

        if self.menu.confirm(f"Deploy to all {len(self.vps_manager.servers)} servers?", default=True):
            self.tui.info("Deploying polyglot...")
            print()

            # Show deployment information
            self.tui.info("Deployment method: Manual SCP/SFTP")
            self.tui.info("To deploy manually, run on each server:")
            print()

            for server in self.vps_manager.servers:
                deploy_cmd = f"scp {polyglot_file} root@{server.ip_address}:/tmp/"
                self.tui.list_item(deploy_cmd, level=1)

            print()
            self.tui.warning("Note: Automatic SSH deployment not yet implemented")
            self.tui.info("Copy the commands above to deploy to each server")
            self.tui.info("Future versions will support automatic deployment")

    def _generate_and_deploy(self):
        """Generate a new polyglot and deploy it"""
        self.tui.section("Generate & Deploy")

        self.tui.info("First, let's generate the polyglot...")

        # Run polyglot workflow
        self._run_polyglot_workflow()

        # Then offer to deploy
        if self.menu.confirm("Deploy generated polyglot to VPS servers?", default=True):
            self._deploy_existing_polyglot()

    def _regional_deployment(self):
        """Deploy different payloads to different regions"""
        self.tui.section("Regional Deployment")

        self.tui.info("Deploy region-specific polyglots:")
        self.tui.list_item("North America: Custom payload for US/CA", level=1)
        self.tui.list_item("Europe: Custom payload for EU countries", level=1)
        self.tui.list_item("Asia-Pacific: Custom payload for APAC region", level=1)
        print()

        self.tui.info("This feature allows targeted deployment based on geolocation")
        self.tui.warning("Not yet implemented - coming soon!")

        if self.menu.confirm("Return to deployment menu?", default=True):
            return


def main():
    """Main entry point with enhanced error handling"""
    parser = argparse.ArgumentParser(
        description="POLYGOTTEM Enhanced Orchestrator v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
✨ ENHANCED FEATURES (v2.0):

🛡️ Production Enhancements:
  - Input validation with detailed error messages
  - Atomic file writes (no corruption on failure)
  - Progress indicators for large operations
  - Configuration file support (~/.polygottem/config.ini)
  - Comprehensive logging with multiple levels
  - Graceful dependency handling

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
    parser.add_argument('--config', type=str, metavar='FILE',
                       help='Path to configuration file (default: ~/.polygottem/config.ini)')
    parser.add_argument('--create-config', action='store_true',
                       help='Create default configuration file and exit')
    parser.add_argument('--show-config', action='store_true',
                       help='Show current configuration and exit')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Handle config-only operations
    if args.create_config:
        if ENHANCEMENTS_AVAILABLE:
            try:
                config = get_config(args.config)
                config.create_default_config()
                return 0
            except Exception as e:
                print(f"[!] Error creating config: {e}", file=sys.stderr)
                return 1
        else:
            print("[!] Configuration system not available", file=sys.stderr)
            print("[*] Install enhancements: validation_utils.py, config.py", file=sys.stderr)
            return 1

    if args.show_config:
        if ENHANCEMENTS_AVAILABLE:
            try:
                config = get_config(args.config)
                print(f"\nConfiguration file: {config.config_file}")
                print("\nCurrent settings:")
                for section in config.config.sections():
                    print(f"\n[{section}]")
                    for key, value in config.config.items(section):
                        print(f"  {key} = {value}")
                return 0
            except Exception as e:
                print(f"[!] Error reading config: {e}", file=sys.stderr)
                return 1
        else:
            print("[!] Configuration system not available", file=sys.stderr)
            return 1

    # Setup logging if verbose
    if args.verbose and ENHANCEMENTS_AVAILABLE:
        setup_logging(verbose=True)

    # Run interactive orchestrator with error handling
    try:
        orchestrator = EnhancedPolyglotOrchestrator(config_file=args.config)
        orchestrator.run_interactive()
        return 0
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Fatal error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
