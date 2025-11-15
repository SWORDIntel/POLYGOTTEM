#!/usr/bin/env python3
"""
C Methods TUI Integration for POLYGOTTEM
=========================================

Provides terminal UI workflows for C Methods Framework.
Integrates with interactive menu system for easy exploitation method selection.

EDUCATIONAL/RESEARCH USE ONLY
"""

import sys
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors, Symbols
from interactive_menu import InteractiveMenu
from c_methods_autoexec_bridge import CMethodsAutoExecBridge

try:
    from guarantee_c_integration import CMethodsIntegration
    C_INTEGRATION_AVAILABLE = True
except ImportError:
    C_INTEGRATION_AVAILABLE = False


class CMethodsTUIWorkflows:
    """Terminal UI workflows for C Methods"""

    def __init__(self, tui: Optional[TUI] = None):
        """Initialize C Methods TUI workflows"""
        self.tui = tui or TUI()
        self.menu = InteractiveMenu(self.tui)
        self.bridge = CMethodsAutoExecBridge(verbose=False)
        self.colors = Colors()
        self.symbols = Symbols()

    def display_c_methods_banner(self):
        """Display C Methods framework banner"""
        self.tui.print_box(
            "POLYGOTTEM C Methods Framework",
            f"{self.colors.CYAN}Advanced Native Exploitation Methods{self.colors.RESET}",
            width=70
        )

    def workflow_select_c_method(self) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Interactive workflow: Select C method

        Returns:
            Tuple of (method_id, method_definition) or None if cancelled
        """
        self.menu.clear_screen()
        self.display_c_methods_banner()

        # Get available methods
        methods = self.bridge.list_methods()
        if not methods:
            self.tui.error("No C methods available. Ensure C framework is compiled.")
            return None

        # Build menu options
        options = []
        method_map = {}
        option_num = 1

        for category, category_methods in methods.items():
            self.tui.print(f"\n{self.colors.YELLOW}{category.upper()}{self.colors.RESET}")
            self.tui.print("-" * 60)

            for method_dict in category_methods:
                method_id = method_dict["id"]
                method_name = method_dict["name"]
                platforms = ", ".join(method_dict["platforms"])
                reliability = method_dict["reliability"]

                # Format display
                display = f"[{option_num}] {method_name:40} ({platforms})"
                options.append(display)
                method_map[str(option_num)] = method_id

                self.tui.print(display)
                option_num += 1

        # Get user selection
        self.tui.print(f"\n{self.colors.GREEN}Selection{self.colors.RESET}")
        selection = input("Select method number (or 'q' to cancel): ").strip()

        if selection.lower() == 'q':
            return None

        if selection not in method_map:
            self.tui.error("Invalid selection")
            return None

        selected_method_id = method_map[selection]

        # Return method details
        exec_methods = self.bridge.get_execution_methods()
        method_key = f"c_{selected_method_id}"
        if method_key in exec_methods:
            return selected_method_id, exec_methods[method_key]

        return None

    def workflow_c_method_quick_exploit(self):
        """
        Workflow: Quick C Method Exploitation

        Steps:
        1. Select target platform
        2. Select exploitation method
        3. Display exploitation details
        4. Execute (if authorized)
        """
        self.menu.clear_screen()
        self.display_c_methods_banner()

        self.tui.print("\n⚡ Quick C Method Exploitation\n")

        # Step 1: Platform selection
        self.tui.print(f"{self.colors.CYAN}[1/3] Select Target Platform{self.colors.RESET}")
        platforms = ["Windows", "Linux", "macOS", "Cross-Platform"]
        platform_selection = self.menu.show_menu(platforms, "Target Platform")

        if platform_selection is None:
            return

        platform_name = platforms[platform_selection].lower()

        # Step 2: Method selection for platform
        self.tui.print(f"\n{self.colors.CYAN}[2/3] Select Exploitation Method{self.colors.RESET}")

        methods = self.bridge.list_methods(
            platform="windows" if "windows" in platform_name else
                    "linux" if "linux" in platform_name else
                    "macos" if "macos" in platform_name else None
        )

        if not methods:
            self.tui.error(f"No exploitation methods available for {platform_name}")
            return

        # Build method options
        method_options = []
        method_ids = []

        for category, category_methods in methods.items():
            for method_dict in category_methods:
                method_name = f"[{category}] {method_dict['name']}"
                method_options.append(method_name)
                method_ids.append(method_dict['id'])

        method_selection = self.menu.show_menu(method_options, "Exploitation Method")

        if method_selection is None:
            return

        selected_method_id = method_ids[method_selection]

        # Step 3: Display and confirm
        self.tui.print(f"\n{self.colors.CYAN}[3/3] Execution Details{self.colors.RESET}\n")

        # Get method metadata
        integration = CMethodsIntegration() if C_INTEGRATION_AVAILABLE else None
        if integration:
            metadata = integration.C_METHODS_METADATA.get(selected_method_id)
            if metadata:
                self.tui.print(f"Method: {metadata.method_name}")
                self.tui.print(f"Category: {metadata.category}")
                self.tui.print(f"Platform: {', '.join(metadata.platforms)}")
                self.tui.print(f"Reliability: {metadata.reliability}/5")
                self.tui.print(f"Description: {metadata.description}")
                self.tui.print(f"Requires Root: {'Yes' if metadata.requires_root else 'No'}")
                self.tui.print(f"Requires Elevated: {'Yes' if metadata.requires_elevated else 'No'}")

        self.tui.print("\n" + "=" * 70)
        self.tui.warning("AUTHORIZED USE ONLY - Ensure proper authorization before execution")
        confirm = input("Execute method? (y/N): ").strip().lower()

        if confirm != 'y':
            self.tui.info("Execution cancelled")
            return

        # Execute
        self.tui.print(f"\n{self.colors.GREEN}Executing C method...{self.colors.RESET}")
        success, result = self.bridge.execute_method(selected_method_id)

        if success:
            self.tui.success(f"Method execution successful")
            self.tui.print(f"Result: {result}")
        else:
            self.tui.error(f"Method execution failed: {result}")

    def workflow_c_method_analysis(self):
        """
        Workflow: C Methods Analysis and Selection

        Helps users analyze and select appropriate C methods for their target
        """
        self.menu.clear_screen()
        self.display_c_methods_banner()

        self.tui.print("\n🔍 C Methods Analysis & Selection\n")

        # Show statistics
        methods = self.bridge.list_methods()
        total_methods = sum(len(m) for m in methods.values())

        self.tui.print(f"Available C Methods: {total_methods}")
        self.tui.print(f"Categories: {len(methods)}")

        for category, category_methods in methods.items():
            self.tui.print(f"  - {category}: {len(category_methods)} methods")

        # Show category breakdown
        self.tui.print(f"\n{self.colors.CYAN}Method Breakdown by Category:{self.colors.RESET}")

        for category in ["exploitation", "utilities", "native", "payloads"]:
            if category in methods:
                category_methods = methods[category]
                self.tui.print(f"\n{category.upper()}:")
                for method_dict in category_methods:
                    self.tui.print(
                        f"  • {method_dict['name']:40} "
                        f"({', '.join(method_dict['platforms'])})"
                    )

    def workflow_c_method_advanced(self):
        """
        Workflow: Advanced C Methods Configuration

        Allows advanced users to:
        - Configure method parameters
        - Chain multiple methods
        - Set up callbacks and post-execution
        """
        self.menu.clear_screen()
        self.display_c_methods_banner()

        self.tui.print("\n⚙️  Advanced C Methods Configuration\n")

        self.tui.warning("Advanced mode - for experienced users only")

        # Step 1: Method selection
        result = self.workflow_select_c_method()
        if not result:
            return

        method_id, method_def = result

        # Step 2: Parameter configuration
        self.tui.print(f"\n{self.colors.CYAN}Method Parameters{self.colors.RESET}")
        self.tui.print(f"Method: {method_def['name']}")
        self.tui.print(f"Description: {method_def['description']}")
        self.tui.print(f"Requirements: {', '.join(method_def['requirements'])}")

        # Step 3: Method chaining options
        self.tui.print(f"\n{self.colors.CYAN}Chaining Options{self.colors.RESET}")

        chain_options = [
            "None - Execute single method",
            "Chain with encryption (AES-256)",
            "Chain with obfuscation",
            "Chain with compression",
            "Custom chain"
        ]

        chain_selection = self.menu.show_menu(chain_options, "Method Chaining")
        if chain_selection is not None:
            self.tui.info(f"Chaining option selected: {chain_options[chain_selection]}")

    def show_main_menu(self) -> Optional[str]:
        """
        Show C Methods main menu

        Returns:
            Selected workflow ID or None
        """
        self.menu.clear_screen()
        self.display_c_methods_banner()

        workflows = {
            "quick_exploit": "⚡ Quick C Method Exploitation",
            "select_method": "🎯 Select & Configure C Method",
            "analysis": "🔍 C Methods Analysis",
            "advanced": "⚙️  Advanced Configuration",
            "list_all": "📋 List All C Methods",
            "back": "↩️  Back to Main Menu"
        }

        self.tui.print("\nAvailable Workflows:\n")
        options = list(workflows.values())
        selection = self.menu.show_menu(options, "C Methods Workflow")

        if selection is None:
            return None

        workflow_keys = list(workflows.keys())
        return workflow_keys[selection]

    def run_workflow(self, workflow_id: str):
        """Execute selected workflow"""
        workflows = {
            "quick_exploit": self.workflow_c_method_quick_exploit,
            "select_method": self.workflow_select_c_method,
            "analysis": self.workflow_c_method_analysis,
            "advanced": self.workflow_c_method_advanced,
        }

        workflow_func = workflows.get(workflow_id)
        if workflow_func:
            workflow_func()
        else:
            self.tui.error(f"Unknown workflow: {workflow_id}")

    def interactive_loop(self):
        """Run interactive workflow loop"""
        while True:
            workflow_id = self.show_main_menu()

            if workflow_id is None or workflow_id == "back":
                break

            if workflow_id == "list_all":
                methods = self.bridge.list_methods()
                import json
                self.tui.print(json.dumps(methods, indent=2))
                input("\nPress Enter to continue...")
                continue

            self.run_workflow(workflow_id)


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="POLYGOTTEM C Methods TUI")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run interactive mode")
    parser.add_argument("--quick", "-q", action="store_true", help="Quick exploitation workflow")
    parser.add_argument("--analyze", "-a", action="store_true", help="Analysis workflow")
    parser.add_argument("--list", "-l", action="store_true", help="List all methods")

    args = parser.parse_args()

    workflows = CMethodsTUIWorkflows()

    if args.list:
        methods = workflows.bridge.list_methods()
        import json
        print(json.dumps(methods, indent=2))
    elif args.quick:
        workflows.workflow_c_method_quick_exploit()
    elif args.analyze:
        workflows.workflow_c_method_analysis()
    elif args.interactive:
        workflows.interactive_loop()
    else:
        workflows.interactive_loop()


if __name__ == "__main__":
    main()
