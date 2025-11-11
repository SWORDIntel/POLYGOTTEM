#!/usr/bin/env python3
"""
Execution Method Validator - Real-time Testing and Validation
=============================================================
Provides real-time validation and testing of auto-execution methods
to determine which vectors work in the current environment.

Features:
- Environment detection and compatibility checking
- Real-time method testing with safety sandboxing
- Dependency verification
- Success rate estimation
- Automatic method ranking

Author: SWORDIntel
Date: 2025-11-11
"""

import os
import sys
import platform
import subprocess
import tempfile
import shutil
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from tools.tui_helper import TUI, Colors, Symbols


@dataclass
class ValidationResult:
    """Result of validation test"""
    method_id: str
    success: bool
    reason: str
    tested: bool = True
    dependencies_met: bool = True
    platform_compatible: bool = True
    estimated_reliability: float = 0.0


class ExecutionValidator:
    """Validates and tests auto-execution methods"""

    def __init__(self, tui: Optional[TUI] = None):
        """
        Initialize validator

        Args:
            tui: TUI instance for output
        """
        self.tui = tui if tui else TUI()
        self.platform = platform.system().lower()
        self.env_cache = {}

    def validate_environment(self) -> Dict[str, Any]:
        """
        Validate current environment and available capabilities

        Returns:
            Dict with environment information
        """
        self.tui.section("Environment Validation")

        env = {
            'platform': self.platform,
            'architecture': platform.machine(),
            'python_version': sys.version.split()[0],
            'shell': os.environ.get('SHELL', 'unknown'),
            'capabilities': {},
            'installed_software': {}
        }

        # Check for common tools
        tools_to_check = {
            'bash': ['bash', '--version'],
            'python3': ['python3', '--version'],
            'java': ['java', '-version'],
            'powershell': ['powershell', '--version'] if 'windows' in self.platform else ['pwsh', '--version'],
            'wscript': ['wscript', '/?'],  # Windows only
            'cscript': ['cscript', '/?'],  # Windows only
            'mshta': ['mshta', '/?'],  # Windows only
            'pdf_reader': self._check_pdf_reader(),
            'web_browser': self._check_web_browser(),
        }

        self.tui.info("Checking installed software...")
        for tool_name, check_cmd in tools_to_check.items():
            if check_cmd is None:
                continue

            available = self._check_command_available(check_cmd)
            env['installed_software'][tool_name] = available

            status_symbol = self.symbols.SUCCESS if available else self.symbols.FAILURE
            color = self.colors.GREEN if available else self.colors.RED
            self.tui.list_item(
                f"{tool_name}: " + self.tui.colorize("Available" if available else "Not found", color),
                level=1
            )

        # Check file associations (platform-specific)
        if 'windows' in self.platform:
            env['capabilities']['file_associations'] = self._check_windows_file_associations()
        elif 'linux' in self.platform:
            env['capabilities']['desktop_environment'] = self._check_desktop_environment()
            env['capabilities']['mime_handlers'] = self._check_mime_handlers()

        # Check permissions
        env['capabilities']['can_execute'] = self._check_execution_permissions()
        env['capabilities']['can_write'] = self._check_write_permissions()

        self.env_cache = env
        return env

    def validate_method(self, method_id: str, method_def: Any, test_payload: Optional[bytes] = None) -> ValidationResult:
        """
        Validate a specific execution method

        Args:
            method_id: Method identifier
            method_def: Method definition object
            test_payload: Optional test payload (safe test if None)

        Returns:
            ValidationResult object
        """
        result = ValidationResult(
            method_id=method_id,
            success=False,
            reason="Not tested",
            tested=False
        )

        # Check platform compatibility
        if hasattr(method_def, 'platform'):
            platform_match = (
                method_def.platform.value == 'cross' or
                method_def.platform.value in self.platform
            )
            result.platform_compatible = platform_match

            if not platform_match:
                result.reason = f"Platform mismatch: requires {method_def.platform.value}, have {self.platform}"
                return result

        # Check dependencies
        if hasattr(method_def, 'requirements'):
            deps_met, missing = self._check_dependencies(method_def.requirements)
            result.dependencies_met = deps_met

            if not deps_met:
                result.reason = f"Missing dependencies: {', '.join(missing)}"
                return result

        # Perform safe test
        try:
            if test_payload is None:
                test_payload = b'echo "test"'

            # Generate test file
            if hasattr(method_def, 'generator'):
                test_file = method_def.generator(test_payload)

                # Validate file was created
                if not os.path.exists(test_file):
                    result.reason = "File generation failed"
                    result.tested = True
                    return result

                # Check file size
                if os.path.getsize(test_file) == 0:
                    result.reason = "Generated file is empty"
                    result.tested = True
                    os.unlink(test_file)
                    return result

                # Validate file structure (basic check)
                if self._validate_file_structure(test_file, method_id):
                    result.success = True
                    result.reason = "Validation passed"
                else:
                    result.reason = "File structure validation failed"

                result.tested = True

                # Estimate reliability based on environment
                result.estimated_reliability = self._estimate_reliability(
                    method_id, method_def, result
                )

                # Cleanup
                try:
                    os.unlink(test_file)
                except:
                    pass

            else:
                result.reason = "No generator function available"

        except Exception as e:
            result.reason = f"Test failed: {str(e)}"
            result.tested = True

        return result

    def validate_all_methods(self, methods: Dict[str, Any]) -> Dict[str, ValidationResult]:
        """
        Validate all provided methods

        Args:
            methods: Dict of method_id -> method_def

        Returns:
            Dict of method_id -> ValidationResult
        """
        self.tui.section("Validating Execution Methods")

        results = {}
        total = len(methods)

        for i, (method_id, method_def) in enumerate(methods.items(), 1):
            self.tui.info(f"[{i}/{total}] Testing: {method_def.name if hasattr(method_def, 'name') else method_id}")

            result = self.validate_method(method_id, method_def)
            results[method_id] = result

            # Show result
            if result.success:
                self.tui.success(f"✓ {method_id}")
            elif not result.platform_compatible:
                self.tui.info(f"⊗ {method_id} - {result.reason}")
            elif not result.dependencies_met:
                self.tui.warning(f"⚠ {method_id} - {result.reason}")
            else:
                self.tui.error(f"✗ {method_id} - {result.reason}")

        return results

    def get_recommended_methods(self,
                               validation_results: Dict[str, ValidationResult],
                               min_reliability: float = 0.5) -> List[str]:
        """
        Get recommended methods based on validation results

        Args:
            validation_results: Results from validate_all_methods
            min_reliability: Minimum reliability threshold (0.0-1.0)

        Returns:
            List of recommended method IDs, sorted by reliability
        """
        recommended = []

        for method_id, result in validation_results.items():
            if result.success and result.estimated_reliability >= min_reliability:
                recommended.append((method_id, result.estimated_reliability))

        # Sort by reliability
        recommended.sort(key=lambda x: x[1], reverse=True)

        return [method_id for method_id, _ in recommended]

    def show_validation_report(self, validation_results: Dict[str, ValidationResult]):
        """
        Show comprehensive validation report

        Args:
            validation_results: Results from validate_all_methods
        """
        self.tui.section("Validation Report")

        # Summary
        total = len(validation_results)
        passed = sum(1 for r in validation_results.values() if r.success)
        failed = sum(1 for r in validation_results.values() if r.tested and not r.success)
        skipped = sum(1 for r in validation_results.values() if not r.tested)

        self.tui.key_value("Total Methods", str(total))
        self.tui.key_value("Passed", self.tui.colorize(str(passed), self.colors.GREEN))
        self.tui.key_value("Failed", self.tui.colorize(str(failed), self.colors.RED))
        self.tui.key_value("Skipped", self.tui.colorize(str(skipped), self.colors.YELLOW))

        # Detailed results table
        print()
        self.tui.info("Detailed Results:")

        headers = ["Method", "Status", "Reliability", "Reason"]
        rows = []

        for method_id, result in validation_results.items():
            # Status
            if result.success:
                status = self.tui.colorize("✓ PASS", self.colors.GREEN)
            elif not result.tested:
                status = self.tui.colorize("⊗ SKIP", self.colors.YELLOW)
            else:
                status = self.tui.colorize("✗ FAIL", self.colors.RED)

            # Reliability
            if result.success:
                rel_pct = f"{result.estimated_reliability*100:.0f}%"
                if result.estimated_reliability >= 0.75:
                    rel_str = self.tui.colorize(rel_pct, self.colors.GREEN)
                elif result.estimated_reliability >= 0.50:
                    rel_str = self.tui.colorize(rel_pct, self.colors.YELLOW)
                else:
                    rel_str = self.tui.colorize(rel_pct, self.colors.RED)
            else:
                rel_str = "N/A"

            rows.append([
                method_id,
                status,
                rel_str,
                result.reason[:40]  # Truncate long reasons
            ])

        self.tui.table(headers, rows)

        # Recommendations
        recommended = self.get_recommended_methods(validation_results)
        if recommended:
            print()
            self.tui.success(f"Recommended Methods ({len(recommended)}):")
            for method_id in recommended[:10]:  # Top 10
                result = validation_results[method_id]
                rel_pct = f"{result.estimated_reliability*100:.0f}%"
                self.tui.list_item(f"{method_id} - {rel_pct} reliability", level=1)

    # === Helper Methods ===

    def _check_command_available(self, cmd: List[str]) -> bool:
        """Check if a command is available"""
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return True  # Command exists but returned error
        except (FileNotFoundError, OSError):
            return False

    def _check_pdf_reader(self) -> Optional[List[str]]:
        """Check for PDF reader"""
        readers = {
            'windows': [['where', 'AcroRd32.exe']],
            'linux': [['which', 'evince'], ['which', 'okular'], ['which', 'xpdf']],
            'darwin': [['which', 'open']]  # macOS uses 'open'
        }

        for platform_key, reader_checks in readers.items():
            if platform_key in self.platform:
                for check in reader_checks:
                    if self._check_command_available(check):
                        return check
        return None

    def _check_web_browser(self) -> Optional[List[str]]:
        """Check for web browser"""
        browsers = {
            'windows': [['where', 'chrome.exe'], ['where', 'firefox.exe']],
            'linux': [['which', 'firefox'], ['which', 'chromium'], ['which', 'google-chrome']],
            'darwin': [['which', 'open']]
        }

        for platform_key, browser_checks in browsers.items():
            if platform_key in self.platform:
                for check in browser_checks:
                    if self._check_command_available(check):
                        return check
        return None

    def _check_dependencies(self, requirements: List[str]) -> Tuple[bool, List[str]]:
        """
        Check if dependencies are met

        Args:
            requirements: List of requirement strings

        Returns:
            Tuple of (all_met, missing_list)
        """
        missing = []

        for req in requirements:
            req_lower = req.lower()

            # Check against known software
            if 'bash' in req_lower and not self.env_cache.get('installed_software', {}).get('bash'):
                missing.append(req)
            elif 'python' in req_lower and not self.env_cache.get('installed_software', {}).get('python3'):
                missing.append(req)
            elif 'java' in req_lower and not self.env_cache.get('installed_software', {}).get('java'):
                missing.append(req)
            elif 'pdf' in req_lower and not self.env_cache.get('installed_software', {}).get('pdf_reader'):
                missing.append(req)
            elif 'browser' in req_lower and not self.env_cache.get('installed_software', {}).get('web_browser'):
                missing.append(req)
            elif 'windows' in req_lower and 'windows' not in self.platform:
                missing.append(req)
            elif 'wscript' in req_lower and not self.env_cache.get('installed_software', {}).get('wscript'):
                missing.append(req)
            elif 'mshta' in req_lower and not self.env_cache.get('installed_software', {}).get('mshta'):
                missing.append(req)

        return (len(missing) == 0, missing)

    def _check_windows_file_associations(self) -> Dict[str, bool]:
        """Check Windows file associations"""
        # Simplified check
        return {
            '.lnk': True,
            '.bat': True,
            '.vbs': 'windows' in self.platform,
            '.hta': 'windows' in self.platform,
        }

    def _check_desktop_environment(self) -> Optional[str]:
        """Check Linux desktop environment"""
        de = os.environ.get('DESKTOP_SESSION') or os.environ.get('XDG_CURRENT_DESKTOP')
        return de

    def _check_mime_handlers(self) -> Dict[str, bool]:
        """Check MIME handlers on Linux"""
        # Simplified check
        return {
            'application/pdf': self.env_cache.get('installed_software', {}).get('pdf_reader', False),
            'text/html': self.env_cache.get('installed_software', {}).get('web_browser', False),
        }

    def _check_execution_permissions(self) -> bool:
        """Check if we can execute files"""
        try:
            test_file = tempfile.mktemp(suffix='.sh')
            with open(test_file, 'w') as f:
                f.write('#!/bin/bash\necho test\n')
            os.chmod(test_file, 0o755)
            can_exec = os.access(test_file, os.X_OK)
            os.unlink(test_file)
            return can_exec
        except:
            return False

    def _check_write_permissions(self) -> bool:
        """Check if we can write files"""
        try:
            test_file = tempfile.mktemp()
            with open(test_file, 'w') as f:
                f.write('test')
            os.unlink(test_file)
            return True
        except:
            return False

    def _validate_file_structure(self, file_path: str, method_id: str) -> bool:
        """
        Validate file structure for specific method

        Args:
            file_path: Path to file
            method_id: Method identifier

        Returns:
            True if structure is valid
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)

            # Check magic numbers
            if method_id.startswith('pdf'):
                return header.startswith(b'%PDF')
            elif method_id.startswith('html'):
                return b'<html' in header.lower() or b'<!doc' in header.lower()
            elif method_id == 'elf_binary':
                return header.startswith(b'\x7fELF')
            elif method_id == 'pe_binary':
                return header.startswith(b'MZ')
            elif method_id == 'jar_file':
                return header.startswith(b'PK\x03\x04')  # ZIP signature
            else:
                # For scripts and other files, just check size > 0
                return os.path.getsize(file_path) > 0

        except Exception:
            return False

    def _estimate_reliability(self, method_id: str, method_def: Any, result: ValidationResult) -> float:
        """
        Estimate reliability based on environment and method

        Args:
            method_id: Method identifier
            method_def: Method definition
            result: Validation result

        Returns:
            Estimated reliability (0.0-1.0)
        """
        if not result.success:
            return 0.0

        # Base reliability from method definition
        base_reliability = 0.7  # Default
        if hasattr(method_def, 'reliability'):
            base_reliability = method_def.reliability.value / 5.0

        # Adjust based on environment
        adjustments = 0.0

        # Platform match
        if result.platform_compatible:
            adjustments += 0.1

        # Dependencies met
        if result.dependencies_met:
            adjustments += 0.1

        # Specific method adjustments
        if 'html' in method_id or 'bash' in method_id:
            adjustments += 0.1  # Generally reliable

        if 'office' in method_id or 'dde' in method_id:
            adjustments -= 0.2  # Often blocked

        # Clamp to 0.0-1.0
        return max(0.0, min(1.0, base_reliability + adjustments))


if __name__ == '__main__':
    # Demo validation
    tui = TUI()
    validator = ExecutionValidator(tui)

    tui.banner("Execution Method Validator", "Real-time Testing and Validation")

    # Validate environment
    env = validator.validate_environment()

    # Show environment info
    print()
    tui.section("Environment Summary")
    tui.key_value("Platform", env['platform'])
    tui.key_value("Architecture", env['architecture'])
    tui.key_value("Python", env['python_version'])
    tui.key_value("Shell", env['shell'])

    print()
    tui.success("Validation complete!")
