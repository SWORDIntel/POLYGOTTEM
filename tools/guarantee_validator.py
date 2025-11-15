#!/usr/bin/env python3
"""
Guarantee Validator - Authorization and Legal Compliance Checks
================================================================
Enforces authorization requirements, displays legal disclaimers, and
validates that GUARANTEE cascade mode is used responsibly.

Features:
- Multi-layer authorization verification
- Legal disclaimer display
- Authorized use case validation
- Audit logging
- Consent tracking
- Responsible use enforcement

Author: SWORDIntel
Date: 2025-11-15
"""

import os
import sys
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

# Add tools to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tui_helper import TUI, Colors


# Try to import classified theme
try:
    from tui_theme_classified import ClassifiedTheme
    CLASSIFIED_THEME_AVAILABLE = True
except ImportError:
    CLASSIFIED_THEME_AVAILABLE = False
    ClassifiedTheme = None


# Try to import fingerprint auth and setup
try:
    from guarantee_fingerprint_auth import GuaranteeFingerprintAuth
    FINGERPRINT_AVAILABLE = True
except ImportError:
    FINGERPRINT_AVAILABLE = False
    GuaranteeFingerprintAuth = None

try:
    from guarantee_fingerprint_setup import FingerprintSetupManager
    FINGERPRINT_SETUP_AVAILABLE = True
except ImportError:
    FINGERPRINT_SETUP_AVAILABLE = False
    FingerprintSetupManager = None


class AuthorizationLevel:
    """Authorization levels for GUARANTEE mode"""
    NONE = 0
    EDUCATIONAL = 1
    AUTHORIZED_PENTESTING = 2
    COORDINATED_RESEARCH = 3
    THREAT_INTEL = 4


class GuaranteeValidator:
    """Validates authorization and ensures responsible use of GUARANTEE mode"""

    LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                      ⚠️  CRITICAL LEGAL DISCLAIMER  ⚠️                       ║
║                                                                              ║
║  POLYGOTTEM - GUARANTEE CASCADE MODE                                        ║
║  "Advanced Exploitation Chain Generation"                                   ║
║                                                                              ║
║  This tool replicates NATION-STATE EXPLOIT TECHNIQUES and is EXTREMELY      ║
║  DANGEROUS if misused. Unauthorized use is ILLEGAL and may violate:         ║
║                                                                              ║
║  • Computer Fraud and Abuse Act (CFAA) - US                                 ║
║  • UK Computer Misuse Act - UK                                              ║
║  • Criminal Code Article 143-145 - France                                   ║
║  • StGB § 202a-c - Germany                                                  ║
║  • Laws in your jurisdiction                                                ║
║                                                                              ║
║  AUTHORIZED USE CASES ONLY:                                                 ║
║                                                                              ║
║  ✅ PERMITTED:                                                               ║
║  • Authorized penetration testing (WRITTEN approval required)               ║
║  • Security research (isolated lab environment)                             ║
║  • YARA rule development and testing                                        ║
║  • EDR/IDS signature creation                                               ║
║  • Defensive security training                                              ║
║  • Academic research with institutional approval                            ║
║  • CTF competitions (with permission)                                       ║
║                                                                              ║
║  ❌ PROHIBITED:                                                              ║
║  • Unauthorized system access                                               ║
║  • Malware distribution                                                     ║
║  • Real-world attacks                                                       ║
║  • Production testing without approval                                      ║
║  • Mass targeting                                                           ║
║  • Supply chain compromise                                                  ║
║  • Detection evasion for malicious purposes                                 ║
║  • Any illegal activities whatsoever                                        ║
║                                                                              ║
║  By proceeding, you agree to use this tool LEGALLY and RESPONSIBLY.        ║
║  The authors are NOT liable for misuse or damage caused by this tool.      ║
║                                                                              ║
║  For more information: https://github.com/SWORDIntel/POLYGOTTEM            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

    def __init__(self, tui: Optional[TUI] = None, audit_log_file: Optional[str] = None, use_classified_theme: bool = True):
        """
        Initialize guarantee validator

        Args:
            tui: TUI instance for output
            audit_log_file: Path to audit log file (optional)
            use_classified_theme: Use classified document theme
        """
        if tui:
            self.tui = tui
        elif use_classified_theme and CLASSIFIED_THEME_AVAILABLE and ClassifiedTheme:
            try:
                self.tui = ClassifiedTheme(classification_level="C")
            except Exception:
                self.tui = TUI()
        else:
            self.tui = TUI()
        self.audit_log_file = audit_log_file or "guarantee_audit.log"
        self.auth_level = AuthorizationLevel.NONE
        self.authorizations: List[Dict[str, Any]] = []
        self.disclaimers_accepted: List[Dict[str, Any]] = []

        # Initialize fingerprint setup manager (checks if first run)
        self.fingerprint_setup = None
        if FINGERPRINT_SETUP_AVAILABLE:
            try:
                self.fingerprint_setup = FingerprintSetupManager(self.tui)
            except Exception as e:
                self.tui.warning(f"Could not initialize fingerprint setup: {e}")

        # Initialize fingerprint authentication if available
        self.fingerprint_auth = None
        if FINGERPRINT_AVAILABLE:
            try:
                self.fingerprint_auth = GuaranteeFingerprintAuth(self.tui)
                self.tui.success("Fingerprint authentication system initialized")
            except Exception as e:
                self.tui.warning(f"Could not initialize fingerprint auth: {e}")

    def display_critical_warning(self):
        """Display critical legal warning"""
        self.tui.raw(self.LEGAL_DISCLAIMER)
        print()

    def get_authorization_status(self) -> Dict[str, Any]:
        """
        Get current authorization status

        Returns:
            Dict with authorization details
        """
        return {
            'authorized': self.auth_level > AuthorizationLevel.NONE,
            'level': self.auth_level,
            'level_name': self._get_level_name(self.auth_level),
            'authorizations': self.authorizations,
            'disclaimers_accepted': len(self.disclaimers_accepted),
            'timestamp': datetime.now().isoformat()
        }

    def validate_authorization_interactive(self) -> bool:
        """
        Interactively validate authorization with fingerprint authentication

        Returns:
            True if user confirms authorization
        """
        # First run: Setup fingerprint if needed
        if self.fingerprint_setup and self.fingerprint_setup.is_first_run():
            self.tui.section("FIRST-RUN SETUP")
            self.tui.warning("⚠️  FIRST TIME SETUP REQUIRED")
            self.tui.info("Setting up biometric authentication to prevent unauthorized access")
            print()

            if not self.fingerprint_setup.run_setup_wizard():
                self.tui.error("⛔ Setup failed - cannot proceed without authentication setup")
                return False

            print()
            self.tui.success("✅ Setup complete - now authenticating...")
            print()

        # Second: Require fingerprint authentication
        if self.fingerprint_auth:
            self.tui.section("Step 1: Biometric Authentication")
            if not self.fingerprint_auth.require_authentication():
                self.tui.error("❌ Fingerprint authentication required to proceed")
                if self.fingerprint_setup:
                    self.fingerprint_setup.display_lockout_notice()
                return False

            self.fingerprint_auth.display_auth_status()
            print()

        self.display_critical_warning()

        # Check authorization
        self.tui.header("Authorization Verification")
        print()

        options = [
            {
                'label': '✅ Authorized Penetration Testing',
                'description': 'I have written approval for a specific engagement'
            },
            {
                'label': '🔬 Security Research (Isolated Lab)',
                'description': 'I am conducting security research in an isolated environment'
            },
            {
                'label': '🛡️ Defensive Security Training',
                'description': 'I am developing YARA rules or EDR signatures'
            },
            {
                'label': '🎓 Academic Research',
                'description': 'I have institutional approval for security research'
            },
            {
                'label': '❌ None of the Above / Not Authorized',
                'description': 'I do not have authorization'
            },
        ]

        try:
            from interactive_menu import InteractiveMenu, MenuBuilder
            menu = InteractiveMenu(self.tui)
        except ImportError:
            menu = InteractiveMenuStub(self.tui)

        selected = menu.single_select(
            "Select your authorization context",
            options,
            default=4
        )

        if selected == 4:
            # Not authorized
            self.tui.error("⛔ Authorization REQUIRED to use GUARANTEE cascade mode")
            self.tui.info("Please ensure you have proper authorization before continuing")
            print()
            return False

        # Map selection to authorization level
        auth_mapping = {
            0: AuthorizationLevel.AUTHORIZED_PENTESTING,
            1: AuthorizationLevel.COORDINATED_RESEARCH,
            2: AuthorizationLevel.THREAT_INTEL,
            3: AuthorizationLevel.THREAT_INTEL,
        }

        self.auth_level = auth_mapping.get(selected, AuthorizationLevel.NONE)

        # Get authorization details
        print()
        self.tui.section("Authorization Details")

        if self.auth_level == AuthorizationLevel.AUTHORIZED_PENTESTING:
            engagement_name = menu.prompt_input(
                "Engagement name/ID",
                default="ENGAGEMENT_001"
            )
            client_name = menu.prompt_input(
                "Client organization name",
                default="Client Inc."
            )
            approval_date = menu.prompt_input(
                "Approval date (YYYY-MM-DD)",
                default=datetime.now().strftime('%Y-%m-%d')
            )
            self.authorizations.append({
                'type': 'authorized_pentesting',
                'engagement': engagement_name,
                'client': client_name,
                'approval_date': approval_date,
                'timestamp': datetime.now().isoformat()
            })

        elif self.auth_level == AuthorizationLevel.COORDINATED_RESEARCH:
            research_topic = menu.prompt_input(
                "Research topic",
                default="Exploit chain analysis"
            )
            institution = menu.prompt_input(
                "Institution/Organization",
                default="Research Lab"
            )
            self.authorizations.append({
                'type': 'security_research',
                'topic': research_topic,
                'institution': institution,
                'timestamp': datetime.now().isoformat()
            })

        elif self.auth_level == AuthorizationLevel.THREAT_INTEL:
            use_case = menu.prompt_input(
                "Specific use case",
                default="YARA rule development"
            )
            self.authorizations.append({
                'type': 'defensive_security',
                'use_case': use_case,
                'timestamp': datetime.now().isoformat()
            })

        # Get explicit consent
        print()
        self.tui.warning("You must acknowledge the legal implications")
        print()

        acknowledged = menu.confirm(
            "I acknowledge that unauthorized use is ILLEGAL and may violate computer fraud laws",
            default=False
        )

        if not acknowledged:
            self.tui.error("⛔ You must acknowledge the legal disclaimer to continue")
            return False

        responsible = menu.confirm(
            "I agree to use this tool RESPONSIBLY and LEGALLY",
            default=False
        )

        if not responsible:
            self.tui.error("⛔ You must agree to responsible use to continue")
            return False

        # Record acceptance
        self.disclaimers_accepted.append({
            'disclaimer': 'legal_warning',
            'timestamp': datetime.now().isoformat(),
            'legal_acknowledged': acknowledged,
            'responsible_use_acknowledged': responsible
        })

        # Log authorization
        self._log_authorization(
            'authorization_granted',
            self.get_authorization_status()
        )

        self.tui.success("✅ Authorization verified")
        self.tui.success("GUARANTEE cascade mode authorized")
        print()

        return True

    def validate_guaranteed_chain(self, chain: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a generated guarantee chain

        Args:
            chain: Chain structure to validate

        Returns:
            Validation result with warnings/issues
        """
        result = {
            'valid': True,
            'warnings': [],
            'notes': [],
            'methods_count': len(chain.get('methods', [])),
            'success_probability': chain.get('success_probability', 0),
            'requires_approval': False
        }

        # Check chain complexity
        if result['methods_count'] > 8:
            result['warnings'].append(
                "Complex chain with 8+ methods detected. "
                "This significantly increases success probability. "
                "Ensure this is appropriate for your authorized use case."
            )

        # Check success probability
        if result['success_probability'] > 0.95:
            result['warnings'].append(
                "Very high success probability (>95%). "
                "This may be too aggressive for some use cases. "
                "Consider limiting chain length if this is for defensive research."
            )

        # Check for dangerous combinations
        dangerous_combos = self._check_dangerous_combinations(chain)
        if dangerous_combos:
            result['warnings'].extend(dangerous_combos)
            result['requires_approval'] = True

        return result

    def _check_dangerous_combinations(self, chain: Dict[str, Any]) -> List[str]:
        """
        Check for dangerous method combinations

        Args:
            chain: Chain structure

        Returns:
            List of warnings
        """
        warnings = []
        methods = [m.get('name', '').lower() for m in chain.get('methods', [])]

        # Check for persistence + privilege escalation combinations
        has_persistence = any('persistence' in m for m in methods)
        has_priv_esc = any('privilege' in m or 'escalation' in m for m in methods)

        if has_persistence and has_priv_esc:
            warnings.append(
                "Chain includes persistence + privilege escalation methods. "
                "This is extremely powerful and may indicate malicious intent. "
                "Ensure this is strictly for authorized defensive research."
            )

        # Check for lateral movement patterns
        has_lateral = any('lateral' in m or 'network' in m for m in methods)
        if has_lateral:
            warnings.append(
                "Chain includes lateral movement methods. "
                "Ensure you have explicit authorization for network-wide testing."
            )

        return warnings

    def _log_authorization(self, event_type: str, data: Dict[str, Any]):
        """
        Log authorization event to audit log

        Args:
            event_type: Type of event
            data: Event data
        """
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'user': os.getenv('USER', 'unknown'),
                'hostname': os.getenv('HOSTNAME', 'unknown'),
                'data': data
            }

            with open(self.audit_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            self.tui.warning(f"Could not write to audit log: {e}")

    def _get_level_name(self, level: int) -> str:
        """Get human-readable authorization level name"""
        names = {
            AuthorizationLevel.NONE: 'None',
            AuthorizationLevel.EDUCATIONAL: 'Educational',
            AuthorizationLevel.AUTHORIZED_PENTESTING: 'Authorized Penetration Testing',
            AuthorizationLevel.COORDINATED_RESEARCH: 'Coordinated Research',
            AuthorizationLevel.THREAT_INTEL: 'Threat Intelligence / Defensive Security'
        }
        return names.get(level, 'Unknown')

    def export_authorization_report(self, output_file: str) -> bool:
        """
        Export authorization report for compliance

        Args:
            output_file: Output file path

        Returns:
            True if successful
        """
        try:
            report = {
                'generated': datetime.now().isoformat(),
                'authorization_status': self.get_authorization_status(),
                'audit_log': self.audit_log_file,
                'version': '1.0'
            }

            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)

            self.tui.success(f"Authorization report exported to {output_file}")
            return True
        except Exception as e:
            self.tui.error(f"Failed to export authorization report: {e}")
            return False


# Interactive menu for authorization (requires tui_helper)
class InteractiveMenuStub:
    """Stub for interactive menu functionality"""
    def __init__(self, tui: TUI):
        self.tui = tui

    def single_select(self, prompt: str, options: List[Dict[str, str]], default: int = 0) -> int:
        """Simple single select"""
        self.tui.info(prompt)
        for i, opt in enumerate(options):
            prefix = "  ➜ " if i == default else "    "
            self.tui.raw(f"{prefix}[{i}] {opt['label']}")
            self.tui.raw(f"      {opt['description']}")
        choice = input("\nSelect option (default={}): ".format(default)).strip()
        return int(choice) if choice.isdigit() else default

    def confirm(self, prompt: str, default: bool = False) -> bool:
        """Simple confirmation"""
        default_str = "y" if default else "n"
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        if response:
            return response[0] == 'y'
        return default

    def prompt_input(self, prompt: str, default: str = "") -> str:
        """Simple input prompt"""
        if default:
            response = input(f"{prompt} [{default}]: ").strip()
            return response if response else default
        else:
            return input(f"{prompt}: ").strip()
